"""The deterministic red-team runner (item 14).

It loads the YAML corpus, runs each case against a live deployment as the case's
identity, derives the *observed* blocking layer from the SQLSTATE, HTTP status or
audit outcome, and asks the case's oracle whether the attack's objective was
achieved. A must-block case counts as blocked only when the oracle says the
objective failed *and* the observed layer matches the one the case expected; a
benign control counts as passed only when it succeeds. Categories that need the
demo data or the approval/OAuth flows run only against the demo stack.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from typing import Any

import asyncpg
import yaml

from pgwarden.redteam import mcp_client
from pgwarden.redteam.oracles import ORACLES, OracleContext, table_checksum
from pgwarden.redteam.stack import StackClient, Tokens

ATTACKS_DIR = Path(__file__).parent / "attacks"
BENIGN_FILE = Path(__file__).parent / "benign.yaml"

# The single region each RLS-restricted person may see (see demo/pgwarden.yaml).
REGION_FOR_IDENTITY = {"bob": "EU", "dana": "US"}
# The mock IdP subject for each demo person.
IDP_SUB = {
    "alice": "usr_alice",
    "bob": "usr_bob",
    "dana": "usr_dana",
    "carol": "usr_carol",
    "mallory": "usr_mallory",
}

ERROR_LAYER_BY_SQLSTATE = {
    "42601": "protocol",
    "25006": "read_only_transaction",
    "42501": "privileges",
    "57014": "timeout_or_cap",
    "55P03": "timeout_or_cap",
    "54000": "timeout_or_cap",
    "53400": "rate_limit",
    "53300": "rate_limit",
    # the function is not available to the role (dblink not installed, no EXECUTE)
    "42883": "privileges",
    # "transaction read-write mode must be set before any query": the read-only
    # transaction refusing a switch to read-write mid-transaction
    "25001": "read_only_transaction",
}
# Layers that can only show up as an error. privileges, RLS and masking can also
# block silently (privilege-filtered metadata, zero foreign rows, masked values).
_ERROR_LAYERS = {"protocol", "read_only_transaction"}
_APPROVAL_CODES = {
    "rejected_by_validation",
    "no_writer_role",
    "self_approval",
    "not_an_approver",
    "not_executable",
    "binding_mismatch",
    "not_pending",
    "not_found",
}
_TABLE_FOR_CATEGORY = {
    "A": "refunds",
    "B": "refunds",
    "C": "customers",
    "G": "billing.payment_methods",
}


@dataclasses.dataclass
class CaseResult:
    id: str
    category: str
    title: str
    kind: str  # "attack", "benign" or "residual"
    must_block: bool
    blocked: bool
    passed: bool
    expected_layer: str | None
    observed_layer: str | None
    detail: str


def load_corpus() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for path in sorted(ATTACKS_DIR.glob("*.yaml")):
        cases.extend(yaml.safe_load(path.read_text(encoding="utf-8")))
    cases.extend(yaml.safe_load(BENIGN_FILE.read_text(encoding="utf-8")))
    return cases


def observed_layer(response: mcp_client.ToolResponse, expected: str | None) -> str:
    err = response.tool_error
    if err is not None:
        if err.get("code") in _APPROVAL_CODES:
            return "approval"
        sqlstate = err.get("sqlstate")
        return ERROR_LAYER_BY_SQLSTATE.get(str(sqlstate), f"error:{sqlstate}")
    if response.status in (401, 403):
        return "oauth"
    if expected in _ERROR_LAYERS:
        return "none"  # should have been blocked by an error layer, but the call succeeded
    return expected or "ok"


@dataclasses.dataclass
class Runner:
    client: StackClient
    admin_dsn: str
    machine_secrets: dict[str, str] = dataclasses.field(default_factory=dict)
    allow_load: bool = False
    _tokens: dict[str, Tokens] = dataclasses.field(default_factory=dict)

    async def _token(self, identity: str) -> Tokens:
        if identity not in self._tokens:
            if identity in self.machine_secrets:
                self._tokens[identity] = await self.client.machine_token(
                    identity, self.machine_secrets[identity]
                )
            else:
                self._tokens[identity] = await self.client.login(IDP_SUB[identity])
        return self._tokens[identity]

    async def run_case(self, case: dict[str, Any], admin: asyncpg.Connection) -> CaseResult:
        must_block = case.get("must_block", "expected_layer" in case)
        category = case["category"]
        table = _TABLE_FOR_CATEGORY.get(category)
        before = await table_checksum(admin, table) if table else None

        token = await self._token(case["identity"])
        args = case.get("args", {})
        started = time.perf_counter()
        response = await mcp_client.call_tool(
            self.client.resource, token.access_token, case["tool"], args
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        if not must_block:
            ok = response.tool_error is None and response.status == 200
            if case.get("residual_risk"):
                # A documented residual risk: record the behaviour, count it nowhere.
                return CaseResult(
                    case["id"],
                    category,
                    case["title"],
                    "residual",
                    False,
                    blocked=False,
                    passed=True,
                    expected_layer=None,
                    observed_layer=observed_layer(response, None),
                    detail=f"residual risk ({case['residual_risk']}): "
                    + ("the call returns data, as documented" if ok else "the call was refused"),
                )
            return CaseResult(
                case["id"],
                category,
                case["title"],
                "benign",
                False,
                blocked=False,
                passed=ok,
                expected_layer=None,
                observed_layer=observed_layer(response, None),
                detail="benign control succeeded"
                if ok
                else f"benign control failed: {response.text[:120]}",
            )

        expected = case.get("expected_layer")
        observed = observed_layer(response, expected)
        # a fresh whoami confirms the gateway is still healthy after the attack
        healthy = (
            await mcp_client.call_tool(self.client.resource, token.access_token, "whoami", {})
        ).result.get("pg_role") is not None

        ctx = OracleContext(
            response=response,
            admin=admin,
            identity=case["identity"],
            region_for_identity=REGION_FOR_IDENTITY,
        )
        oracle_details: list[str] = []
        blocked = True
        for spec in case.get("oracles", []):
            otype = spec["type"]
            oracle = ORACLES.get(otype)
            if oracle is None:
                oracle_details.append(f"{otype}: UNKNOWN ORACLE")
                blocked = False
                continue
            enriched = {**spec, "elapsed_ms": elapsed_ms, "healthy_after": healthy}
            if otype == "table_checksum_unchanged":
                enriched.setdefault("table", table or "refunds")
                enriched["before"] = (
                    before
                    if enriched["table"] == table
                    else await table_checksum(admin, enriched["table"])
                )
            outcome = await oracle(ctx, enriched)
            oracle_details.append(f"{otype}: {outcome.detail}")
            blocked = blocked and outcome.blocked
        # RLS/masking cases without an explicit foreign-row oracle: check data too
        if category == "D" and not any(
            o["type"] == "response_excludes_foreign_rows" for o in case.get("oracles", [])
        ):
            outcome = await ORACLES["response_excludes_foreign_rows"](ctx, {})
            oracle_details.append(f"foreign_rows: {outcome.detail}")
            blocked = blocked and outcome.blocked

        layer_ok = observed == expected
        passed = blocked and layer_ok
        detail = "; ".join(oracle_details)
        if not layer_ok:
            detail = f"layer expected {expected}, observed {observed}. {detail}"
        return CaseResult(
            case["id"],
            category,
            case["title"],
            "attack",
            True,
            blocked,
            passed,
            expected,
            observed,
            detail,
        )

    async def run(self, cases: list[dict[str, Any]]) -> list[CaseResult]:
        admin = await asyncpg.connect(self.admin_dsn, timeout=10)
        results: list[CaseResult] = []
        try:
            for case in cases:
                is_flood = case["id"].startswith("F") and "flood" in case.get("title", "").lower()
                if is_flood and not self.allow_load:
                    continue
                results.append(await self.run_case(case, admin))
        finally:
            await admin.close()
        return results


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    by_cat: dict[str, dict[str, Any]] = {}
    for r in results:
        cat = by_cat.setdefault(r.category, {"attacks": 0, "blocked": 0, "layers": set()})
        if r.must_block:
            cat["attacks"] += 1
            if r.passed:
                cat["blocked"] += 1
            cat["layers"].add(r.observed_layer)
    must = [r for r in results if r.kind == "attack"]
    benign = [r for r in results if r.kind == "benign"]
    residual = [r for r in results if r.kind == "residual"]
    return {
        "must_block_total": len(must),
        "must_block_blocked": sum(1 for r in must if r.passed),
        "benign_total": len(benign),
        "benign_passed": sum(1 for r in benign if r.passed),
        "residual_risks": [{"id": r.id, "title": r.title, "detail": r.detail} for r in residual],
        "by_category": {
            cat: {
                "attacks": v["attacks"],
                "blocked": v["blocked"],
                "layers": sorted(layer for layer in v["layers"] if layer),
            }
            for cat, v in sorted(by_cat.items())
        },
        "failures": [
            {
                "id": r.id,
                "expected": r.expected_layer,
                "observed": r.observed_layer,
                "detail": r.detail,
            }
            for r in results
            if not r.passed
        ],
    }


__all__ = ["CaseResult", "Runner", "load_corpus", "observed_layer", "summarize"]
