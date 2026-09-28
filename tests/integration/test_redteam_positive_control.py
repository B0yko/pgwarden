"""Positive control for the red-team oracles (spec item 14).

An oracle that never fires proves nothing. This test replays the SQL-bearing
must-block cases of categories C, D, E and G over a deliberately unsafe
connection (a scratch superuser session: no privilege checks, RLS bypassed, no
masking views on the search path), and the oracles must flag at least 90% of
them as *achieved*. It is test-only: nothing here is part of the product, and
every case runs in a transaction that is always rolled back, so the scratch
cluster is left as it was found.
"""

from __future__ import annotations

import json
from typing import Any

import asyncpg
import pytest

from pgwarden.db.serialize import serialize_value
from pgwarden.redteam.mcp_client import ToolResponse
from pgwarden.redteam.oracles import ORACLES, OracleContext
from pgwarden.redteam.runner import MASKED_IDENTITIES, REGION_FOR_IDENTITY, load_corpus

pytestmark = pytest.mark.pg

CATEGORIES = "CDEG"
ROW_CAP = 500  # the gateway's default row_cap, so responses have the same shape
THRESHOLD = 0.90

# The metadata tools, expressed as the raw catalog queries an unrestricted session runs.
_TOOL_SQL = {
    "describe_table": (
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = split_part($1, '.', 1) AND table_name = split_part($1, '.', 2)"
    ),
    "list_tables": "SELECT table_schema, table_name FROM information_schema.tables "
    "WHERE table_schema = $1",
}


def _tool_response(result: dict[str, Any]) -> ToolResponse:
    body = {"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {"result": result}}}
    return ToolResponse(status=200, text=json.dumps(body), body=body)


async def _unsafe_call(dsn: str, case: dict[str, Any]) -> ToolResponse:
    """Run one corpus case as a superuser, inside a transaction that is rolled back."""
    args = case.get("args", {})
    tool = case["tool"]
    if tool == "query":
        sql, params = args["sql"], list(args.get("params", []))
    else:
        sql = _TOOL_SQL[tool]
        params = [args.get("name", args.get("schema", "public"))]
        if tool == "describe_table" and "." not in params[0]:
            params = [f"public.{params[0]}"]
    conn = await asyncpg.connect(dsn, timeout=10)
    tx = conn.transaction()
    await tx.start()
    try:
        try:
            stmt = await conn.prepare(sql)
            records = (await stmt.fetch(*params))[:ROW_CAP]
        except asyncpg.PostgresError as exc:
            return _tool_response(
                {"error": {"sqlstate": exc.sqlstate, "message": str(exc), "detail": exc.detail}}
            )
        rows = [{k: serialize_value(v) for k, v in dict(r).items()} for r in records]
        return _tool_response({"rows_untrusted": rows, "row_count": len(rows)})
    finally:
        await tx.rollback()
        await conn.close()


async def _achieved(
    admin: asyncpg.Connection, case: dict[str, Any], response: ToolResponse
) -> bool:
    """True when any of the case's oracles reports the attack objective as achieved."""
    ctx = OracleContext(
        response=response,
        admin=admin,
        identity=case["identity"],
        region_for_identity=REGION_FOR_IDENTITY,
        masked_identities=MASKED_IDENTITIES,
    )
    specs = list(case.get("oracles", []))
    if case["category"] == "D" and not any(
        s["type"] == "response_excludes_foreign_rows" for s in specs
    ):
        specs.append({"type": "response_excludes_foreign_rows"})  # the runner adds this too
    for spec in specs:
        outcome = await ORACLES[spec["type"]](ctx, spec)
        if not outcome.blocked:
            return True
    return False


async def test_oracles_flag_at_least_90_percent_on_an_unsafe_connection(
    pg_shop_dsn: str, pg_demo_masking: None
) -> None:
    cases = [
        c
        for c in load_corpus()
        if c["category"] in CATEGORIES
        and c.get("expected_layer")
        and c.get("must_block", True)
        and c.get("tool") in ("query", "describe_table", "list_tables")
    ]
    assert len(cases) >= 30
    admin = await asyncpg.connect(pg_shop_dsn, timeout=10)
    flagged: list[str] = []
    missed: list[str] = []
    try:
        for case in cases:
            response = await _unsafe_call(pg_shop_dsn, case)
            (flagged if await _achieved(admin, case, response) else missed).append(case["id"])
    finally:
        await admin.close()
    ratio = len(flagged) / len(cases)
    print(f"unsafe run: flagged {len(flagged)}/{len(cases)} ({ratio:.0%}); not flagged: {missed}")
    assert ratio >= THRESHOLD, f"only {ratio:.0%} flagged; missed {missed}"


async def test_the_same_oracles_stay_quiet_for_a_refused_call(pg_shop_dsn: str) -> None:
    """The control's other half: a refusal is not flagged, so the 90% is not always-true."""
    admin = await asyncpg.connect(pg_shop_dsn, timeout=10)
    try:
        refused = _tool_response({"error": {"sqlstate": "42501", "message": "permission denied"}})
        case = {"category": "C", "identity": "bob", "oracles": [{"type": "role_unchanged"}]}
        assert not await _achieved(admin, case, refused)
    finally:
        await admin.close()
