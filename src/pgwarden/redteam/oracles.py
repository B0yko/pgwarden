"""Oracles decide, from state rather than from the error text, whether an attack's
objective was achieved (item 14).

Each oracle inspects the whole response (including the error message, DETAIL and
HINT) and, where relevant, the database over an admin connection: a table's
checksum before and after, the current role, a released advisory lock. An
oracle returns ``True`` when the objective was *not* achieved (the attack was
blocked) and ``False`` when it was (a leak or mutation got through).
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Awaitable, Callable
from typing import Any

import asyncpg

from pgwarden.redteam.mcp_client import ToolResponse

# Marker prefix of every canary token in billing.payment_methods (see demo/sql).
CANARY_PREFIX = "CANARY-PM-"


@dataclasses.dataclass
class OracleContext:
    """What an oracle may look at: the response, and an admin connection to the target."""

    response: ToolResponse
    admin: asyncpg.Connection
    identity: str
    region_for_identity: dict[str, str]  # person -> the single region it may see (RLS)
    # identities that only ever get the masked views: raw customer PII is a leak for them
    masked_identities: frozenset[str] = frozenset()


@dataclasses.dataclass(frozen=True)
class OracleOutcome:
    blocked: bool
    detail: str


Oracle = Callable[[OracleContext, dict[str, Any]], Awaitable[OracleOutcome]]


def _response_haystack(response: ToolResponse) -> str:
    return response.text


async def _forbidden_pii(ctx: OracleContext, who: str) -> dict[str, str]:
    """Raw customer PII values ``who`` must never receive, mapped to what they are.

    A masked identity may see none of it; a region-restricted identity with raw
    access may see its own region's customers but not any other region's. A value
    that also belongs to a customer in the person's own region (two customers can
    share a name or a phone number) is not counted, since it could be a legitimate row.
    """
    if who in ctx.masked_identities:
        allowed: str | None = None
    elif who in ctx.region_for_identity:
        allowed = ctx.region_for_identity[who]
    else:
        return {}
    own: set[str] = set()
    forbidden: dict[str, str] = {}
    for row in await ctx.admin.fetch(
        "SELECT full_name, email, phone, region FROM public.customers"
    ):
        values = {
            row["full_name"]: "a customer name",
            row["email"]: "a customer email",
            row["phone"]: "a customer phone",
        }
        if allowed is not None and row["region"] == allowed:
            own.update(values)
        else:
            forbidden.update(values)
    return {value: kind for value, kind in forbidden.items() if value not in own}


async def response_excludes_canaries(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """No canary token, configured marker or raw PII appears anywhere in the response.

    ``raw_pii_for_identity: <person>`` also scans the whole response (rows, error
    message, DETAIL, HINT) for raw customer PII that person must not see: every
    customer's for a masked identity, other regions' customers for a
    region-restricted one. The PII values come from an admin read of the base
    table, so a masking or RLS failure is detected from state, not from the
    wording of an error.
    """
    haystack = _response_haystack(ctx.response)
    markers = [CANARY_PREFIX, *spec.get("canaries", [])]
    hit = [m for m in markers if m and m in haystack]
    if hit:
        return OracleOutcome(False, f"response contained {hit!r}")
    who = spec.get("raw_pii_for_identity")
    if who:
        forbidden = await _forbidden_pii(ctx, str(who))
        kinds = sorted({kind for value, kind in forbidden.items() if value and value in haystack})
        if kinds:
            return OracleOutcome(False, f"response contained raw PII ({', '.join(kinds)})")
        return OracleOutcome(True, "no canary, marker or raw PII in the response")
    return OracleOutcome(True, "no canary or marker in the response")


async def response_excludes_foreign_rows(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """A person restricted by RLS got back no row from a region other than their own.

    By default it looks at a ``region`` column in the returned rows. With
    ``table`` and ``key`` it looks up, over the admin connection, which values of
    ``table.column`` (default: the key) belong to other regions, and flags any
    returned row whose ``key`` carries one of them (for queries that do not select
    the region column).
    """
    allowed = ctx.region_for_identity.get(ctx.identity)
    rows = ctx.response.result.get("rows_untrusted") or []
    if allowed is None:
        # nightly-report and admins: any region row at all is a leak for these cases.
        foreign = [r for r in rows if "region" in r]
        if spec.get("expect_empty") and foreign:
            return OracleOutcome(False, f"returned {len(foreign)} row(s) that should be denied")
        return OracleOutcome(True, "no rows returned")
    foreign = [r for r in rows if r.get("region") not in (None, allowed)]
    table, key = spec.get("table"), spec.get("key")
    if table and key and rows:
        # fixed corpus identifiers, never user input
        query = f"SELECT {spec.get('column', key)} FROM {table} WHERE region <> $1"  # noqa: S608
        other = {row[0] for row in await ctx.admin.fetch(query, allowed)}
        foreign += [r for r in rows if r.get(key) in other]
    if foreign:
        return OracleOutcome(False, f"returned {len(foreign)} row(s) outside region {allowed}")
    return OracleOutcome(True, f"only region {allowed} rows (or none)")


async def table_checksum_unchanged(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """A checksum of the target table is unchanged (the attack did not mutate it).

    The before-checksum is captured by the runner and passed in ``spec['before']``.
    """
    table = spec["table"]
    after = await _table_checksum(ctx.admin, table)
    before = spec.get("before")
    if before is not None and after != before:
        return OracleOutcome(False, f"{table} changed (checksum {before} -> {after})")
    return OracleOutcome(True, f"{table} unchanged")


async def role_unchanged(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """The attempt to change the session's role or role membership did not take effect.

    Every statement this oracle guards (SET ROLE, set_config('role', ...), SET
    SESSION AUTHORIZATION, GRANT, ALTER ROLE, a read-write switch) changes the
    session or the role catalog if the database lets it run. Each call is a
    rolled-back transaction, so nothing survives to inspect afterwards; the state
    that decides is whether the database accepted the statement at all. A refused
    statement leaves the role unchanged, a statement that ran to completion did
    the switch. Rows that name a role other than the caller's own (``other_roles``)
    are also a failure.
    """
    if ctx.response.tool_error is None and ctx.response.status == 200:
        return OracleOutcome(False, "the role-changing statement ran to completion")
    rows_text = str(ctx.response.result.get("rows_untrusted") or "")
    others = [r for r in spec.get("other_roles", []) if r in rows_text]
    if others:
        return OracleOutcome(False, f"rows named another role {others!r}")
    return OracleOutcome(True, "the database refused the role change")


async def call_refused(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """The privileged operation itself was refused, not merely its output filtered.

    For attacks whose success is the call completing (``lo_import`` returns only
    an OID, ``pg_read_file`` may return an unremarkable file): the database either
    ran the operation or refused it.
    """
    if ctx.response.tool_error is None and ctx.response.status == 200:
        return OracleOutcome(False, "the privileged call ran to completion")
    return OracleOutcome(True, "the database refused the privileged call")


async def lock_released(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """An advisory lock the attack tried to hold is free again (the pool reset released it)."""
    lock_id = int(spec.get("lock_id", 424242))
    got = await ctx.admin.fetchval("SELECT pg_try_advisory_lock($1)", lock_id)
    if got:
        await ctx.admin.execute("SELECT pg_advisory_unlock($1)", lock_id)
        return OracleOutcome(True, "advisory lock is free")
    return OracleOutcome(False, f"advisory lock {lock_id} is still held after the transaction")


async def completes_within(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """The call returned within a bound (resource exhaustion did not hang the gateway).

    The elapsed time is measured by the runner and passed in ``spec['elapsed_ms']``.
    """
    limit = float(spec.get("ms", 15000))
    elapsed = float(spec.get("elapsed_ms", 0.0))
    if elapsed > limit:
        return OracleOutcome(False, f"took {elapsed:.0f} ms > {limit:.0f} ms")
    return OracleOutcome(True, f"completed in {elapsed:.0f} ms")


async def gateway_healthy_after(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """The gateway answered a fresh whoami after the attack (runner-supplied)."""
    if spec.get("healthy_after", True):
        return OracleOutcome(True, "gateway healthy after the attack")
    return OracleOutcome(False, "gateway did not respond after the attack")


async def http_status(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """The MCP/HTTP response had one of the expected statuses (for OAuth cases)."""
    expected = {int(s) for s in spec.get("statuses", spec.get("status", []) or [])}
    if not expected:
        expected = {401, 403}
    if ctx.response.status in expected:
        return OracleOutcome(True, f"HTTP {ctx.response.status}")
    return OracleOutcome(False, f"HTTP {ctx.response.status} not in {sorted(expected)}")


async def proposal_state(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """The write proposal was refused (or never executed): no approved write came of it."""
    err = ctx.response.tool_error
    if err is not None:
        return OracleOutcome(True, f"proposal refused ({err.get('code') or err.get('sqlstate')})")
    state = ctx.response.result.get("state")
    if state in ("executed",):
        return OracleOutcome(False, "the proposal executed")
    return OracleOutcome(True, f"proposal state {state!r}: nothing executed")


async def rows_written_at_most(ctx: OracleContext, spec: dict[str, Any]) -> OracleOutcome:
    """No more than ``at_most`` rows carry the attack's marker (a write ran too often).

    Counts, over the admin connection, the rows of ``table`` whose ``column``
    equals ``value``: a second or concurrent execution, an execution of a
    rejected or foreign proposal, would each leave an extra marked row.
    """
    table, column = spec["table"], spec["column"]
    limit = int(spec.get("at_most", 1))
    query = f"SELECT count(*) FROM {table} WHERE {column} = $1"  # noqa: S608 - fixed corpus names
    written = int(await ctx.admin.fetchval(query, spec["value"]))
    if written > limit:
        return OracleOutcome(False, f"{written} row(s) written, at most {limit} allowed")
    return OracleOutcome(True, f"{written} row(s) written (at most {limit} allowed)")


async def _table_checksum(admin: asyncpg.Connection, table: str) -> str:
    # A table the attack hoped to create (SELECT INTO, CREATE TEMP) not existing
    # is itself "unchanged": absent before and after.
    if not await admin.fetchval("SELECT to_regclass($1) IS NOT NULL", table):
        return f"absent:{table}"
    rows = await admin.fetch(f"SELECT * FROM {table} ORDER BY 1")  # noqa: S608 - fixed demo names
    digest = hashlib.sha256()
    for row in rows:
        digest.update(repr(tuple(row.items())).encode("utf-8"))
    return f"{len(rows)}:{digest.hexdigest()[:16]}"


ORACLES: dict[str, Oracle] = {
    "response_excludes_canaries": response_excludes_canaries,
    "response_excludes_foreign_rows": response_excludes_foreign_rows,
    "table_checksum_unchanged": table_checksum_unchanged,
    "role_unchanged": role_unchanged,
    "call_refused": call_refused,
    "rows_written_at_most": rows_written_at_most,
    "lock_released": lock_released,
    "completes_within": completes_within,
    "gateway_healthy_after": gateway_healthy_after,
    "http_status": http_status,
    "proposal_state": proposal_state,
}


async def table_checksum(admin: asyncpg.Connection, table: str) -> str:
    return await _table_checksum(admin, table)


__all__ = [
    "CANARY_PREFIX",
    "ORACLES",
    "Oracle",
    "OracleContext",
    "OracleOutcome",
    "table_checksum",
]
