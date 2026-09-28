"""Validate a proposed write by asking Postgres, not by parsing SQL.

The proposal is prepared as ``EXPLAIN (FORMAT JSON) <user SQL>`` on the
person's own connection, after ``set_config('role', <writer role>, true)``,
with the actual parameters bound. That one prefix is the only text pgwarden
ever adds to user SQL. Postgres then does all the work: Parse rejects a second
statement (42601), EXPLAIN rejects DDL, COPY and other utility statements,
planning checks the writer role's privileges (42501), and a statement prepared
earlier on another connection does not exist here. The transaction is always
rolled back; EXPLAIN without ANALYZE never executes the statement.

The proposal is accepted only if the whole plan tree, including InitPlans and
CTE subplans, contains exactly one ``ModifyTable`` node, that node is the root,
and its operation is Insert, Update or Delete. That rejects a SELECT with a
data-modifying CTE, ``WITH d AS (DELETE ...) INSERT ...``, MERGE and anything
else that is not a single plain INSERT, UPDATE or DELETE.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator
from typing import Any

import asyncpg

from pgwarden.db.params import coerce_params
from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import statement_name

EXPLAIN_PREFIX = "EXPLAIN (FORMAT JSON) "
_ALLOWED_OPERATIONS = frozenset({"Insert", "Update", "Delete"})

# pgwarden's own fixed SQL with bound values; never interpolated.
_SET_CONFIG_SQL = (
    "SELECT set_config('role', $1, true), "
    "set_config('statement_timeout', $2, true), "
    "set_config('lock_timeout', $3, true), "
    "set_config('application_name', $4, true)"
)


@dataclasses.dataclass(frozen=True)
class PlanSummary:
    operation: str
    relation: str | None
    estimated_rows: int | None


@dataclasses.dataclass(frozen=True)
class ValidationResult:
    ok: bool
    plan: PlanSummary | None = None
    sqlstate: str | None = None
    reason: str | None = None


def _walk(node: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield node
    for child in node.get("Plans", []) or []:
        if isinstance(child, dict):
            yield from _walk(child)


def check_plan(plan_json: Any) -> ValidationResult:
    """Apply the single-root-ModifyTable rule to ``EXPLAIN (FORMAT JSON)`` output."""
    if isinstance(plan_json, str):
        plan_json = json.loads(plan_json)
    if not isinstance(plan_json, list) or not plan_json or not isinstance(plan_json[0], dict):
        return ValidationResult(False, reason="unexpected EXPLAIN output")
    root = plan_json[0].get("Plan")
    if not isinstance(root, dict):
        return ValidationResult(False, reason="unexpected EXPLAIN output")

    modify_nodes = [n for n in _walk(root) if n.get("Node Type") == "ModifyTable"]
    if not modify_nodes:
        return ValidationResult(False, reason="the statement does not write (no ModifyTable node)")
    if len(modify_nodes) > 1:
        return ValidationResult(
            False,
            reason=(
                "the statement writes more than once (a data-modifying CTE or subplan); "
                "propose one plain INSERT, UPDATE or DELETE"
            ),
        )
    if root.get("Node Type") != "ModifyTable":
        return ValidationResult(
            False, reason="the write is not the top-level statement (it sits inside a CTE)"
        )
    operation = root.get("Operation")
    if operation not in _ALLOWED_OPERATIONS:
        return ValidationResult(
            False, reason=f"operation {operation!r} is not allowed; use INSERT, UPDATE or DELETE"
        )

    children = root.get("Plans") or []
    estimate: int | None = None
    if children and isinstance(children[0], dict) and "Plan Rows" in children[0]:
        estimate = int(children[0]["Plan Rows"])
    elif "Plan Rows" in root:
        estimate = int(root["Plan Rows"])
    relation = root.get("Relation Name")
    return ValidationResult(
        True,
        plan=PlanSummary(
            operation=str(operation),
            relation=str(relation) if relation is not None else None,
            estimated_rows=estimate,
        ),
    )


async def validate_write(
    pool_manager: PoolManager,
    role_name: str,
    writer_role: str,
    sql: str,
    params: list[Any],
    *,
    statement_timeout_ms: int = 5000,
    lock_timeout_ms: int = 1000,
) -> ValidationResult:
    """EXPLAIN ``sql`` as ``writer_role`` on ``role_name``'s connection; always rolled back."""
    try:
        async with pool_manager.acquire(role_name) as conn:
            tx = conn.transaction()
            await tx.start()
            try:
                await conn.execute(
                    _SET_CONFIG_SQL,
                    writer_role,
                    str(statement_timeout_ms),
                    str(lock_timeout_ms),
                    f"pgwarden:{role_name}:propose",
                )
                # Extended-protocol Parse of the prefixed user SQL: a second
                # statement is rejected here with 42601.
                stmt = await conn.prepare(EXPLAIN_PREFIX + sql, name=statement_name())
                coerced = coerce_params(params, stmt.get_parameters())
                plan = await stmt.fetchval(*coerced)
            finally:
                await tx.rollback()
    except asyncpg.PostgresError as exc:
        return ValidationResult(
            False,
            sqlstate=getattr(exc, "sqlstate", None),
            reason=str(exc),
        )
    except (asyncpg.InterfaceError, asyncpg.DataError, ValueError, TypeError) as exc:
        return ValidationResult(False, reason=f"could not bind the parameters: {exc}")
    return check_plan(plan)


__all__ = [
    "EXPLAIN_PREFIX",
    "PlanSummary",
    "ValidationResult",
    "check_plan",
    "validate_write",
]
