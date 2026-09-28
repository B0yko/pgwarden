"""ADR-0002's experiment, run for real: does the shared-login escalation reproduce?

Writes the observed one-paragraph result to
``~/Documents/portfolio/_work/pgwarden/adr0002-result.txt`` (outside the
repo -- ADRs are not written into the repo until a later step) so ADR-0002
can quote it verbatim.
"""

from __future__ import annotations

from pathlib import Path

import asyncpg
import pytest

from pgwarden.db.shared_login_experiment import run_experiment

pytestmark = pytest.mark.pg

_RESULT_FILE = Path.home() / "Documents" / "portfolio" / "_work" / "pgwarden" / "adr0002-result.txt"


async def test_shared_login_escalation_reproduces(pg_shop_dsn: str) -> None:
    result = await run_experiment(pg_shop_dsn)

    # The spec's research predicts this reproduces on Postgres 16 for
    # dynamic SQL (query_to_xml); assert the observed behaviour either way
    # (never assume it silently).
    assert result.dynamic_sql_escalation_reproduced is True
    assert result.dynamic_sql_leaked_xml is not None
    assert "secret_b" in result.dynamic_sql_leaked_xml

    # A plain *static* subquery in the same target list is a separate,
    # narrower question this experiment also measures: Postgres checks the
    # whole plan tree's permissions upfront, so this is expected to NOT
    # leak (see the module docstring) -- assert the observed behaviour
    # either way rather than assume it.
    assert result.static_subquery_escalation_reproduced is False
    assert result.static_subquery_leaked_value is None

    # And the defense pgwarden's actual design (a per-person login role,
    # nothing to SET ROLE to) relies on: SET SESSION AUTHORIZATION blocked.
    assert result.session_authorization_blocked is True
    assert result.session_authorization_error is not None

    _RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _RESULT_FILE.write_text(result.summary + "\n", encoding="utf-8")


async def test_scratch_objects_cleaned_up_after_experiment(pg_shop_dsn: str) -> None:
    await run_experiment(pg_shop_dsn)

    conn = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        schema_exists = await conn.fetchval(
            "SELECT 1 FROM pg_namespace WHERE nspname = 'pw_shared_login_experiment'"
        )
        role_exists = await conn.fetchval(
            "SELECT 1 FROM pg_roles WHERE rolname = 'pw_experiment_gw_login'"
        )
    finally:
        await conn.close()
    assert schema_exists is None
    assert role_exists is None


async def test_experiment_is_repeatable(pg_shop_dsn: str) -> None:
    first = await run_experiment(pg_shop_dsn)
    second = await run_experiment(pg_shop_dsn)
    assert first.dynamic_sql_escalation_reproduced == second.dynamic_sql_escalation_reproduced
    assert (
        first.static_subquery_escalation_reproduced == second.static_subquery_escalation_reproduced
    )
    assert first.session_authorization_blocked == second.session_authorization_blocked
