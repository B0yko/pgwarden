"""Shared pytest fixtures.

Integration tests (marker ``pg``) need a superuser DSN in
``PGWARDEN_TEST_ADMIN_DSN`` (see ``devtools/testpg.sh up``). Without it they
are skipped, unless ``PGWARDEN_REQUIRE_PG=1`` turns the skip into a failure
(used in CI so a missing test database is loud, not silent).

Login roles are cluster-global, so `roles sync`-dependent fixtures are
session-scoped and tests that use them must run serially (no xdist).
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "demo"))

TEST_ADMIN_DSN_VAR = "PGWARDEN_TEST_ADMIN_DSN"
REQUIRE_PG_VAR = "PGWARDEN_REQUIRE_PG"

TEST_ROLE_SECRET = "pgwarden-test-role-secret-do-not-use-in-prod"
TEST_STATE_APP_PASSWORD = "pgwarden-test-state-app-password"  # noqa: S105 (test fixture, not a real secret)


def with_dbname(dsn: str, dbname: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, ""))


def with_role(dsn: str, role: str, password: str) -> str:
    parts = urlsplit(dsn)
    netloc = f"{role}:{password}@{parts.hostname}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def target_dsn(dsn: str, dbname: str) -> str:
    """Host/port/database/sslmode only, no user/password: what ``PGWARDEN_TARGET_DSN`` carries."""
    parts = urlsplit(dsn)
    netloc = f"{parts.hostname}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, f"/{dbname}", "sslmode=disable", ""))


@pytest.fixture(scope="session")
def pg_admin_dsn() -> str:
    dsn = os.environ.get(TEST_ADMIN_DSN_VAR)
    if dsn:
        return dsn
    if os.environ.get(REQUIRE_PG_VAR) == "1":
        pytest.fail(f"{TEST_ADMIN_DSN_VAR} is required when {REQUIRE_PG_VAR}=1")
    pytest.skip(f"{TEST_ADMIN_DSN_VAR} not set; run devtools/testpg.sh up")


async def _recreate_database(admin_dsn: str, dbname: str) -> None:
    admin = await asyncpg.connect(admin_dsn, timeout=10)
    try:
        # WITH (FORCE) (PG13+): a previous session -- most likely a pooled
        # backend connection left open by the test PgBouncer fixture
        # (tests/integration/test_doctor.py), which does not close its idle
        # server connections just because the client disconnected -- must
        # never make this fixture flaky.
        await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        await admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await admin.close()


@pytest.fixture(scope="session")
def pg_shop_dsn(pg_admin_dsn: str) -> str:
    """A fresh ``pgw_shop`` database, loaded with demo SQL once per session."""
    from load import load_demo_sql  # demo/load.py

    dsn = with_dbname(pg_admin_dsn, "pgw_shop")

    async def setup() -> None:
        await _recreate_database(pg_admin_dsn, "pgw_shop")
        await load_demo_sql(dsn)

    asyncio.run(setup())
    return dsn


@pytest.fixture(scope="session")
def pg_state_dsn(pg_admin_dsn: str) -> str:
    """A fresh, migrated ``pgw_state`` database, connecting as ``pgwarden_app``."""
    from pgwarden.state.bootstrap import db_init

    state_dsn = with_role(
        with_dbname(pg_admin_dsn, "pgw_state"), "pgwarden_app", TEST_STATE_APP_PASSWORD
    )

    async def setup() -> None:
        await _recreate_database(pg_admin_dsn, "pgw_state")
        admin = await asyncpg.connect(pg_admin_dsn, timeout=10)
        try:
            await admin.execute("DROP ROLE IF EXISTS pgwarden_app")
        finally:
            await admin.close()
        await db_init(pg_admin_dsn, state_dsn)

    asyncio.run(setup())
    return state_dsn


@pytest.fixture(scope="session")
def pg_target_dsn(pg_admin_dsn: str) -> str:
    """``pgw_shop``'s host/port/db/sslmode only -- what a `PoolManager` connects with."""
    return target_dsn(pg_admin_dsn, "pgw_shop")


@pytest.fixture(scope="session")
def pg_role_secret() -> str:
    return TEST_ROLE_SECRET


@pytest.fixture(scope="session")
def pg_demo_config() -> object:
    from pgwarden.config import load_config

    return load_config(REPO_ROOT / "demo" / "pgwarden.yaml")


@pytest.fixture(scope="session")
def pg_demo_roles(pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object) -> None:
    """Runs `roles sync` for the demo config once per session."""
    from pgwarden.config import Config
    from pgwarden.db.provisioning import sync_roles

    assert isinstance(pg_demo_config, Config)

    async def setup() -> None:
        await sync_roles(pg_demo_config, pg_shop_dsn, pg_role_secret, dry_run=False)

    asyncio.run(setup())


@pytest.fixture(scope="session")
def pg_person_dsn(
    pg_shop_dsn: str, pg_role_secret: str, pg_demo_roles: None
) -> Callable[[str], str]:
    """``pg_person_dsn("pw_u_bob")`` -> a DSN that logs in as that role."""
    from pgwarden.db.scram import derive_password

    def _dsn(role_name: str) -> str:
        password = derive_password(pg_role_secret, role_name)
        return with_role(pg_shop_dsn, role_name, password)

    return _dsn
