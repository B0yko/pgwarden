"""Follow docs/own-database.md literally against a plain Postgres 16 (item 16).

A DBA's migration creates a bundle role, a table, RLS keyed on session_user, and a
masking tag; then pgwarden's own commands run (db init, roles sync, masking apply,
doctor) and the person queries their data as themselves, seeing only their rows and
masked PII. This mirrors the documented setup for a user's own database.
"""

from __future__ import annotations

import os

import asyncpg
import pytest

from pgwarden.config import (
    Config,
    IdentityRef,
    MaskingConfig,
    PersonConfig,
    UpstreamConfig,
)
from pgwarden.db.doctor import run_doctor
from pgwarden.db.masking import apply_masking
from pgwarden.db.pools import PoolManager
from pgwarden.db.provisioning import sync_roles
from pgwarden.db.readpath import run_read_query
from pgwarden.db.scram import derive_password
from pgwarden.state.bootstrap import db_init

pytestmark = pytest.mark.pg

ROLE_SECRET = "own-db-test-role-secret"  # noqa: S105 (test fixture)
APP_PASSWORD = "own-db-test-app-password"  # noqa: S105


def _admin_dsn() -> str:
    dsn = os.environ.get("OWN_DB_ADMIN_DSN") or os.environ.get("PGWARDEN_TEST_ADMIN_DSN")
    if not dsn:
        if os.environ.get("PGWARDEN_REQUIRE_PG") == "1":
            pytest.fail("OWN_DB_ADMIN_DSN or PGWARDEN_TEST_ADMIN_DSN is required")
        pytest.skip("no admin DSN for the own-database test")
    return dsn


def _with_db(dsn: str, dbname: str, *, user: str | None = None, password: str | None = None) -> str:
    from urllib.parse import urlsplit, urlunsplit

    p = urlsplit(dsn)
    host = p.hostname or "127.0.0.1"
    if user:
        netloc = f"{user}:{password}@{host}:{p.port or 5432}"
    else:
        netloc = p.netloc
    return urlunsplit((p.scheme, netloc, f"/{dbname}", "sslmode=disable", ""))


async def _dba_migration(admin_dsn: str) -> None:
    """The DBA's own migration: a bundle, a table, RLS on session_user, a masking tag."""
    conn = await asyncpg.connect(admin_dsn, timeout=10)
    try:
        await conn.execute("DROP TABLE IF EXISTS public.reports")
        await conn.execute("DROP SCHEMA IF EXISTS internal CASCADE")
        for role in ("readers", "pw_u_rowan"):
            await conn.execute(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') "
                f"THEN CREATE ROLE {role} NOLOGIN; END IF; END $$"
            )
        await conn.execute("ALTER ROLE readers NOLOGIN")
        await conn.execute(
            "CREATE SCHEMA internal; "
            "CREATE TABLE internal.reader_team (login_role text, team text); "
            "INSERT INTO internal.reader_team VALUES ('pw_u_rowan', 'eu'); "
            "CREATE FUNCTION internal.my_team() RETURNS text LANGUAGE sql STABLE "
            "SECURITY DEFINER SET search_path = internal, pg_catalog AS "
            "$$ SELECT team FROM internal.reader_team WHERE login_role = session_user LIMIT 1 $$"
        )
        await conn.execute(
            "CREATE TABLE public.reports (id int PRIMARY KEY, team text NOT NULL, "
            "owner_email text NOT NULL, body text NOT NULL); "
            "INSERT INTO public.reports VALUES "
            "(1,'eu','anna@example.com','eu report'),(2,'us','ulf@example.com','us report')"
        )
        await conn.execute("ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY")
        await conn.execute(
            "CREATE POLICY team_isolation ON public.reports FOR ALL TO PUBLIC "
            "USING (team = internal.my_team()) WITH CHECK (team = internal.my_team())"
        )
        await conn.execute("GRANT USAGE ON SCHEMA public TO readers")
        await conn.execute("GRANT SELECT ON public.reports TO readers")
        await conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    finally:
        await conn.close()


def _config() -> Config:
    return Config(
        public_url="https://pgwarden.example.com",
        upstream=UpstreamConfig(
            name="corp", issuer="https://idp.example.com", client_id="pgwarden"
        ),
        people=[
            PersonConfig(
                identity=IdentityRef(email="rowan@example.com"), role="rowan", bundles=["readers"]
            )
        ],
        masking=MaskingConfig(
            columns={"public.reports.owner_email": "email"},
            view_grants={"public.reports": ["readers"]},
        ),
        rls_required=["public.reports"],
    )


async def test_own_database_setup_end_to_end() -> None:
    admin = _admin_dsn()
    app_db = "pgw_owndb"
    # a clean app database
    root = await asyncpg.connect(admin, timeout=10)
    try:
        await root.execute(f"DROP DATABASE IF EXISTS {app_db} WITH (FORCE)")
        await root.execute("DROP DATABASE IF EXISTS pgw_owndb_state WITH (FORCE)")
        await root.execute(f"CREATE DATABASE {app_db}")
    finally:
        await root.close()

    app_admin_dsn = _with_db(admin, app_db)
    await _dba_migration(app_admin_dsn)

    # pgwarden's own commands, exactly as documented.
    state_dsn = _with_db(admin, "pgw_owndb_state", user="own_db_app", password=APP_PASSWORD)
    await db_init(app_admin_dsn, state_dsn)
    config = _config()
    await sync_roles(config, app_admin_dsn, ROLE_SECRET)
    await apply_masking(config, app_admin_dsn)

    report = await run_doctor(
        config,
        admin_dsn=app_admin_dsn,
        target_dsn=_with_db(admin, app_db),
        role_secret=ROLE_SECRET,
        extra_checks=(),
    )
    # the masking checks live in db.masking; run the core checks here
    assert report.ok, [(r.check, r.message) for r in report.results if r.status == "fail"]

    # the person queries as themselves: only their team's rows, PII masked.
    from urllib.parse import urlsplit

    target = _with_db(admin, app_db)
    parts = urlsplit(target)
    role_secret = ROLE_SECRET
    pm = PoolManager(target_dsn=target, role_secret=role_secret)
    try:
        password = derive_password(role_secret, "pw_u_rowan")
        conn = await asyncpg.connect(
            host=parts.hostname,
            port=parts.port or 5432,
            database=app_db,
            user="pw_u_rowan",
            password=password,
        )
        try:
            rows = await conn.fetch("SELECT team, owner_email FROM reports")
        finally:
            await conn.close()
        assert {r["team"] for r in rows} == {"eu"}  # RLS: only rowan's team
        assert all("***@" in r["owner_email"] for r in rows)  # masking applies
        # through the read path too
        result = await run_read_query(pm, "pw_u_rowan", "SELECT owner_email FROM reports", [])
        assert result.ok and all("***@" in row["owner_email"] for row in result.rows)
    finally:
        await pm.aclose()
