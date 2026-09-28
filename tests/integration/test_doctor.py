"""Integration tests for `pgwarden doctor` (pgwarden.db.doctor): every check,
each with a fixture that makes it fail, against the demo database and roles.
"""

from __future__ import annotations

import socket

import asyncpg
import pytest

from pgwarden.config import Config, IdentityRef, PersonConfig, UpstreamConfig
from pgwarden.db.doctor import (
    CheckResult,
    DoctorContext,
    check_dblink_fdw,
    check_not_behind_pooler,
    check_postgres_version,
    check_public_schema_create,
    check_rls_required,
    check_role_attributes,
    check_unencrypted_connection,
    run_doctor,
)

pytestmark = pytest.mark.pg

BOUNCER_HOST = "127.0.0.1"
BOUNCER_PORT = 55434


def _minimal_config(**overrides: object) -> Config:
    base: dict[str, object] = {
        "public_url": "http://localhost",
        "upstream": UpstreamConfig(name="test-idp", issuer="http://idp.test", client_id="x"),
        "people": [
            PersonConfig(identity=IdentityRef(email="alice@example.com"), role="alice", bundles=[])
        ],
    }
    base.update(overrides)
    return Config(**base)


def _bouncer_available() -> bool:
    try:
        with socket.create_connection((BOUNCER_HOST, BOUNCER_PORT), timeout=1):
            return True
    except OSError:
        return False


def _require_bouncer() -> None:
    import os

    if _bouncer_available():
        return
    if os.environ.get("PGWARDEN_REQUIRE_PG") == "1":
        pytest.fail("pgwarden-testbouncer is required when PGWARDEN_REQUIRE_PG=1")
    pytest.skip("pgwarden-testbouncer not reachable on 127.0.0.1:55434; run devtools/testpg.sh up")


def _target_dsn_for(shop_dsn: str, *, port: int | None = None) -> str:
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(shop_dsn)
    host = parts.hostname or "127.0.0.1"
    netloc = f"{host}:{port or parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


async def test_postgres_version_passes(pg_demo_roles: None, pg_shop_dsn: str) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_postgres_version(
            DoctorContext(
                admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
            )
        )
    finally:
        await admin.close()
    assert result.status == "pass"


async def test_pooler_check_passes_on_a_direct_connection(
    pg_demo_roles: None, pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_not_behind_pooler(
            DoctorContext(
                admin=admin,
                config=pg_demo_config,
                role_secret=pg_role_secret,
                target_dsn=_target_dsn_for(pg_shop_dsn),
            )
        )
    finally:
        await admin.close()
    assert result.status == "pass", result.message


async def test_pooler_check_fails_behind_a_real_transaction_mode_pgbouncer(
    pg_demo_roles: None, pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object
) -> None:
    _require_bouncer()
    assert isinstance(pg_demo_config, Config)
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_not_behind_pooler(
            DoctorContext(
                admin=admin,
                config=pg_demo_config,
                role_secret=pg_role_secret,
                target_dsn=_target_dsn_for(pg_shop_dsn, port=BOUNCER_PORT),
            )
        )
    finally:
        await admin.close()
    assert result.status == "fail"
    assert "0004" in result.message


async def test_role_attributes_passes_for_demo_roles(pg_demo_roles: None, pg_shop_dsn: str) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_role_attributes(
            DoctorContext(
                admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
            )
        )
    finally:
        await admin.close()
    assert result.status == "pass"


async def test_role_attributes_fails_when_a_role_has_superuser(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        await admin.execute("DROP ROLE IF EXISTS pw_u_doctortest")
        await admin.execute("CREATE ROLE pw_u_doctortest LOGIN SUPERUSER")
        try:
            result = await check_role_attributes(
                DoctorContext(
                    admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
                )
            )
            assert result.status == "fail"
            assert "pw_u_doctortest" in result.message
        finally:
            await admin.execute("DROP ROLE IF EXISTS pw_u_doctortest")
    finally:
        await admin.close()


async def test_role_attributes_fails_for_forbidden_predefined_role_membership(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        await admin.execute("DROP ROLE IF EXISTS pw_u_doctortest2")
        await admin.execute("CREATE ROLE pw_u_doctortest2 LOGIN")
        await admin.execute("GRANT pg_signal_backend TO pw_u_doctortest2")
        try:
            result = await check_role_attributes(
                DoctorContext(
                    admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
                )
            )
            assert result.status == "fail"
            assert "pg_signal_backend" in result.message
        finally:
            await admin.execute("DROP ROLE IF EXISTS pw_u_doctortest2")
    finally:
        await admin.close()


async def test_public_schema_create_passes_by_default(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_public_schema_create(
            DoctorContext(
                admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
            )
        )
    finally:
        await admin.close()
    assert result.status == "pass"


async def test_public_schema_create_fails_when_granted_to_public(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        await admin.execute("GRANT CREATE ON SCHEMA public TO PUBLIC")
        try:
            result = await check_public_schema_create(
                DoctorContext(
                    admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
                )
            )
            assert result.status == "fail"
        finally:
            await admin.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    finally:
        await admin.close()


async def test_dblink_fdw_passes_when_not_installed(pg_demo_roles: None, pg_shop_dsn: str) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_dblink_fdw(
            DoctorContext(
                admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
            )
        )
    finally:
        await admin.close()
    assert result.status == "pass"


async def test_dblink_fdw_fails_when_installed_and_executable(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        await admin.execute("CREATE EXTENSION IF NOT EXISTS dblink")
        try:
            result = await check_dblink_fdw(
                DoctorContext(
                    admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
                )
            )
            assert result.status == "fail"
            assert "pw_u_" in result.message
        finally:
            await admin.execute("DROP EXTENSION IF EXISTS dblink")
    finally:
        await admin.close()


async def test_rls_required_passes_for_demo_tables(
    pg_demo_roles: None, pg_shop_dsn: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_rls_required(
            DoctorContext(
                admin=admin, config=pg_demo_config, role_secret="x", target_dsn=pg_shop_dsn
            )
        )
    finally:
        await admin.close()
    assert result.status == "pass"


async def test_rls_required_fails_for_a_table_without_rls(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_rls_required(
            DoctorContext(
                admin=admin,
                config=_minimal_config(rls_required=["public.regions"]),
                role_secret="x",
                target_dsn=pg_shop_dsn,
            )
        )
    finally:
        await admin.close()
    assert result.status == "fail"
    assert "public.regions" in result.message


async def test_unencrypted_connection_passes_on_loopback(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_unencrypted_connection(
            DoctorContext(
                admin=admin, config=_minimal_config(), role_secret="x", target_dsn=pg_shop_dsn
            )
        )
    finally:
        await admin.close()
    assert result.status == "pass"


async def test_unencrypted_connection_warns_for_a_non_local_host(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    # The admin connection is real (loopback); only the target_dsn's host,
    # which the check parses for its "is this local" decision, is faked --
    # pgwarden-testpg does not have TLS configured, so a non-loopback host
    # must warn.
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        result = await check_unencrypted_connection(
            DoctorContext(
                admin=admin,
                config=_minimal_config(),
                role_secret="x",
                target_dsn="postgresql://db.pgwarden.example.test:5432/pgw_shop",
            )
        )
    finally:
        await admin.close()
    assert result.status == "warn"


async def test_run_doctor_ok_end_to_end_on_a_compliant_setup(
    pg_demo_roles: None, pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    report = await run_doctor(
        pg_demo_config,
        admin_dsn=pg_shop_dsn,
        target_dsn=_target_dsn_for(pg_shop_dsn),
        role_secret=pg_role_secret,
    )
    failed = [r for r in report.results if r.status == "fail"]
    assert not failed, failed
    assert report.ok
    names = {r.check for r in report.results}
    assert {"postgres_version", "pooler_mode", "role_attributes", "rls_required"} <= names


async def test_run_doctor_extension_point_runs_extra_checks(
    pg_demo_roles: None, pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)

    async def custom_check(ctx: DoctorContext) -> CheckResult:
        return CheckResult("custom", "warn", "from an extra check")

    report = await run_doctor(
        pg_demo_config,
        admin_dsn=pg_shop_dsn,
        target_dsn=_target_dsn_for(pg_shop_dsn),
        role_secret=pg_role_secret,
        extra_checks=[custom_check],
    )
    by_name = {r.check: r for r in report.results}
    assert by_name["custom"].status == "warn"
    assert by_name["custom"].message == "from an extra check"
