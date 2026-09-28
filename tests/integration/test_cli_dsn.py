"""End-to-end coverage of item 0's fix: `PGWARDEN_ADMIN_DSN` carries only
credentials and a host, and `roles sync`/`doctor` swap in the right
database themselves, through the actual CLI (not just the dsn.py helper).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from pgwarden.cli import app

pytestmark = pytest.mark.pg

REPO_ROOT = Path(__file__).parent.parent.parent
DEMO_CONFIG = REPO_ROOT / "demo" / "pgwarden.yaml"

runner = CliRunner()


def _admin_dsn_with_bogus_database(pg_admin_dsn: str) -> str:
    """`pg_admin_dsn` with its path replaced by a database that does not exist.

    Proves the CLI never actually connects to whatever database happens to
    be in PGWARDEN_ADMIN_DSN's own path.
    """
    from pgwarden.db.dsn import with_dbname

    return with_dbname(pg_admin_dsn, "this_database_does_not_exist")


def test_roles_sync_dry_run_ignores_admin_dsns_own_database(
    pg_demo_roles: None, pg_admin_dsn: str, pg_shop_dsn: str, pg_role_secret: str, monkeypatch
) -> None:
    from urllib.parse import urlsplit

    target_dsn = (
        f"postgresql://{urlsplit(pg_shop_dsn).hostname}:{urlsplit(pg_shop_dsn).port}/pgw_shop"
    )

    monkeypatch.setenv("PGWARDEN_CONFIG", str(DEMO_CONFIG))
    monkeypatch.setenv("PGWARDEN_ADMIN_DSN", _admin_dsn_with_bogus_database(pg_admin_dsn))
    monkeypatch.setenv("PGWARDEN_TARGET_DSN", target_dsn)
    monkeypatch.setenv("PGWARDEN_ROLE_SECRET", pg_role_secret)

    result = runner.invoke(app, ["roles", "sync", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "no changes" in result.output


def test_doctor_ignores_admin_dsns_own_database(
    pg_demo_roles: None, pg_admin_dsn: str, pg_shop_dsn: str, pg_role_secret: str, monkeypatch
) -> None:
    from urllib.parse import urlsplit

    target_dsn = (
        f"postgresql://{urlsplit(pg_shop_dsn).hostname}:{urlsplit(pg_shop_dsn).port}"
        "/pgw_shop?sslmode=disable"
    )

    monkeypatch.setenv("PGWARDEN_CONFIG", str(DEMO_CONFIG))
    monkeypatch.setenv("PGWARDEN_ADMIN_DSN", _admin_dsn_with_bogus_database(pg_admin_dsn))
    monkeypatch.setenv("PGWARDEN_TARGET_DSN", target_dsn)
    monkeypatch.setenv("PGWARDEN_ROLE_SECRET", pg_role_secret)

    result = runner.invoke(app, ["doctor", "--json"])
    # Warnings (e.g. the connection-encryption check, on a loopback
    # sslmode=disable target it will actually pass) are fine; only a
    # connection failure to the bogus database would show up as an
    # unhandled exception rather than a clean --json report.
    assert result.exception is None, result.output
    assert '"check"' in result.output
