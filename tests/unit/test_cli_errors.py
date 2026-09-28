"""Provisioning commands report a database refusal in one line, not a traceback."""

from __future__ import annotations

from typing import Any

import asyncpg
import pytest
from typer.testing import CliRunner

from pgwarden import cli

runner = CliRunner()


def test_db_init_reports_a_permission_error_in_one_line(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(*_args: Any) -> None:
        raise asyncpg.InsufficientPrivilegeError("permission denied to create role")

    monkeypatch.setenv("PGWARDEN_ADMIN_DSN", "postgresql://admin:pw@127.0.0.1:1/postgres")
    monkeypatch.setenv("PGWARDEN_STATE_DSN", "postgresql://pgwarden_app:pw@127.0.0.1:1/pgw_state")
    monkeypatch.setattr(cli, "_db_init", refuse)

    result = runner.invoke(cli.app, ["db", "init"])

    assert result.exit_code == 1
    assert "PostgreSQL refused the command: permission denied to create role" in result.output
    assert "docs/own-database.md" in result.output
    assert "Traceback" not in result.output


def test_db_init_reports_an_unreachable_database_in_one_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unreachable(*_args: Any) -> None:
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setenv("PGWARDEN_ADMIN_DSN", "postgresql://admin:pw@127.0.0.1:1/postgres")
    monkeypatch.setenv("PGWARDEN_STATE_DSN", "postgresql://pgwarden_app:pw@127.0.0.1:1/pgw_state")
    monkeypatch.setattr(cli, "_db_init", unreachable)

    result = runner.invoke(cli.app, ["db", "init"])

    assert result.exit_code == 1
    assert "could not reach the database" in result.output
    assert "Traceback" not in result.output
