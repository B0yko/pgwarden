"""pgwarden's command-line interface (Typer).

Only implemented command groups are registered here; groups from later build
steps (``serve``, ``people``, ``machine``, ``keys``, ``redteam``, ``bench``,
``report``) are added when they exist.
"""

from __future__ import annotations

import asyncio
import datetime as _datetime
import json as jsonlib
import os
from typing import NoReturn

import typer

from pgwarden.config import ConfigError, load_config
from pgwarden.db.doctor import run_doctor
from pgwarden.db.dsn import dbname_from_dsn, with_dbname
from pgwarden.db.masking import MaskingError, apply_masking, masking_checks
from pgwarden.db.provisioning import sync_roles
from pgwarden.secrets import SecretError, read_secret
from pgwarden.state.bootstrap import BootstrapError
from pgwarden.state.bootstrap import db_init as _db_init

app = typer.Typer(
    no_args_is_help=True, add_completion=False, help="Governed Postgres access for AI assistants."
)

db_app = typer.Typer(no_args_is_help=True, help="State database provisioning.")
app.add_typer(db_app, name="db")

roles_app = typer.Typer(no_args_is_help=True, help="Target-database login role provisioning.")
app.add_typer(roles_app, name="roles")

masking_app = typer.Typer(
    no_args_is_help=True, help="Column masking: pw_fn functions and pw_masked views."
)
app.add_typer(masking_app, name="masking")

audit_app = typer.Typer(no_args_is_help=True, help="Audit log: verify the chain and export events.")
app.add_typer(audit_app, name="audit")


def _fail(message: str) -> NoReturn:
    typer.secho(message, fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        _fail(f"{name} is required")
    return value


def _require_secret(name: str) -> str:
    try:
        value = read_secret(name)
    except SecretError as exc:
        _fail(str(exc))
    if not value:
        _fail(f"{name} (or {name}_FILE) is required")
    return value


def _admin_dsn_for_target(admin_dsn: str, target_dsn: str) -> str:
    """``PGWARDEN_ADMIN_DSN`` with its database part swapped for the target's.

    ``PGWARDEN_ADMIN_DSN`` carries only credentials and a host; `roles sync`,
    `masking apply` and `doctor` always operate on the database named in
    ``PGWARDEN_TARGET_DSN``, never on whatever database happened to be in
    the admin DSN's own path. This is what lets one admin DSN work unchanged
    for the compose stack and for Cloud SQL.
    """
    try:
        dbname = dbname_from_dsn(target_dsn)
    except ValueError as exc:
        _fail(f"PGWARDEN_TARGET_DSN: {exc}")
    return with_dbname(admin_dsn, dbname)


@db_app.command("init")
def db_init_command() -> None:
    """Create pgwarden_app and the state database, apply migrations, grant access.

    Reads PGWARDEN_ADMIN_DSN (naming an existing maintenance database on the
    same cluster) and PGWARDEN_STATE_DSN (or PGWARDEN_STATE_DSN_FILE), which
    names the state database and the pgwarden_app credentials to provision.
    Idempotent: safe to run again.
    """
    admin_dsn = _require_env("PGWARDEN_ADMIN_DSN")
    state_dsn = _require_secret("PGWARDEN_STATE_DSN")

    try:
        result = asyncio.run(_db_init(admin_dsn, state_dsn))
    except BootstrapError as exc:
        _fail(str(exc))

    if result.role_created:
        typer.echo("created role pgwarden_app")
    if result.role_password_changed:
        typer.echo("updated the pgwarden_app password")
    if result.database_created:
        typer.echo("created the state database")
    if result.schema_created:
        typer.echo("created schema pgwarden")
    if result.migrations_applied:
        typer.echo("applied migrations: " + ", ".join(result.migrations_applied))
    if not result.changed:
        typer.echo("state database already up to date")


@roles_app.command("sync")
def roles_sync_command(
    dry_run: bool = typer.Option(False, "--dry-run", help="Print the SQL without executing it."),
    prune: bool = typer.Option(
        False, "--prune", help="Also NOLOGIN and revoke pw_u_*/pw_m_* roles no longer in config."
    ),
) -> None:
    """Reconcile pw_u_<role>/pw_m_<role> login roles with pgwarden.yaml.

    Reads PGWARDEN_CONFIG, PGWARDEN_ADMIN_DSN (credentials and a host; its
    own database part is ignored), PGWARDEN_TARGET_DSN (names the database
    this command connects to) and PGWARDEN_ROLE_SECRET (or
    PGWARDEN_ROLE_SECRET_FILE).
    """
    config_path = _require_env("PGWARDEN_CONFIG")
    admin_dsn = _require_env("PGWARDEN_ADMIN_DSN")
    target_dsn = _require_env("PGWARDEN_TARGET_DSN")
    role_secret = _require_secret("PGWARDEN_ROLE_SECRET")

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))

    admin_dsn = _admin_dsn_for_target(admin_dsn, target_dsn)
    result = asyncio.run(sync_roles(config, admin_dsn, role_secret, dry_run=dry_run, prune=prune))
    if not result.actions:
        typer.echo("no changes")
        return
    verb = "would run" if dry_run else "ran"
    for action in result.actions:
        typer.echo(f"{verb}: [{action.role}] {action.display_sql}")


@masking_app.command("apply")
def masking_apply_command(
    dry_run: bool = typer.Option(False, "--dry-run", help="Print the SQL without executing it."),
) -> None:
    """Reconcile pw_fn masking functions and pw_masked views/grants with pgwarden.yaml.

    Reads PGWARDEN_CONFIG, PGWARDEN_ADMIN_DSN (credentials and a host; its
    own database part is ignored) and PGWARDEN_TARGET_DSN (names the
    database this command connects to, same as `roles sync`/`doctor`).
    """
    config_path = _require_env("PGWARDEN_CONFIG")
    admin_dsn = _require_env("PGWARDEN_ADMIN_DSN")
    target_dsn = _require_env("PGWARDEN_TARGET_DSN")

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))

    admin_dsn = _admin_dsn_for_target(admin_dsn, target_dsn)
    try:
        result = asyncio.run(apply_masking(config, admin_dsn, dry_run=dry_run))
    except MaskingError as exc:
        _fail(str(exc))
    if not result.actions:
        typer.echo("no changes")
        return
    verb = "would run" if dry_run else "ran"
    for action in result.actions:
        typer.echo(f"{verb}: [{action.kind}] {action.display_sql}")


@app.command("doctor")
def doctor_command(
    json_output: bool = typer.Option(False, "--json", help="Print the report as JSON."),
) -> None:
    """Environment and privilege checks; exits non-zero if any check fails.

    Reads PGWARDEN_CONFIG, PGWARDEN_ADMIN_DSN (credentials and a host; its
    own database part is ignored), PGWARDEN_TARGET_DSN (names the database
    every check but the pooler check connects to) and PGWARDEN_ROLE_SECRET
    (or PGWARDEN_ROLE_SECRET_FILE; used only to derive the pooler check's
    probe credential, never sent as the admin DSN).
    """
    config_path = _require_env("PGWARDEN_CONFIG")
    admin_dsn = _require_env("PGWARDEN_ADMIN_DSN")
    target_dsn = _require_env("PGWARDEN_TARGET_DSN")
    role_secret = _require_secret("PGWARDEN_ROLE_SECRET")

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))

    admin_dsn = _admin_dsn_for_target(admin_dsn, target_dsn)
    report = asyncio.run(
        run_doctor(
            config,
            admin_dsn=admin_dsn,
            target_dsn=target_dsn,
            role_secret=role_secret,
            extra_checks=masking_checks(config),
        )
    )

    if json_output:
        payload = [
            {"check": r.check, "status": r.status, "message": r.message} for r in report.results
        ]
        typer.echo(jsonlib.dumps(payload, indent=2))
    else:
        colors = {
            "pass": typer.colors.GREEN,
            "warn": typer.colors.YELLOW,
            "fail": typer.colors.RED,
        }
        for r in report.results:
            typer.secho(f"[{r.status.upper():4}] {r.check}: {r.message}", fg=colors[r.status])

    if not report.ok:
        raise typer.Exit(code=1)


@audit_app.command("verify")
def audit_verify_command() -> None:
    """Walk the hash chain, report the first broken link, and print the head hash.

    Reads PGWARDEN_STATE_DSN (or PGWARDEN_STATE_DSN_FILE). Exits non-zero if the
    chain is broken. Recomputes every hash in Python, independently of the SQL.
    """
    import asyncpg

    from pgwarden.state.audit import verify_chain

    state_dsn = _require_secret("PGWARDEN_STATE_DSN")

    async def run() -> None:
        conn = await asyncpg.connect(state_dsn, timeout=10)
        try:
            result = await verify_chain(conn)
        finally:
            await conn.close()
        if result.ok:
            typer.secho(f"OK: {result.detail}", fg=typer.colors.GREEN)
            if result.head_hash is not None:
                typer.echo(f"head seq: {result.head_seq}")
                typer.echo(f"head hash: {result.head_hash}")
        else:
            typer.secho(
                f"BROKEN at seq {result.first_broken_seq}: {result.detail}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

    asyncio.run(run())


@audit_app.command("export")
def audit_export_command(
    since: str = typer.Option(None, "--since", help="ISO timestamp; only events at or after it."),
    fmt: str = typer.Option("jsonl", "--format", help="jsonl or csv."),
) -> None:
    """Export audit events as JSON Lines or CSV to stdout."""
    import asyncpg

    from pgwarden.state.audit import export_events

    if fmt not in ("jsonl", "csv"):
        _fail("--format must be jsonl or csv")
    since_dt = None
    if since is not None:
        try:
            since_dt = _datetime.datetime.fromisoformat(since)
        except ValueError:
            _fail(f"--since is not a valid ISO timestamp: {since!r}")
    state_dsn = _require_secret("PGWARDEN_STATE_DSN")

    async def run() -> None:
        conn = await asyncpg.connect(state_dsn, timeout=10)
        try:
            async for line in export_events(conn, since=since_dt, fmt=fmt):  # type: ignore[arg-type]
                typer.echo(line)
        finally:
            await conn.close()

    asyncio.run(run())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
