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

from pgwarden.config import (
    Config,
    ConfigError,
    PersonConfig,
    load_config,
    machine_role_name,
    person_role_name,
)
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

people_app = typer.Typer(no_args_is_help=True, help="People: list, suspend and unsuspend.")
app.add_typer(people_app, name="people")


def _find_person(config: Config, identity: str) -> PersonConfig:
    wanted = identity.lower()
    for person in config.people:
        email = (person.identity.email or "").lower()
        if wanted in (person.role, person_role_name(person.role), email):
            return person
    _fail(f"no person matches {identity!r} (use the role suffix, pw_u_<role> or the email)")


def _set_suspended(identity: str, suspended: bool) -> None:
    import asyncpg

    from pgwarden.identity import person_subject
    from pgwarden.oauth import store

    config_path = _require_env("PGWARDEN_CONFIG")
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))
    person = _find_person(config, identity)
    role = person_role_name(person.role)
    state_dsn = _require_secret("PGWARDEN_STATE_DSN")

    async def run() -> int:
        now = _datetime.datetime.now(tz=_datetime.UTC)
        conn = await asyncpg.connect(state_dsn, timeout=10)
        try:
            await conn.execute(
                "INSERT INTO pgwarden.people_status (person_role, suspended, suspended_at, "
                "suspended_by, updated_at) VALUES ($1, $2, $3, 'cli', $3) "
                "ON CONFLICT (person_role) DO UPDATE SET suspended = EXCLUDED.suspended, "
                "suspended_at = EXCLUDED.suspended_at, suspended_by = EXCLUDED.suspended_by, "
                "updated_at = EXCLUDED.updated_at",
                role,
                suspended,
                now,
            )
            revoked = 0
            if suspended:
                revoked = await store.revoke_families_for_subject(
                    conn, person_subject(person.role), "suspended", now
                )
            return revoked
        finally:
            await conn.close()

    revoked = asyncio.run(run())
    if suspended:
        typer.echo(
            f"suspended {role}: access tokens are refused from now on, {revoked} refresh-token "
            "session(s) revoked; the gateway closes the pool on the next request it refuses"
        )
    else:
        typer.echo(f"unsuspended {role}")


@people_app.command("suspend")
def people_suspend_command(
    identity: str = typer.Argument(..., help="Role suffix or email."),
) -> None:
    """Suspend a person immediately (tokens refused, refresh sessions revoked)."""
    _set_suspended(identity, True)


@people_app.command("unsuspend")
def people_unsuspend_command(
    identity: str = typer.Argument(..., help="Role suffix or email."),
) -> None:
    """Lift a suspension. The person signs in again to get new tokens."""
    _set_suspended(identity, False)


@people_app.command("list")
def people_list_command() -> None:
    """List configured people and machines with their roles, bundles and status."""
    import asyncpg

    config_path = _require_env("PGWARDEN_CONFIG")
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))
    state_dsn = _require_secret("PGWARDEN_STATE_DSN")

    async def run() -> dict[str, bool]:
        conn = await asyncpg.connect(state_dsn, timeout=10)
        try:
            rows = await conn.fetch("SELECT person_role, suspended FROM pgwarden.people_status")
        finally:
            await conn.close()
        return {r["person_role"]: bool(r["suspended"]) for r in rows}

    status = asyncio.run(run())
    for person in config.people:
        role = person_role_name(person.role)
        who = person.identity.email or person.identity.subject or person.identity.oid or "?"
        state = "suspended" if status.get(role) else "active"
        writer = f" writer={person.writer}" if person.writer else ""
        typer.echo(f"person  {role:24} {who:28} bundles={','.join(person.bundles)}{writer} {state}")
    for machine in config.machines:
        typer.echo(
            f"machine {machine_role_name(machine.role):24} {machine.name:28} "
            f"bundles={','.join(machine.bundles)}"
        )


@app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (0.0.0.0 in a container)."),
    port: int = typer.Option(8080, "--port", help="Bind port."),
    proxy_headers: bool = typer.Option(
        False, "--proxy-headers", help="Trust X-Forwarded-* from the reverse proxy in front."
    ),
) -> None:
    """Run the gateway (MCP at /mcp, OAuth, consent and approval pages).

    Reads PGWARDEN_CONFIG, PGWARDEN_TARGET_DSN and the server's own secrets (see
    docs/configuration.md). Refuses to start if PGWARDEN_ADMIN_DSN is present.
    """
    import uvicorn

    from pgwarden.wiring import WiringError, build_app

    try:
        application = build_app()
    except (WiringError, ConfigError, SecretError, ValueError) as exc:
        _fail(str(exc))
    uvicorn.run(
        application,
        host=host,
        port=port,
        proxy_headers=proxy_headers,
        forwarded_allow_ips="*" if proxy_headers else None,
        log_level="info",
    )


machine_app = typer.Typer(no_args_is_help=True, help="Machine (client_credentials) identities.")
app.add_typer(machine_app, name="machine")


@machine_app.command("secret")
def machine_secret_command(
    name: str = typer.Argument(None, help="Machine name from pgwarden.yaml."),
    out_file: str = typer.Option(
        None, "--out-file", help="Write the secret to this file (mode 0600) instead of stdout."
    ),
    all_machines: bool = typer.Option(
        False, "--all", help="Issue a secret for every configured machine (needs --out-dir)."
    ),
    out_dir: str = typer.Option(
        None, "--out-dir", help="With --all: write machine-<name> files into this directory."
    ),
) -> None:
    """Issue or rotate a machine's client secret. It is shown once and stored hashed.

    Reads PGWARDEN_CONFIG and PGWARDEN_STATE_DSN (or PGWARDEN_STATE_DSN_FILE).
    """
    import secrets as _secrets
    from pathlib import Path

    import asyncpg

    from pgwarden.oauth import store

    config_path = _require_env("PGWARDEN_CONFIG")
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))
    if all_machines:
        if not out_dir:
            _fail("--all needs --out-dir")
        names = [m.name for m in config.machines]
    else:
        if not name:
            _fail("give a machine name, or --all --out-dir DIR")
        if not any(m.name == name for m in config.machines):
            _fail(f"no machine named {name!r} in {config_path}")
        names = [name]
    state_dsn = _require_secret("PGWARDEN_STATE_DSN")
    issued = {n: _secrets.token_urlsafe(32) for n in names}

    async def run() -> None:
        conn = await asyncpg.connect(state_dsn, timeout=10)
        try:
            now = _datetime.datetime.now(tz=_datetime.UTC)
            for machine, secret in issued.items():
                await store.set_machine_secret(conn, machine, secret, now)
        finally:
            await conn.close()

    asyncio.run(run())

    def write(path: str, secret: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(secret + "\n")

    if all_machines:
        assert out_dir is not None
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        for machine, secret in issued.items():
            write(str(Path(out_dir) / f"machine-{machine}"), secret)
        typer.echo(f"wrote {len(issued)} machine secret(s) to {out_dir}")
    elif out_file:
        write(out_file, issued[names[0]])
        typer.echo(f"wrote the new secret for {names[0]} to {out_file}")
    else:
        typer.echo(issued[names[0]])


bench_app = typer.Typer(no_args_is_help=True, help="Benchmarks: baselines, latency and load.")
app.add_typer(bench_app, name="bench")


@bench_app.command("baselines")
def bench_baselines_command(
    report: str = typer.Option(None, "--report", help="Write the results JSON to this path."),
) -> None:
    """Run the attack corpus through two statement filters (ADR-0001 evidence).

    A keyword/regex blocklist and a SELECT-only sqlglot allowlist, next to
    pgwarden's measured 0/0. These filters live only in bench/, never in the
    product. Needs the `bench` extra (sqlglot).
    """
    try:
        from pgwarden.bench.baselines import run as run_baselines
    except ModuleNotFoundError as exc:  # pragma: no cover - missing optional extra
        _fail(f"the bench extra is required (uv sync --extra bench): {exc}")
    result = run_baselines()
    if report:
        from pathlib import Path

        Path(report).parent.mkdir(parents=True, exist_ok=True)
        Path(report).write_text(jsonlib.dumps(result, indent=2) + "\n", encoding="utf-8")
        typer.echo(f"wrote {report}")
    typer.echo(
        f"SQL-bearing attacks: {result['sql_attacks_total']}, "
        f"benign controls: {result['benign_total']}"
    )
    for b in result["baselines"]:
        typer.echo(
            f"  {b['baseline']}: {b['attacks_let_through']} attacks let through, "
            f"{b['benign_wrongly_blocked']} benign wrongly blocked"
        )
    typer.echo("  pgwarden: 0 attacks let through, 0 benign wrongly blocked")


redteam_app = typer.Typer(no_args_is_help=True, help="Red-team the running gateway.")
app.add_typer(redteam_app, name="redteam")


@redteam_app.command("run")
def redteam_run_command(
    target_url: str = typer.Option(
        None, "--target-url", help="Gateway base URL. Defaults to PGWARDEN_CONFIG's public_url."
    ),
    report: str = typer.Option(None, "--report", help="Write the results JSON to this path."),
    allow_load: bool = typer.Option(
        False, "--allow-load", help="Also run the flood cases (they generate load)."
    ),
    machine: str = typer.Option(
        "nightly-report", "--machine", help="Machine identity used for machine-run categories."
    ),
    machine_secret_file: str = typer.Option(
        None, "--machine-secret-file", help="File holding the machine's client secret."
    ),
    hardware: str = typer.Option(
        "unspecified", "--hardware", help="Hardware string for the report."
    ),
) -> None:
    """Run the deterministic red-team suite against a deployment and report per category.

    Needs PGWARDEN_ADMIN_DSN (naming the target database) for the state-based
    oracles, and a machine secret (--machine-secret-file or PGWARDEN_MACHINE_SECRET)
    for the machine-run cases. Exits non-zero unless every must-block attack is
    blocked and every benign control passes.
    """
    import datetime as _dt

    from pgwarden.redteam.report import build_report
    from pgwarden.redteam.runner import Runner, load_corpus
    from pgwarden.redteam.stack import StackClient

    base_url = target_url
    config_path = os.environ.get("PGWARDEN_CONFIG")
    if base_url is None:
        if not config_path:
            _fail("give --target-url or set PGWARDEN_CONFIG")
        try:
            base_url = load_config(config_path).public_url
        except ConfigError as exc:
            _fail(str(exc))
    admin_dsn = _require_secret("PGWARDEN_ADMIN_DSN")
    secret = None
    if machine_secret_file:
        secret = _require_secret_from_path(machine_secret_file)
    elif os.environ.get("PGWARDEN_MACHINE_SECRET"):
        secret = os.environ["PGWARDEN_MACHINE_SECRET"]
    machine_secrets = {machine: secret} if secret else {}

    async def run() -> dict[str, object]:
        runner = Runner(
            StackClient(base_url),
            admin_dsn=admin_dsn,
            machine_secrets=machine_secrets,
            allow_load=allow_load,
        )
        results = await runner.run(load_corpus())
        return await build_report(
            results,
            admin_dsn=admin_dsn,
            config_path=config_path,
            date=os.environ.get("PGWARDEN_RUN_DATE", _dt.date.today().isoformat()),
            hardware=hardware,
            command="pgwarden redteam run",
        )

    document = asyncio.run(run())
    summary = document["summary"]
    assert isinstance(summary, dict)
    if report:
        from pathlib import Path

        Path(report).parent.mkdir(parents=True, exist_ok=True)
        Path(report).write_text(jsonlib.dumps(document, indent=2) + "\n", encoding="utf-8")
        typer.echo(f"wrote {report}")
    for cat, v in summary["by_category"].items():
        typer.echo(f"{cat}: {v['blocked']}/{v['attacks']} blocked  layers={','.join(v['layers'])}")
    typer.echo(
        f"must-block: {summary['must_block_blocked']}/{summary['must_block_total']}  "
        f"benign: {summary['benign_passed']}/{summary['benign_total']}  "
        f"residual risks: {len(summary['residual_risks'])}"
    )
    gate_ok = (
        summary["must_block_blocked"] == summary["must_block_total"]
        and summary["benign_passed"] == summary["benign_total"]
    )
    if not gate_ok:
        for f in summary["failures"]:
            typer.secho(f"FAIL {f['id']}: {f['detail']}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


keys_app = typer.Typer(no_args_is_help=True, help="Generate the gateway's secrets and signing key.")
app.add_typer(keys_app, name="keys")


@keys_app.command("generate")
def keys_generate_command(
    out: str = typer.Option(..., "--out", help="Directory to write the secret files into."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing files."),
) -> None:
    """Write PGWARDEN_SIGNING_KEY, PGWARDEN_ROLE_SECRET and PGWARDEN_SESSION_SECRET files.

    Values are written to <out>/{signing_key.pem, role_secret, session_secret}, mode
    0600. Point the matching *_FILE environment variables at them. Never prints the
    values themselves.
    """
    import os
    import secrets as _secrets
    from pathlib import Path

    from pgwarden.oauth.keys import generate_signing_key_pem

    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "signing_key.pem": generate_signing_key_pem(),
        "role_secret": _secrets.token_urlsafe(32) + "\n",
        "session_secret": _secrets.token_urlsafe(32) + "\n",
    }
    written = []
    for name, value in files.items():
        path = out_dir / name
        if path.exists() and not force:
            _fail(f"{path} already exists; pass --force to overwrite")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(value)
        written.append(str(path))
    for path_str in written:
        typer.echo(f"wrote {path_str}")


def _fail(message: str) -> NoReturn:
    typer.secho(message, fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        _fail(f"{name} is required")
    return value


def _require_secret_from_path(path: str) -> str:
    from pathlib import Path

    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        _fail(f"cannot read {path}: {exc}")
    if not value:
        _fail(f"{path} is empty")
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
    admin_dsn = _require_secret("PGWARDEN_ADMIN_DSN")
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
    admin_dsn = _require_secret("PGWARDEN_ADMIN_DSN")
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
    admin_dsn = _require_secret("PGWARDEN_ADMIN_DSN")
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
    record: bool = typer.Option(
        False,
        "--record",
        help="Also store the results in the state database (PGWARDEN_STATE_DSN) for the "
        "admin Health page.",
    ),
) -> None:
    """Environment and privilege checks; exits non-zero if any check fails.

    Reads PGWARDEN_CONFIG, PGWARDEN_ADMIN_DSN (credentials and a host; its
    own database part is ignored), PGWARDEN_TARGET_DSN (names the database
    every check but the pooler check connects to) and PGWARDEN_ROLE_SECRET
    (or PGWARDEN_ROLE_SECRET_FILE; used only to derive the pooler check's
    probe credential, never sent as the admin DSN).
    """
    config_path = _require_env("PGWARDEN_CONFIG")
    admin_dsn = _require_secret("PGWARDEN_ADMIN_DSN")
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

    payload = [{"check": r.check, "status": r.status, "message": r.message} for r in report.results]
    if record:
        import asyncpg

        state_dsn = _require_secret("PGWARDEN_STATE_DSN")

        async def store_run() -> None:
            conn = await asyncpg.connect(state_dsn, timeout=10)
            try:
                await conn.execute(
                    "INSERT INTO pgwarden.doctor_runs (ok, results) VALUES ($1, $2::jsonb)",
                    report.ok,
                    jsonlib.dumps(payload),
                )
            finally:
                await conn.close()

        asyncio.run(store_run())

    if json_output:
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


@app.command("report")
def report_command(
    results: str = typer.Option("docs/results", "--results", help="Directory of *.json results."),
    readme: str = typer.Option("README.md", "--readme", help="README to inject tables into."),
    config_doc: str = typer.Option(
        "docs/configuration.md", "--config-doc", help="Generated configuration reference."
    ),
    check: bool = typer.Option(
        False, "--check", help="Fail if the README or the config doc would change (for CI)."
    ),
) -> None:
    """Render the README results tables and the configuration reference from the models.

    Without --check it writes both; with --check it exits non-zero if either is out
    of date, printing nothing else.
    """
    from pathlib import Path

    from pgwarden.docsgen import generate_configuration_md, render_readme

    drift: list[str] = []
    config_path = Path(config_doc)
    wanted_config = generate_configuration_md()
    current_config = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""
    if wanted_config != current_config:
        drift.append(config_doc)
        if not check:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(wanted_config, encoding="utf-8")

    readme_path = Path(readme)
    if readme_path.is_file():
        current_readme = readme_path.read_text(encoding="utf-8")
        wanted_readme = render_readme(current_readme, Path(results))
        if wanted_readme != current_readme:
            drift.append(readme)
            if not check:
                readme_path.write_text(wanted_readme, encoding="utf-8")

    if check:
        if drift:
            _fail(f"out of date, regenerate with `pgwarden report`: {', '.join(drift)}")
        typer.echo("report: README and configuration doc are in sync")
    else:
        typer.echo(f"report: updated {', '.join(drift) if drift else 'nothing (already in sync)'}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
