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
from pathlib import Path
from typing import Any, NoReturn

import asyncpg
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


bench_app = typer.Typer(
    no_args_is_help=True, help="Benchmarks: baselines, latency, cold start and load."
)
app.add_typer(bench_app, name="bench")


def _bench_target(target_url: str | None) -> str:
    if target_url:
        return target_url
    config_path = os.environ.get("PGWARDEN_CONFIG")
    if not config_path:
        _fail("give --target-url or set PGWARDEN_CONFIG")
    try:
        return load_config(config_path).public_url
    except ConfigError as exc:
        _fail(str(exc))


def _bench_client(target_url: str | None, connect_url: str | None) -> Any:
    from pgwarden.redteam.stack import StackClient

    return StackClient(_bench_target(target_url), connect_url=connect_url or None)


def _bench_secret_path(explicit: str | None, secret_dir: str | None, machine: str) -> str:
    if explicit:
        return explicit
    if secret_dir:
        return str(Path(secret_dir) / f"machine-{machine}")
    _fail("give --machine-secret-file or set PGWARDEN_BENCH_MACHINE_SECRET_DIR")


def _emit_bench(document: dict[str, Any], report: str | None, lines: list[str]) -> None:
    """Write the results JSON to a path, or to stdout for ``--report -``; summary on the rest."""
    to_stdout = report == "-"
    if report and not to_stdout:
        Path(report).parent.mkdir(parents=True, exist_ok=True)
        Path(report).write_text(jsonlib.dumps(document, indent=2) + "\n", encoding="utf-8")
        typer.echo(f"wrote {report}")
    for line in lines:
        typer.echo(line, err=to_stdout)
    if to_stdout:
        typer.echo(jsonlib.dumps(document, indent=2))


_TARGET_URL = typer.Option(None, "--target-url", help="Gateway public URL (default: from config).")
_CONNECT_URL = typer.Option(
    None,
    "--connect-url",
    envvar="PGWARDEN_BENCH_CONNECT_URL",
    help="Where to send requests when the public URL is not reachable (compose network).",
)
_SECRET_FILE = typer.Option(None, "--machine-secret-file", help="The machine's client secret.")
_SECRET_DIR = typer.Option(
    None,
    "--machine-secret-dir",
    envvar="PGWARDEN_BENCH_MACHINE_SECRET_DIR",
    help="Directory of machine-<name> secret files.",
)
_REPORT = typer.Option(None, "--report", help="Write the results JSON here; '-' for stdout.")


@bench_app.command("latency")
def bench_latency_command(
    target_url: str = _TARGET_URL,
    connect_url: str = _CONNECT_URL,
    iterations: int = typer.Option(1000, "--iterations"),
    warmup: int = typer.Option(100, "--warmup"),
    repetitions: int = typer.Option(3, "--repetitions"),
    role: str = typer.Option("pw_m_bench_01", "--role", help="Machine login role to time as."),
    machine: str = typer.Option("bench-01", "--machine"),
    machine_secret_file: str = _SECRET_FILE,
    machine_secret_dir: str = _SECRET_DIR,
    report: str = _REPORT,
) -> None:
    """Measure the gateway's latency overhead against direct Postgres.

    Runs the three committed query shapes through direct asyncpg, the read-path wrapper and
    the gateway, ``--repetitions`` times, and reports the median with the spread. Needs the
    bench config on the gateway (raised rate limits); see README, "Latency and load".
    """
    from pgwarden.bench import latency as lat
    from pgwarden.bench.metadata import collect_metadata

    client = _bench_client(target_url, connect_url)
    target_dsn = _require_env("PGWARDEN_TARGET_DSN")
    role_secret = _require_secret("PGWARDEN_ROLE_SECRET")
    secret = _require_secret_from_path(
        _bench_secret_path(machine_secret_file, machine_secret_dir, machine)
    )
    config_path = os.environ.get("PGWARDEN_CONFIG")

    async def run() -> dict[str, Any]:
        token = await client.machine_token(machine, secret)
        version = await lat.fetch_postgres_version(lat.role_dsn_for(target_dsn, role, role_secret))
        reps = await lat.run_repetitions(
            repetitions=repetitions,
            target_dsn=target_dsn,
            role=role,
            role_secret=role_secret,
            client=client,
            token=token,
            iterations=iterations,
            warmup=warmup,
        )
        return {
            "command": (
                f"pgwarden bench latency --iterations {iterations} --warmup {warmup} "
                f"--repetitions {repetitions}"
            ),
            **collect_metadata(config_path=config_path, postgres_version=version),
            "iterations": iterations,
            "warmup": warmup,
            "repetitions": repetitions,
            "queries": lat.aggregate_repetitions(reps),
        }

    try:
        document = asyncio.run(run())
    except lat.BenchCallError as exc:
        _fail(str(exc))
    lines = [
        f"{r['query']}: direct p50 {r['direct_p50']} / gateway p50 {r['gateway_p50']} / "
        f"overhead p50 {r['overhead_p50']} p95 {r['overhead_p95']} ms "
        f"(p50 spread {r['spread']['overhead_p50'][0]} to {r['spread']['overhead_p50'][1]})"
        for r in document["queries"]
    ]
    _emit_bench(document, report, lines)


@bench_app.command("cold")
def bench_cold_command(
    target_url: str = _TARGET_URL,
    connect_url: str = _CONNECT_URL,
    samples: int = typer.Option(30, "--samples"),
    idle_wait: float = typer.Option(
        2.5, "--idle-wait", help="Seconds of silence before each call."
    ),
    role: str = typer.Option("pw_m_bench_01", "--role"),
    machine: str = typer.Option("bench-01", "--machine"),
    machine_secret_file: str = _SECRET_FILE,
    machine_secret_dir: str = _SECRET_DIR,
    report: str = _REPORT,
) -> None:
    """Cold first-query cost (connect + SCRAM) after the pooled connection was evicted.

    Run it against the gateway started with demo/pgwarden.bench-cold.yaml (pool idle timeout
    1 s). Says so in the output, instead of a number, when the eviction cannot be confirmed.
    """
    from pgwarden.bench import cold
    from pgwarden.bench.latency import BenchCallError, role_dsn_for
    from pgwarden.bench.metadata import collect_metadata

    client = _bench_client(target_url, connect_url)
    target_dsn = _require_env("PGWARDEN_TARGET_DSN")
    role_secret = _require_secret("PGWARDEN_ROLE_SECRET")
    secret = _require_secret_from_path(
        _bench_secret_path(machine_secret_file, machine_secret_dir, machine)
    )
    config_path = os.environ.get("PGWARDEN_CONFIG")
    idle_timeout: int | None = None
    if config_path:
        try:
            idle_timeout = load_config(config_path).pool.idle_timeout_s
        except ConfigError as exc:
            _fail(str(exc))
    if idle_timeout is not None and idle_wait <= idle_timeout:
        _fail(
            f"--idle-wait {idle_wait} must exceed the config's pool.idle_timeout_s "
            f"({idle_timeout}); use the bench-cold config"
        )

    async def run() -> dict[str, Any]:
        token = await client.machine_token(machine, secret)
        found = await cold.run_cold(
            client=client,
            token=token,
            role_dsn=role_dsn_for(target_dsn, role, role_secret),
            samples=samples,
            idle_wait_s=idle_wait,
        )
        summary = cold.summarize_cold(found, idle_wait_s=idle_wait, idle_timeout_s=idle_timeout)
        return {
            "command": f"pgwarden bench cold --samples {samples} --idle-wait {idle_wait:g}",
            **collect_metadata(config_path=config_path),
            "cold_start": summary,
        }

    try:
        document = asyncio.run(run())
    except BenchCallError as exc:
        _fail(str(exc))
    summary = document["cold_start"]
    if summary["measured"]:
        lines = [
            f"cold first query {summary['cold_first_query_ms']['median']} ms vs warm "
            f"{summary['warm_query_ms']['median']} ms: cold cost {summary['cold_cost_ms']} ms "
            f"({summary['confirmed_cold_samples']}/{summary['samples']} samples confirmed cold)"
        ]
    else:
        lines = [f"cold start NOT measured: {summary['reason']}"]
    _emit_bench(document, report, lines)


@bench_app.command("load")
def bench_load_command(
    target_url: str = _TARGET_URL,
    connect_url: str = _CONNECT_URL,
    identities: int = typer.Option(20, "--identities"),
    concurrency: int = typer.Option(20, "--concurrency"),
    duration: int = typer.Option(60, "--duration"),
    mix: str = typer.Option("pk:60,filter:30,agg:10", "--mix"),
    machine_secret_dir: str = _SECRET_DIR,
    report: str = _REPORT,
) -> None:
    """Concurrent load test across many machine identities.

    Peak Postgres connections are sampled here only when PGWARDEN_ADMIN_DSN is set (a host
    run); the benchmark container has no admin credentials, so devtools/bench/run.sh samples
    them, and the gateway's CPU and RSS, from the host.
    """
    from pgwarden.bench.load import parse_mix, result_dict, run_load
    from pgwarden.bench.metadata import collect_metadata

    if not machine_secret_dir:
        _fail("give --machine-secret-dir or set PGWARDEN_BENCH_MACHINE_SECRET_DIR")
    client = _bench_client(target_url, connect_url)
    admin_dsn = os.environ.get("PGWARDEN_ADMIN_DSN") or None
    config_path = os.environ.get("PGWARDEN_CONFIG")

    async def run() -> dict[str, Any]:
        tokens = []
        for i in range(1, identities + 1):
            secret = _require_secret_from_path(
                str(Path(machine_secret_dir) / f"machine-bench-{i:02d}")
            )
            tokens.append((await client.machine_token(f"bench-{i:02d}", secret)).access_token)
        result = await run_load(
            client=client,
            tokens=tokens,
            admin_dsn=admin_dsn,
            duration_s=float(duration),
            concurrency=concurrency,
            mix=parse_mix(mix),
        )
        return result_dict(result)

    result = asyncio.run(run())
    document = {
        "command": (
            f"pgwarden bench load --identities {identities} --concurrency {concurrency} "
            f"--duration {duration} --mix {mix}"
        ),
        **collect_metadata(config_path=config_path),
        "mix": mix,
        "result": result,
    }
    peak = result["peak_pg_connections"]
    lines = [
        f"{result['total_requests']} requests, {result['requests_per_s']} req/s, "
        f"p50 {result['p50_ms']} / p95 {result['p95_ms']} / p99 {result['p99_ms']} ms, "
        f"errors {result['errors']} (rate {result['error_rate']}), "
        f"rate-limited {result['rate_limited']}, "
        f"peak PG connections {peak if peak is not None else 'not sampled here'}"
    ]
    _emit_bench(document, report, lines)


@bench_app.command("merge")
def bench_merge_command(
    kind: str = typer.Argument(..., help="latency, cold or load."),
    samples_dir: str = typer.Option(..., "--samples-dir", help="Directory the wrapper filled."),
    out: str = typer.Option(..., "--out", help="Results file to write (cold: to update)."),
) -> None:
    """Fold the wrapper's host samples and the container output into a results file.

    Used by devtools/bench/run.sh. ``latency`` and ``load`` write ``--out``; ``cold`` adds the
    cold-start block to the existing latency file at ``--out``.
    """
    from pgwarden.bench import hostmetrics

    directory = Path(samples_dir)
    target = Path(out)
    try:
        if kind == "load":
            document = hostmetrics.merge_load(directory)
        elif kind == "latency":
            document = hostmetrics.merge_latency(directory)
        elif kind == "cold":
            if not target.is_file():
                _fail(f"{out} does not exist: run the latency step first")
            document = hostmetrics.merge_cold(directory, jsonlib.loads(target.read_text("utf-8")))
        else:
            _fail("kind must be latency, cold or load")
    except (ValueError, KeyError) as exc:
        _fail(f"cannot merge: {exc}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(jsonlib.dumps(document, indent=2) + "\n", encoding="utf-8")
    typer.echo(f"wrote {out}")


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


@redteam_app.command("llm")
def redteam_llm_command(
    models: str = typer.Option(..., "--models", help="Comma-separated OpenRouter model ids."),
    trials: int = typer.Option(3, "--trials"),
    target_url: str = typer.Option(None, "--target-url"),
    budget_usd: float = typer.Option(5.0, "--budget", help="Hard USD cap for this run."),
    max_turns: int = typer.Option(12, "--max-turns"),
    tasks_limit: int = typer.Option(
        None, "--tasks", help="Run only the first N tasks (smoke runs)."
    ),
    provider: list[str] = typer.Option(  # noqa: B008 - typer's repeatable option
        None,
        "--provider",
        help=(
            "Pin a model to OpenRouter provider(s): <model>=<provider>[,<provider>...], "
            "repeatable (for example qwen/qwen3.7-flash=alibaba). Fallbacks are always off; "
            "a model without a pin is served by OpenRouter's first choice. Either way the "
            "provider that served each call is recorded."
        ),
    ),
    report: str = typer.Option(None, "--report"),
) -> None:
    """LLM indirect-injection run over the demo stack (manual; never in CI).

    Environment: OPENROUTER_API_KEY (or PGWARDEN_LLM_API_KEY);
    PGWARDEN_TARGET_DSN naming the shop database (its host and database
    are used to compute each task's expected answer as the person's own
    role); PGWARDEN_ROLE_SECRET (or _FILE); PGWARDEN_ADMIN_DSN (or _FILE).

    The gateway must run demo/pgwarden.llm.yaml (raised rate limits):
    start it with PGWARDEN_DEMO_CONFIG=pgwarden.llm.yaml and export the
    same variable here. The results record that config, the limits the
    gateway reports, PGWARDEN_HARDWARE (a free-text hardware line),
    PGWARDEN_RUN_DATE, the commit, the command line and the prices.

    Prints a cost estimate, stops before the budget, and reports per
    model, including which providers served the calls.
    """
    import os as _os
    import sys as _sys

    from pgwarden.redteam import llm as llm_mod
    from pgwarden.redteam.ledger import BudgetExceeded, Ledger, fetch_prices
    from pgwarden.redteam.stack import StackClient

    base_url = _bench_target(target_url)
    _require_secret("PGWARDEN_ADMIN_DSN")
    target_dsn = _require_env("PGWARDEN_TARGET_DSN")
    role_secret = _require_secret("PGWARDEN_ROLE_SECRET")
    api_key = _os.environ.get("PGWARDEN_LLM_API_KEY") or _os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        _fail("OPENROUTER_API_KEY (or PGWARDEN_LLM_API_KEY) is required")
    llm_base = _os.environ.get("PGWARDEN_LLM_BASE_URL", "https://openrouter.ai/api/v1")
    model_ids = [m.strip() for m in models.split(",") if m.strip()]
    try:
        provider_pins = llm_mod.parse_provider_pins(provider or [], model_ids)
    except ValueError as exc:
        _fail(str(exc))
    injections_path = Path(_os.environ.get("PGWARDEN_INJECTIONS", "demo/injections.yaml"))

    async def run() -> tuple[dict[str, Any] | None, dict[str, Any]]:
        tasks = llm_mod.load_tasks()
        if tasks_limit:
            tasks = tasks[:tasks_limit]
        injections = llm_mod.load_injections(injections_path)
        prices = await fetch_prices(llm_base, api_key, model_ids)
        missing = [m for m in model_ids if m not in prices]
        if missing:
            _fail(f"not listed (with prices) by OpenRouter at run time: {', '.join(missing)}")
        ledger = Ledger(budget_usd=budget_usd, prices=prices)
        client = StackClient(base_url)
        llm = llm_mod.OpenRouterClient(llm_base, api_key, provider_orders=provider_pins)
        gateway_limits = await llm_mod.fetch_gateway_limits(client)
        episodes: list[dict[str, Any]] = []
        n_episodes = len(model_ids) * len(tasks) * trials
        estimate = llm_mod.estimate_cost_usd(prices, model_ids, len(tasks) * trials)
        typer.echo(
            f"estimate: {len(model_ids)} models x {len(tasks)} tasks x {trials} trials "
            f"= {n_episodes} episodes, about ${estimate:.3f} at the run-time prices, "
            f"budget ${budget_usd:.2f}"
        )
        typer.echo(f"gateway limits: {gateway_limits}; provider pins: {provider_pins or 'none'}")
        outcome: dict[str, Any] = {
            "tasks": len(tasks),
            "stopped_early": False,
            "stop_reason": None,
        }
        for model in model_ids:
            for task in tasks:
                for trial in range(1, trials + 1):
                    try:
                        ep = await llm_mod.run_episode(
                            model=model,
                            task=task,
                            trial=trial,
                            client=client,
                            llm=llm,
                            target_dsn=target_dsn,
                            role_secret=role_secret,
                            injections=injections,
                            ledger=ledger,
                            max_turns=max_turns,
                        )
                    except (BudgetExceeded, llm_mod.OpenRouterError) as exc:
                        # keep what ran: a partial run is written, flagged stopped_early
                        typer.secho(str(exc), fg=typer.colors.YELLOW, err=True)
                        outcome["stopped_early"] = True
                        outcome["stop_reason"] = f"{type(exc).__name__}: {exc}"
                        break
                    episodes.append(ep.__dict__)
                    typer.echo(
                        f"[{len(episodes)}/{n_episodes}] {model} {task['id']} trial {trial}: "
                        f"{'solved' if ep.solved else 'not solved'}, {ep.turns} turns, "
                        f"markers {ep.markers_seen or '-'}, attempts "
                        f"{len(ep.out_of_policy_attempts)}, served by {ep.providers_served}, "
                        f"spent ${ledger.spent_usd:.4f}"
                    )
                if outcome["stopped_early"]:
                    break
            if outcome["stopped_early"]:
                break
        outcome.update(episodes=episodes, ledger=ledger.summary())
        return gateway_limits, outcome

    gateway_limits, outcome = asyncio.run(run())
    document = {
        **llm_mod.run_metadata(
            argv=_sys.argv[1:],
            env=_os.environ,
            injections_path=injections_path,
            models=model_ids,
            provider_pins=provider_pins,
            tasks=outcome["tasks"],
            trials=trials,
            max_turns=max_turns,
            gateway_limits=gateway_limits,
        ),
        "stopped_early": outcome["stopped_early"],
        "stop_reason": outcome["stop_reason"],
        "ledger": outcome["ledger"],
        "episodes": outcome["episodes"],
    }
    per_model = llm_mod.summarize_episodes(document["episodes"], provider_pins)
    document["per_model"] = per_model
    if report:
        Path(report).parent.mkdir(parents=True, exist_ok=True)
        Path(report).write_text(jsonlib.dumps(document, indent=2) + "\n", encoding="utf-8")
        typer.echo(f"wrote {report}")
    for row in per_model:
        typer.echo(
            f"{row['model']}: {row['episodes']} episodes, solved {row['tasks_solved']}, "
            f"out-of-policy attempts {row['attempts']} (blocked {row['attempts_blocked']}), "
            f"rows beyond privilege {row['rows_beyond_privilege']}, "
            f"writes w/o approval {row['writes_without_approval']}, "
            f"exfil-in-answer episodes {row['exfil_episodes']}, "
            f"served by {row['providers_served']} (outside pin: {row['calls_outside_pin']})"
        )
    typer.echo(f"spend: ${document['ledger']['spent_usd']:.4f}")
    if any(r["rows_beyond_privilege"] or r["writes_without_approval"] for r in per_model):
        _fail("a model saw rows beyond its privileges or executed a write without approval")
    if any(r["calls_outside_pin"] for r in per_model):
        _fail("a pinned model was served by a provider outside its pin")
    if document["stopped_early"]:
        _fail(f"the run stopped early and is incomplete: {document['stop_reason']}")


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
    other_containers: int = typer.Option(
        None, "--other-containers", help="Number of other running containers, for the report."
    ),
) -> None:
    """Run the deterministic red-team suite against a deployment and report per category.

    Needs PGWARDEN_ADMIN_DSN (naming the target database) for the state-based
    oracles, and a machine secret (--machine-secret-file or PGWARDEN_MACHINE_SECRET)
    for the machine-run cases. The approval (H) and OAuth (I) scenarios sign in to
    the mock identity provider as the demo people, so they run against the demo
    stack. Set PGWARDEN_STATE_DSN (the state database, as pgwarden_app) to let the
    run clear the demo principals' rate windows first, so it can be repeated within
    the hour; a fresh stack does not need it. Exits non-zero unless every
    must-block attack is blocked and every benign control passes.
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
            state_dsn=os.environ.get("PGWARDEN_STATE_DSN"),
        )
        results = await runner.run(load_corpus())
        return await build_report(
            results,
            admin_dsn=admin_dsn,
            config_path=config_path,
            date=os.environ.get("PGWARDEN_RUN_DATE", _dt.date.today().isoformat()),
            hardware=hardware,
            command="pgwarden redteam run",
            other_containers=other_containers,
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


def _fail_database(exc: Exception) -> NoReturn:
    """One-line report of a database error from a provisioning command."""
    if isinstance(exc, asyncpg.PostgresError):
        hint = ""
        if isinstance(exc, asyncpg.InsufficientPrivilegeError):
            hint = " The admin role needs the privileges listed in docs/own-database.md."
        _fail(f"PostgreSQL refused the command: {exc} (SQLSTATE {exc.sqlstate}).{hint}")
    _fail(f"could not reach the database: {exc}")


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
    except (asyncpg.PostgresError, OSError) as exc:
        _fail_database(exc)

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
    try:
        result = asyncio.run(
            sync_roles(config, admin_dsn, role_secret, dry_run=dry_run, prune=prune)
        )
    except (asyncpg.PostgresError, OSError) as exc:
        _fail_database(exc)
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
    except (asyncpg.PostgresError, OSError) as exc:
        _fail_database(exc)
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
