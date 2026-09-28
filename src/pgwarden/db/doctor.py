"""``pgwarden doctor``: environment and privilege checks, independent of masking.

Every check takes a shared :class:`DoctorContext` and returns one
:class:`CheckResult`; ``run_doctor`` runs the fixed set below plus whatever
``extra_checks`` the caller passes in. That ``extra_checks`` sequence is
this module's extension point for step 3's masking invariant, masked-view
grant and writer-subset checks (item 6 and item 7 of the spec) -- they plug
in without this module importing anything about masking.

``admin_dsn`` must already name the target database (see
:mod:`pgwarden.db.dsn`, used the same way by `roles sync`). The pooler check
is the one exception: it never uses ``admin_dsn`` at all, connecting instead
with a derived person or machine credential, per the spec.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Awaitable, Callable, Sequence
from typing import Literal
from urllib.parse import parse_qs, urlsplit

import asyncpg

from pgwarden.config import LOOPBACK_HOSTS, Config, machine_role_name, person_role_name
from pgwarden.db.scram import derive_password

Status = Literal["pass", "warn", "fail"]


@dataclasses.dataclass(frozen=True)
class CheckResult:
    check: str
    status: Status
    message: str


@dataclasses.dataclass(frozen=True)
class DoctorContext:
    admin: asyncpg.Connection
    config: Config
    role_secret: str
    target_dsn: str


CheckFn = Callable[[DoctorContext], Awaitable[CheckResult]]


@dataclasses.dataclass(frozen=True)
class DoctorReport:
    results: list[CheckResult]

    @property
    def ok(self) -> bool:
        """True unless any check failed (warnings do not fail the report)."""
        return all(r.status != "fail" for r in self.results)


def _parse_target_dsn(target_dsn: str) -> tuple[str, int, str, bool | None]:
    parts = urlsplit(target_dsn)
    host = parts.hostname or "localhost"
    port = parts.port or 5432
    dbname = parts.path.lstrip("/")
    if not dbname:
        raise ValueError("PGWARDEN_TARGET_DSN must name a database")
    sslmode = parse_qs(parts.query).get("sslmode", [None])[0]
    ssl: bool | None = None if sslmode is None else sslmode != "disable"
    return host, port, dbname, ssl


# -- checks --------------------------------------------------------------


async def check_postgres_version(ctx: DoctorContext) -> CheckResult:
    """Postgres major version is at least 16."""
    version_num = await ctx.admin.fetchval("SHOW server_version_num")
    major = int(version_num) // 10000
    if major >= 16:
        return CheckResult("postgres_version", "pass", f"Postgres major version {major} (>= 16)")
    return CheckResult(
        "postgres_version", "fail", f"Postgres major version {major} is below the required 16"
    )


def _pick_probe_role(config: Config) -> str | None:
    """A login role name to probe the pooler with -- any configured one will do."""
    if config.people:
        return person_role_name(config.people[0].role)
    if config.machines:
        return machine_role_name(config.machines[0].role)
    return None


async def check_not_behind_pooler(ctx: DoctorContext) -> CheckResult:
    """The gateway is not behind a transaction-mode pooler (see ADR-0004).

    Connects with a derived person or machine credential -- never the admin
    DSN -- opens two client connections at once and compares their
    ``pg_backend_pid()``, then compares the pid across two transactions on
    one of those connections. A direct connection or a session-mode pooler
    guarantees both checks pass; a transaction-mode pooler can share a
    backend between idle client connections and swap backends between
    transactions on the same client connection (verified by experiment
    against a real PgBouncer in transaction mode).
    """
    role = _pick_probe_role(ctx.config)
    if role is None:
        return CheckResult(
            "pooler_mode", "warn", "no person or machine is configured; cannot probe the pooler"
        )
    password = derive_password(ctx.role_secret, role)
    host, port, dbname, ssl = _parse_target_dsn(ctx.target_dsn)

    async def _connect() -> asyncpg.Connection:
        return await asyncpg.connect(
            host=host, port=port, database=dbname, user=role, password=password, ssl=ssl, timeout=10
        )

    try:
        conn_a = await _connect()
        conn_b = await _connect()
    except Exception as exc:
        return CheckResult(
            "pooler_mode", "fail", f"could not open probe connections as {role}: {exc}"
        )
    try:
        pid_a = await conn_a.fetchval("SELECT pg_backend_pid()")
        pid_b = await conn_b.fetchval("SELECT pg_backend_pid()")
        if pid_a == pid_b:
            return CheckResult(
                "pooler_mode",
                "fail",
                f"two concurrent connections share one backend (pid {pid_a}); this looks like a "
                "transaction-mode pooler, which pgwarden does not support -- see "
                "docs/adr/0004-pooler-mode.md",
            )

        tx1 = conn_a.transaction()
        await tx1.start()
        pid_c = await conn_a.fetchval("SELECT pg_backend_pid()")
        await tx1.commit()
        tx2 = conn_a.transaction()
        await tx2.start()
        pid_d = await conn_a.fetchval("SELECT pg_backend_pid()")
        await tx2.commit()
        if pid_c != pid_d:
            return CheckResult(
                "pooler_mode",
                "fail",
                f"one connection's backend pid changed between transactions ({pid_c} -> {pid_d}); "
                "this looks like a transaction-mode pooler, which pgwarden does not support -- see "
                "docs/adr/0004-pooler-mode.md",
            )
        return CheckResult(
            "pooler_mode",
            "pass",
            f"direct/session-mode connection confirmed (backend pids {pid_a}, {pid_b})",
        )
    finally:
        await conn_a.close()
        await conn_b.close()


_FORBIDDEN_ROLE_ATTRS = ("rolsuper", "rolbypassrls", "rolcreaterole", "rolcreatedb")
_FORBIDDEN_PREDEFINED_ROLES = (
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_execute_server_program",
    "pg_signal_backend",
)


async def check_role_attributes(ctx: DoctorContext) -> CheckResult:
    """Person/machine roles have none of the forbidden attributes or memberships."""
    rows = await ctx.admin.fetch(
        "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles "
        "WHERE rolname LIKE 'pw\\_u\\_%' OR rolname LIKE 'pw\\_m\\_%'"
    )
    if not rows:
        return CheckResult("role_attributes", "warn", "no pw_u_*/pw_m_* roles exist yet")

    problems: list[str] = []
    for row in rows:
        name = row["rolname"]
        for attr in _FORBIDDEN_ROLE_ATTRS:
            if row[attr]:
                problems.append(f"{name} has {attr}")
        for predefined in _FORBIDDEN_PREDEFINED_ROLES:
            # pg_has_role(..., 'member') follows indirect membership too,
            # regardless of INHERIT/SET -- exactly "is a member of", direct
            # or not.
            is_member = await ctx.admin.fetchval(
                "SELECT pg_has_role($1, $2, 'member')", name, predefined
            )
            if is_member:
                problems.append(f"{name} is a member of {predefined}")

    if problems:
        return CheckResult("role_attributes", "fail", "; ".join(problems))
    return CheckResult(
        "role_attributes",
        "pass",
        f"{len(rows)} role(s) checked: no forbidden attribute or membership",
    )


async def check_public_schema_create(ctx: DoctorContext) -> CheckResult:
    """``CREATE`` on schema ``public`` is not granted to ``PUBLIC``."""
    granted = await ctx.admin.fetchval(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace n, aclexplode(coalesce(n.nspacl, '{}')) a "
        "WHERE n.nspname = 'public' AND a.grantee = 0 AND a.privilege_type = 'CREATE')"
    )
    if granted:
        return CheckResult(
            "public_schema_create", "fail", "CREATE on schema public is granted to PUBLIC"
        )
    return CheckResult(
        "public_schema_create", "pass", "CREATE on schema public is not granted to PUBLIC"
    )


async def check_dblink_fdw(ctx: DoctorContext) -> CheckResult:
    """No ``dblink``/``postgres_fdw`` function is executable by a person/machine role."""
    functions = await ctx.admin.fetch(
        "SELECT p.oid::regprocedure::text AS signature "
        "FROM pg_proc p "
        "JOIN pg_depend d ON d.objid = p.oid AND d.deptype = 'e' "
        "JOIN pg_extension e ON e.oid = d.refobjid AND e.extname IN ('dblink', 'postgres_fdw')"
    )
    if not functions:
        return CheckResult("dblink_fdw", "pass", "dblink and postgres_fdw are not installed")

    roles = await ctx.admin.fetch(
        "SELECT rolname FROM pg_roles WHERE rolname LIKE 'pw\\_u\\_%' OR rolname LIKE 'pw\\_m\\_%'"
    )
    problems: list[str] = []
    for role_row in roles:
        for fn_row in functions:
            executable = await ctx.admin.fetchval(
                "SELECT has_function_privilege($1, $2, 'EXECUTE')",
                role_row["rolname"],
                fn_row["signature"],
            )
            if executable:
                problems.append(f"{role_row['rolname']} can execute {fn_row['signature']}")
    if problems:
        return CheckResult("dblink_fdw", "fail", "; ".join(problems))
    return CheckResult(
        "dblink_fdw",
        "pass",
        "no dblink/postgres_fdw function is executable by a person/machine role",
    )


async def check_rls_required(ctx: DoctorContext) -> CheckResult:
    """RLS is enabled on every table config lists under ``rls_required``."""
    if not ctx.config.rls_required:
        return CheckResult("rls_required", "warn", "rls_required is empty in config")

    problems: list[str] = []
    for qualified in ctx.config.rls_required:
        schema, _, table = qualified.partition(".")
        enabled = await ctx.admin.fetchval(
            "SELECT relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = $1 AND c.relname = $2",
            schema,
            table,
        )
        if enabled is None:
            problems.append(f"{qualified}: table not found")
        elif not enabled:
            problems.append(f"{qualified}: row level security is not enabled")

    if problems:
        return CheckResult("rls_required", "fail", "; ".join(problems))
    return CheckResult(
        "rls_required",
        "pass",
        f"row level security enabled on all {len(ctx.config.rls_required)} configured table(s)",
    )


async def check_unencrypted_connection(ctx: DoctorContext) -> CheckResult:
    """An unencrypted non-local connection is a warning, never a failure."""
    host = (urlsplit(ctx.target_dsn).hostname or "").lower()
    if host in LOOPBACK_HOSTS:
        return CheckResult(
            "connection_encryption", "pass", "target host is loopback; encryption not required"
        )
    ssl_in_use = await ctx.admin.fetchval(
        "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
    )
    if ssl_in_use:
        return CheckResult(
            "connection_encryption", "pass", "connection to a non-local host is encrypted"
        )
    return CheckResult(
        "connection_encryption", "warn", f"connection to non-local host {host!r} is not encrypted"
    )


DEFAULT_CHECKS: tuple[CheckFn, ...] = (
    check_postgres_version,
    check_not_behind_pooler,
    check_role_attributes,
    check_public_schema_create,
    check_dblink_fdw,
    check_rls_required,
    check_unencrypted_connection,
)


async def run_doctor(
    config: Config,
    *,
    admin_dsn: str,
    target_dsn: str,
    role_secret: str,
    extra_checks: Sequence[CheckFn] = (),
) -> DoctorReport:
    """Run every doctor check and return a report.

    ``admin_dsn`` must already name the target database. ``extra_checks``
    lets a later step (masking, item 6's invariant and item 7's
    writer-subset invariant) add its own checks without this module
    depending on masking at all.
    """
    admin = await asyncpg.connect(admin_dsn, timeout=10)
    try:
        ctx = DoctorContext(
            admin=admin, config=config, role_secret=role_secret, target_dsn=target_dsn
        )
        results = [await check(ctx) for check in (*DEFAULT_CHECKS, *extra_checks)]
        return DoctorReport(results=results)
    finally:
        await admin.close()


__all__ = [
    "CheckFn",
    "CheckResult",
    "DEFAULT_CHECKS",
    "DoctorContext",
    "DoctorReport",
    "run_doctor",
]
