"""``pgwarden db init``: create the state role and database, apply migrations,
and grant ``pgwarden_app`` what it needs.

Runs with ``PGWARDEN_ADMIN_DSN`` -- credentials and a host, whose own
database part is ignored -- and reads the target role name, password and
database name straight out of ``PGWARDEN_STATE_DSN``. The state database is
created, when missing, through the cluster's ``postgres`` maintenance
database, so the same admin DSN works whether or not the state database
already exists. Idempotent: a second run creates nothing new, probes the
existing role's password instead of blindly resetting it (same technique as
``pgwarden roles sync``; see :mod:`pgwarden.db.login_probe`), and applies
zero migrations.
"""

from __future__ import annotations

import dataclasses
from urllib.parse import urlsplit

import asyncpg

from pgwarden.db.dsn import with_dbname
from pgwarden.db.identifiers import quote_ident, quote_literal
from pgwarden.db.login_probe import password_is_current
from pgwarden.db.scram import verifier_for_password
from pgwarden.state.migrate import migrate

STATE_SCHEMA = "pgwarden"
MAINTENANCE_DB = "postgres"


@dataclasses.dataclass(frozen=True)
class StateTarget:
    user: str
    password: str
    host: str
    port: int
    dbname: str


class BootstrapError(RuntimeError):
    """Raised for an unusable ``PGWARDEN_STATE_DSN``."""


def parse_state_dsn(state_dsn: str) -> StateTarget:
    """Extract the role, password and database name ``db init`` provisions."""
    parts = urlsplit(state_dsn)
    if not parts.username or parts.password is None:
        raise BootstrapError("PGWARDEN_STATE_DSN must include a user and a password")
    dbname = parts.path.lstrip("/")
    if not dbname:
        raise BootstrapError("PGWARDEN_STATE_DSN must name a database")
    return StateTarget(
        user=parts.username,
        password=parts.password,
        host=parts.hostname or "localhost",
        port=parts.port or 5432,
        dbname=dbname,
    )


@dataclasses.dataclass
class InitResult:
    role_created: bool = False
    role_password_changed: bool = False
    database_created: bool = False
    schema_created: bool = False
    migrations_applied: list[str] = dataclasses.field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.role_created
            or self.role_password_changed
            or self.database_created
            or self.schema_created
            or self.migrations_applied
        )


async def db_init(admin_dsn: str, state_dsn: str) -> InitResult:
    """Create/reconcile the state role, database, schema and grants, then migrate.

    ``admin_dsn``'s own database part is ignored: the role and (if missing)
    the database are created via the ``postgres`` maintenance database, and
    schema/grants/migrations then run against the state database itself.
    """
    target = parse_state_dsn(state_dsn)
    result = InitResult()
    role_ident = quote_ident(target.user)

    maintenance_dsn = with_dbname(admin_dsn, MAINTENANCE_DB)
    admin = await asyncpg.connect(maintenance_dsn, timeout=10)
    try:
        role_exists = await admin.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", target.user)
        if not role_exists:
            verifier = verifier_for_password(target.password)
            await admin.execute(
                f"CREATE ROLE {role_ident} LOGIN PASSWORD {quote_literal(verifier)} "
                f"NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
            )
            result.role_created = True
        else:
            if not await password_is_current(maintenance_dsn, target.user, target.password):
                verifier = verifier_for_password(target.password)
                await admin.execute(
                    f"ALTER ROLE {role_ident} LOGIN PASSWORD {quote_literal(verifier)}"
                )
                result.role_password_changed = True

        db_exists = await admin.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", target.dbname
        )
        if not db_exists:
            await admin.execute(f"CREATE DATABASE {quote_ident(target.dbname)}")
            result.database_created = True
    finally:
        await admin.close()

    state_admin_dsn = with_dbname(admin_dsn, target.dbname)
    conn = await asyncpg.connect(state_admin_dsn, timeout=10)
    try:
        schema_exists = await conn.fetchval(
            "SELECT 1 FROM pg_namespace WHERE nspname = $1", STATE_SCHEMA
        )
        if not schema_exists:
            await conn.execute(f"CREATE SCHEMA {quote_ident(STATE_SCHEMA)}")
            result.schema_created = True

        result.migrations_applied = await migrate(conn)

        schema_ident = quote_ident(STATE_SCHEMA)
        await conn.execute(f"GRANT USAGE ON SCHEMA {schema_ident} TO {role_ident}")
        await conn.execute(
            f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA {schema_ident} TO {role_ident}"
        )
        # schema_migrations is the migration runner's own bookkeeping table;
        # pgwarden_app only ever needs to read it.
        await conn.execute(
            f"REVOKE INSERT, UPDATE ON {schema_ident}.schema_migrations FROM {role_ident}"
        )
        # The audit log is append-only for pgwarden_app: INSERT and SELECT only.
        # The blanket UPDATE grant above is revoked here (a BEFORE UPDATE/DELETE
        # trigger and the missing TRUNCATE grant enforce it too, defense in depth).
        audit_exists = await conn.fetchval(
            f"SELECT to_regclass('{STATE_SCHEMA}.audit_log') IS NOT NULL"
        )
        if audit_exists:
            await conn.execute(f"REVOKE UPDATE ON {schema_ident}.audit_log FROM {role_ident}")
        # rate_windows holds transient counters the gateway may prune itself.
        rate_exists = await conn.fetchval(
            f"SELECT to_regclass('{STATE_SCHEMA}.rate_windows') IS NOT NULL"
        )
        if rate_exists:
            await conn.execute(f"GRANT DELETE ON {schema_ident}.rate_windows TO {role_ident}")
        await conn.execute(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema_ident} "
            f"GRANT SELECT, INSERT, UPDATE ON TABLES TO {role_ident}"
        )
    finally:
        await conn.close()

    return result


__all__ = ["BootstrapError", "InitResult", "StateTarget", "db_init", "parse_state_dsn"]
