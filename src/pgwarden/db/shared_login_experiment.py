"""ADR-0002's experiment: does a shared login role let one person impersonate another?

pgwarden gives each person their own Postgres login role (``session_user``
cannot change from SQL) instead of one shared gateway login role that runs
``SET ROLE``/``SET SESSION AUTHORIZATION`` per request. This module builds
the *rejected* shared-login design in a scratch schema and roles, and
measures whether the escalation the spec predicts actually reproduces, so
ADR-0002 can quote an observed result instead of an assumption.

Design under test: one ``LOGIN`` role (``gw_login``, standing in for a
shared gateway credential) is granted membership in two otherwise-unrelated
roles (``u_a``, ``u_b``) ``WITH INHERIT FALSE, SET TRUE`` -- the shape a
shared-login gateway would need so ``SET ROLE`` can reach every person's
role from one connection. ``u_a`` and ``u_b`` each own a table only their
own role can read.

Result of :func:`run_experiment`, verified by experiment against Postgres 16
(see ``tests/integration/test_shared_login_experiment.py``) -- and more
precise than a first pass at this experiment suggested, worth stating
exactly: after ``SET ROLE u_a``, a single statement --
``select set_config('role','u_b',true), query_to_xml('select * from tb', ...)``
-- both changes role to ``u_b`` and reads ``tb`` (owned/granted to ``u_b``
only) within that one statement, because ``query_to_xml()`` parses and runs
its SQL-text argument as a fresh, dynamically-planned query *at call time*,
by which point ``set_config`` (evaluated first in the target list) has
already switched the effective role. This is exactly the spec's own
wording: "run dynamic SQL (for example ``query_to_xml(...)``) with the
other role's privileges." A plain *static* subquery in the same target list
-- ``select set_config('role','u_b',true), (select v from tb limit 1)`` --
was checked here too and does **not** leak: Postgres checks every range
table entry's permissions for the whole plan tree, including embedded
subqueries, once at executor startup, before any target-list expression
(including ``set_config``) runs -- so that check still sees the original
role. The danger is specifically dynamic SQL evaluated inside the same
statement as a role change, not every kind of subquery.

By contrast, with a dedicated per-person login role (no multi-membership,
nothing to ``SET ROLE`` to), plain ``SET SESSION AUTHORIZATION <other
role>`` is rejected outright with SQLSTATE 42501 even for a non-superuser
gateway login -- ``session_user`` genuinely cannot be changed from SQL in
that design, which is exactly the property RLS keyed on ``session_user``
(see ``demo/sql/03_rls.sql``) relies on.
"""

from __future__ import annotations

import dataclasses
import secrets

import asyncpg

_SCHEMA = "pw_shared_login_experiment"
_LOGIN_ROLE = "pw_experiment_gw_login"
_ROLE_A = "pw_experiment_u_a"
_ROLE_B = "pw_experiment_u_b"


@dataclasses.dataclass(frozen=True)
class ExperimentResult:
    dynamic_sql_escalation_reproduced: bool
    dynamic_sql_leaked_xml: str | None
    static_subquery_escalation_reproduced: bool
    static_subquery_leaked_value: str | None
    session_authorization_blocked: bool
    session_authorization_error: str | None

    @property
    def summary(self) -> str:
        """A one-paragraph result string, suitable for ADR-0002 to quote verbatim."""
        if self.dynamic_sql_escalation_reproduced:
            dynamic_part = (
                "Reproduced: with one shared login role granted SET-TRUE membership in two "
                "person roles, a single statement -- select set_config('role','u_b',true), "
                "query_to_xml('select * from tb', true, true, '') -- switches role and reads "
                "the other person's table within that one statement, because query_to_xml() "
                "plans and runs its SQL-text argument at call time, after set_config has "
                "already taken effect earlier in the same target list "
                f"(leaked: {self.dynamic_sql_leaked_xml!r})."
            )
        else:
            dynamic_part = (
                "Not reproduced on this Postgres version: query_to_xml() combined with "
                "set_config('role', ...) in one statement did not leak the other role's data."
            )
        if self.static_subquery_escalation_reproduced:
            static_part = (
                " A plain static subquery in the same target list was ALSO found to leak "
                "(unexpected; Postgres's usual upfront permission check for the whole plan "
                "tree did not hold here and needs review)."
            )
        else:
            static_part = (
                " A plain static subquery in the same target list -- select "
                "set_config('role','u_b',true), (select v from tb limit 1) -- does NOT leak: "
                "Postgres checks every relation's permissions for the whole plan, including "
                "embedded subqueries, once at executor startup before any target-list "
                "expression runs, so the danger is specifically dynamic SQL evaluated inside "
                "the same statement as a role change, not every kind of subquery."
            )
        if self.session_authorization_blocked:
            defense = (
                " With a dedicated per-person login role instead, SET SESSION AUTHORIZATION "
                f"to another role is rejected outright (SQLSTATE 42501: "
                f"{self.session_authorization_error}), so session_user -- and RLS keyed on it "
                "-- cannot be spoofed from SQL."
            )
        else:
            defense = (
                " SET SESSION AUTHORIZATION was unexpectedly NOT blocked for a per-person "
                "login role; this is a defense pgwarden's design relies on and needs review."
            )
        return dynamic_part + static_part + defense


async def _setup(admin: asyncpg.Connection) -> str:
    await _teardown(admin)
    await admin.execute(f"CREATE SCHEMA {_SCHEMA}")
    password = secrets.token_hex(16)
    await admin.execute(
        f"CREATE ROLE {_LOGIN_ROLE} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS"
    )
    await admin.execute(f"CREATE ROLE {_ROLE_A} NOLOGIN")
    await admin.execute(f"CREATE ROLE {_ROLE_B} NOLOGIN")
    await admin.execute(f"GRANT {_ROLE_A} TO {_LOGIN_ROLE} WITH INHERIT FALSE, SET TRUE")
    await admin.execute(f"GRANT {_ROLE_B} TO {_LOGIN_ROLE} WITH INHERIT FALSE, SET TRUE")
    await admin.execute(f"GRANT USAGE ON SCHEMA {_SCHEMA} TO {_LOGIN_ROLE}, {_ROLE_A}, {_ROLE_B}")

    await admin.execute(f"CREATE TABLE {_SCHEMA}.ta (v text)")
    await admin.execute(f"INSERT INTO {_SCHEMA}.ta VALUES ('secret_a')")
    await admin.execute(f"REVOKE ALL ON {_SCHEMA}.ta FROM PUBLIC")
    await admin.execute(f"GRANT SELECT ON {_SCHEMA}.ta TO {_ROLE_A}")

    await admin.execute(f"CREATE TABLE {_SCHEMA}.tb (v text)")
    await admin.execute(f"INSERT INTO {_SCHEMA}.tb VALUES ('secret_b')")
    await admin.execute(f"REVOKE ALL ON {_SCHEMA}.tb FROM PUBLIC")
    await admin.execute(f"GRANT SELECT ON {_SCHEMA}.tb TO {_ROLE_B}")

    return password


async def _teardown(admin: asyncpg.Connection) -> None:
    await admin.execute(f"DROP SCHEMA IF EXISTS {_SCHEMA} CASCADE")
    for role in (_LOGIN_ROLE, _ROLE_A, _ROLE_B):
        await admin.execute(f"DROP ROLE IF EXISTS {role}")


def _login_dsn(admin_dsn: str, password: str) -> str:
    from urllib.parse import quote, urlsplit, urlunsplit

    parts = urlsplit(admin_dsn)
    user = quote(_LOGIN_ROLE, safe="")
    pw = quote(password, safe="")
    netloc = f"{user}:{pw}@{parts.hostname}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


async def run_experiment(admin_dsn: str) -> ExperimentResult:
    """Build the shared-login design in a scratch schema/roles and measure the escalation.

    ``admin_dsn`` needs ``CREATEROLE`` and enough privilege to create a
    schema in its target database (an ordinary test/admin DSN is enough).
    Scratch objects are dropped both before and after, so this is safe to
    call repeatedly against the same database.
    """
    admin = await asyncpg.connect(admin_dsn, timeout=10)
    try:
        password = await _setup(admin)
    finally:
        await admin.close()

    login_dsn = _login_dsn(admin_dsn, password)
    conn = await asyncpg.connect(login_dsn, timeout=10, statement_cache_size=0)
    try:
        await conn.execute(f"SET ROLE {_ROLE_A}")
        try:
            xml_row = await conn.fetchrow(
                f"select set_config('role','{_ROLE_B}',true) as sc, "
                f"query_to_xml('select * from {_SCHEMA}.tb', true, true, '') as leaked_xml"
            )
            leaked_xml = str(xml_row["leaked_xml"]) if xml_row is not None else None
            dynamic_reproduced = bool(leaked_xml) and "secret_b" in (leaked_xml or "")
        except asyncpg.InsufficientPrivilegeError:
            leaked_xml = None
            dynamic_reproduced = False
        await conn.execute("RESET ROLE")

        await conn.execute(f"SET ROLE {_ROLE_A}")
        try:
            static_row = await conn.fetchrow(
                f"select set_config('role','{_ROLE_B}',true) as sc, "
                f"(select v from {_SCHEMA}.tb limit 1) as leaked"
            )
            static_leaked = static_row["leaked"] if static_row is not None else None
            static_reproduced = static_leaked is not None
        except asyncpg.InsufficientPrivilegeError:
            static_leaked = None
            static_reproduced = False
        await conn.execute("RESET ROLE")

        session_auth_blocked = False
        session_auth_error: str | None = None
        try:
            await conn.execute(f"SET SESSION AUTHORIZATION {_ROLE_A}")
        except asyncpg.InsufficientPrivilegeError as exc:
            session_auth_blocked = exc.sqlstate == "42501"
            session_auth_error = str(exc)
        else:
            await conn.execute("RESET SESSION AUTHORIZATION")
    finally:
        await conn.close()
        admin2 = await asyncpg.connect(admin_dsn, timeout=10)
        try:
            await _teardown(admin2)
        finally:
            await admin2.close()

    return ExperimentResult(
        dynamic_sql_escalation_reproduced=dynamic_reproduced,
        dynamic_sql_leaked_xml=leaked_xml,
        static_subquery_escalation_reproduced=static_reproduced,
        static_subquery_leaked_value=static_leaked,
        session_authorization_blocked=session_auth_blocked,
        session_authorization_error=session_auth_error,
    )


__all__ = ["ExperimentResult", "run_experiment"]
