"""``pgwarden roles sync``: create and reconcile per-person and per-machine login roles.

Runs with an admin DSN that only needs ``CREATEROLE`` plus ``ADMIN OPTION``
on every bundle and writer role named in config; it never needs superuser
and never reads ``pg_authid`` (verified unreadable to such an admin by
experiment). Instead, password staleness is detected with a login probe
using the role's own derived password (see :mod:`pgwarden.db.scram`): if the
probe succeeds, the role's login state and password are already correct and
nothing is changed; if it fails with an authorization error (wrong password,
or the role is currently ``NOLOGIN``), the role is fixed in one statement.

Every other attribute (``CONNECTION LIMIT``, role defaults, memberships) is
diffed against ``pg_roles``/``pg_auth_members``, both readable to such an
admin (verified by experiment), so a second run performs zero changes.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Literal

import asyncpg

from pgwarden.config import Config, machine_role_name, person_role_name
from pgwarden.db.identifiers import quote_ident, quote_literal
from pgwarden.db.login_probe import password_is_current
from pgwarden.db.scram import role_verifier

logger = logging.getLogger(__name__)

REDACTED = "<verifier redacted>"

RoleKind = Literal["person", "machine"]


@dataclasses.dataclass(frozen=True)
class DesiredRole:
    name: str
    kind: RoleKind
    bundles: tuple[str, ...]
    writer: str | None
    connection_limit: int
    masked_search_path: bool


@dataclasses.dataclass(frozen=True)
class SyncAction:
    """One planned statement. ``sql`` is what runs; ``display_sql`` is what --dry-run prints."""

    role: str
    kind: str
    sql: str
    display_sql: str


@dataclasses.dataclass
class SyncResult:
    actions: list[SyncAction] = dataclasses.field(default_factory=list)
    dry_run: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.actions)


def _desired_roles(config: Config) -> list[DesiredRole]:
    connection_limit = config.pool.max_size * config.max_replicas + 1
    masking_configured = bool(config.masking.columns)
    raw_bundles = set(config.masking.raw_access_bundles)

    roles: list[DesiredRole] = []
    for person in config.people:
        has_raw = bool(raw_bundles & set(person.bundles))
        roles.append(
            DesiredRole(
                name=person_role_name(person.role),
                kind="person",
                bundles=tuple(person.bundles),
                writer=person.writer,
                connection_limit=connection_limit,
                masked_search_path=masking_configured and not has_raw,
            )
        )
    for machine in config.machines:
        has_raw = bool(raw_bundles & set(machine.bundles))
        roles.append(
            DesiredRole(
                name=machine_role_name(machine.role),
                kind="machine",
                bundles=tuple(machine.bundles),
                writer=None,
                connection_limit=connection_limit,
                masked_search_path=masking_configured and not has_raw,
            )
        )
    return roles


@dataclasses.dataclass
class ExistingRole:
    rolcanlogin: bool
    rolconnlimit: int
    config: dict[str, str]


async def _existing_roles(admin: asyncpg.Connection) -> dict[str, ExistingRole]:
    rows = await admin.fetch(
        "SELECT rolname, rolcanlogin, rolconnlimit, rolconfig FROM pg_roles "
        "WHERE rolname LIKE 'pw\\_u\\_%' OR rolname LIKE 'pw\\_m\\_%'"
    )
    result: dict[str, ExistingRole] = {}
    for row in rows:
        config_pairs: dict[str, str] = {}
        for entry in row["rolconfig"] or []:
            key, _, value = entry.partition("=")
            config_pairs[key] = value
        result[row["rolname"]] = ExistingRole(
            rolcanlogin=row["rolcanlogin"],
            rolconnlimit=row["rolconnlimit"],
            config=config_pairs,
        )
    return result


async def _existing_memberships(
    admin: asyncpg.Connection, role: str
) -> dict[str, tuple[bool, bool]]:
    rows = await admin.fetch(
        "SELECT roleid::regrole::text AS bundle, inherit_option, set_option "
        "FROM pg_auth_members WHERE member = $1::regrole",
        role,
    )
    return {row["bundle"]: (row["inherit_option"], row["set_option"]) for row in rows}


def _desired_memberships(desired: DesiredRole) -> dict[str, tuple[bool, bool]]:
    memberships: dict[str, tuple[bool, bool]] = dict.fromkeys(desired.bundles, (True, False))
    if desired.writer:
        memberships[desired.writer] = (False, True)
    return memberships


async def sync_roles(
    config: Config,
    admin_dsn: str,
    role_secret: str,
    *,
    dry_run: bool = False,
    prune: bool = False,
) -> SyncResult:
    """Reconcile login roles, passwords, attributes and bundle grants with ``config``.

    With ``dry_run=True``, nothing is executed; the returned actions show
    the SQL that would run, with every verifier redacted. With
    ``prune=True``, ``pw_u_*``/``pw_m_*`` roles that exist but are no longer
    named in ``config`` are revoked of all memberships and set ``NOLOGIN``
    (never dropped).
    """
    result = SyncResult(dry_run=dry_run)
    admin = await asyncpg.connect(admin_dsn, timeout=10)
    try:
        existing = await _existing_roles(admin)
        desired_roles = _desired_roles(config)
        desired_names = {r.name for r in desired_roles}

        for desired in desired_roles:
            await _sync_one_role(
                admin, admin_dsn, role_secret, desired, existing.get(desired.name), result
            )

        if prune:
            for name, current in existing.items():
                if name in desired_names:
                    continue
                await _prune_role(admin, name, current, result)

        return result
    finally:
        await admin.close()


async def _run(
    admin: asyncpg.Connection, dry_run: bool, action: SyncAction, result: SyncResult
) -> None:
    result.actions.append(action)
    if not dry_run:
        await admin.execute(action.sql)


async def _sync_one_role(
    admin: asyncpg.Connection,
    admin_dsn: str,
    role_secret: str,
    desired: DesiredRole,
    current: ExistingRole | None,
    result: SyncResult,
) -> None:
    name = desired.name
    ident = quote_ident(name)
    password, verifier = role_verifier(role_secret, name)
    verifier_literal = quote_literal(verifier)
    role_exists = current is not None

    if current is None:
        sql = (
            f"CREATE ROLE {ident} LOGIN PASSWORD {verifier_literal} "
            f"NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS "
            f"CONNECTION LIMIT {desired.connection_limit}"
        )
        display = sql.replace(verifier_literal, REDACTED)
        await _run(admin, result.dry_run, SyncAction(name, "create", sql, display), result)
        current = ExistingRole(rolcanlogin=True, rolconnlimit=desired.connection_limit, config={})
        role_exists = not result.dry_run
    else:
        # Password/login: a probe against the live cluster is the only way to know
        # whether the stored verifier is stale, since pg_authid is unreadable here.
        # In --dry-run mode there is nothing to compare against yet for a role that
        # this same run would have just created, so always probe for existing roles.
        current_password_ok = await password_is_current(admin_dsn, name, password)
        if not current_password_ok:
            sql = f"ALTER ROLE {ident} LOGIN PASSWORD {verifier_literal}"
            display = sql.replace(verifier_literal, REDACTED)
            await _run(admin, result.dry_run, SyncAction(name, "password", sql, display), result)

        if current.rolconnlimit != desired.connection_limit:
            sql = f"ALTER ROLE {ident} CONNECTION LIMIT {desired.connection_limit}"
            await _run(admin, result.dry_run, SyncAction(name, "connlimit", sql, sql), result)

    config_now = current.config
    desired_config = {"default_transaction_read_only": "on", "statement_timeout": "30s"}
    if desired.masked_search_path:
        desired_config["search_path"] = "pw_masked, public"

    for key, value in desired_config.items():
        if config_now.get(key) != value:
            if key == "search_path":
                # A comma-separated *identifier list*, not a single string: quoting
                # it as one literal would store one schema literally named
                # "pw_masked, public" instead of two schemas (verified by experiment).
                schema_list = ", ".join(quote_ident(s.strip()) for s in value.split(","))
                sql = f"ALTER ROLE {ident} SET search_path = {schema_list}"
            else:
                sql = f"ALTER ROLE {ident} SET {key} = {quote_literal(value)}"
            await _run(admin, result.dry_run, SyncAction(name, "config", sql, sql), result)

    if not desired.masked_search_path and "search_path" in config_now:
        sql = f"ALTER ROLE {ident} RESET search_path"
        await _run(admin, result.dry_run, SyncAction(name, "config", sql, sql), result)

    existing_memberships = await _existing_memberships(admin, name) if role_exists else {}
    desired_memberships = _desired_memberships(desired)

    for bundle, (inherit, set_opt) in desired_memberships.items():
        if existing_memberships.get(bundle) != (inherit, set_opt):
            bundle_ident = quote_ident(bundle)
            inherit_kw = "TRUE" if inherit else "FALSE"
            set_kw = "TRUE" if set_opt else "FALSE"
            sql = f"GRANT {bundle_ident} TO {ident} WITH INHERIT {inherit_kw}, SET {set_kw}"
            await _run(admin, result.dry_run, SyncAction(name, "grant", sql, sql), result)

    for bundle in existing_memberships:
        if bundle not in desired_memberships:
            bundle_ident = quote_ident(bundle)
            sql = f"REVOKE {bundle_ident} FROM {ident}"
            await _run(admin, result.dry_run, SyncAction(name, "revoke", sql, sql), result)


async def _prune_role(
    admin: asyncpg.Connection, name: str, current: ExistingRole, result: SyncResult
) -> None:
    ident = quote_ident(name)
    existing_memberships = await _existing_memberships(admin, name)
    for bundle in existing_memberships:
        bundle_ident = quote_ident(bundle)
        sql = f"REVOKE {bundle_ident} FROM {ident}"
        await _run(admin, result.dry_run, SyncAction(name, "prune-revoke", sql, sql), result)
    if current.rolcanlogin:
        sql = f"ALTER ROLE {ident} NOLOGIN"
        await _run(admin, result.dry_run, SyncAction(name, "prune-nologin", sql, sql), result)


__all__ = [
    "DesiredRole",
    "SyncAction",
    "SyncResult",
    "sync_roles",
]
