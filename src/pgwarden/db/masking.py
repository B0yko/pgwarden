"""Column masking (item 6): ``pw_fn`` functions, ``pw_masked`` views, and the
doctor checks that verify both hold (item 11) plus the writer-subset
invariant (item 7).

Design, in one pass:

* Masking functions live in schema ``pw_fn``, owned by ``pw_masker``, a
  ``NOLOGIN`` role that never owns a base table. ``mask_email``,
  ``mask_phone`` and ``mask_name`` are plain, deterministic, ``IMMUTABLE``
  SQL functions. ``redact`` is polymorphic (``anyelement``) so it can sit on
  any column type. ``pseudonym`` is ``SECURITY DEFINER`` with a fixed
  ``search_path`` (the same pattern ``internal.can_see_region`` in the demo
  schema already uses, for the same reason: a hijacked ``search_path`` must
  not be able to redirect what a security-definer function resolves), so it
  alone can read the one-row salt table ``pw_fn.pseudonym_salt`` -- nothing
  else is ever granted access to it, including the masked roles themselves.
* ``masking apply`` generates one ``security_barrier`` view per tagged table
  in schema ``pw_masked``, ``SELECT ... FROM`` the base table (never a copy,
  never a materialized snapshot), owned by ``pw_masker``. Because Postgres
  checks a view's underlying-object privileges against the *view owner*, not
  the querying role, ``pw_masker`` -- not the person -- is who needs SELECT
  on the raw columns; the person only ever needs SELECT on the view. Because
  the demo's RLS policies are ``TO PUBLIC`` and keyed on ``session_user``
  (never spoofable, see ADR-0002), they still apply when the view is queried
  under ``pw_masker``'s privileges: RLS is not bypassed by the view, it is
  *carried through* it. There is no result-set post-processing anywhere in
  this module; the masking function calls are the only transformation, and
  they live in the view's own SQL text, resolved to fixed object OIDs at
  ``CREATE VIEW`` time -- immune to a later ``search_path`` change by design,
  not just by convention.
* Every view/schema grant this module issues comes from
  ``config.masking.view_grants``/``raw_access_bundles`` and nothing else;
  a bundle literally named ``public`` is rejected outright, on top of the
  identifier-quoting defense already in :mod:`pgwarden.db.identifiers` (a
  quoted ``"public"`` addresses a role named that, never the PUBLIC
  pseudo-role -- but a config author could still name a bundle ``public`` by
  mistake, so this module refuses it explicitly).
* Second-run idempotency does not rely on textual SQL comparison (Postgres
  reformats view definitions on the way back out, so comparing
  ``pg_get_viewdef()`` to the SQL this module wrote is not reliable). Instead
  each generated view carries a ``COMMENT ON VIEW`` fingerprint -- a hash of
  its base table's column list, types and mask tags -- and this module only
  re-``CREATE OR REPLACE``s a view when that fingerprint changes. Functions,
  the role, the schemas and the salt table are checked for existence only
  (their definitions are fixed, not config-dependent).
"""

from __future__ import annotations

import dataclasses
import hashlib
import os

import asyncpg

from pgwarden.config import Config, MaskTag, machine_role_name, person_role_name
from pgwarden.db.doctor import CheckFn, CheckResult, DoctorContext
from pgwarden.db.identifiers import quote_ident, quote_literal

MASKER_ROLE = "pw_masker"
FUNCTION_SCHEMA = "pw_fn"
VIEW_SCHEMA = "pw_masked"
SALT_TABLE = "pseudonym_salt"

#: Mask tag -> the pw_fn function it wraps a column in. Keep in sync with
#: pgwarden.config.MASK_TAGS.
_MASK_FUNCTIONS: dict[MaskTag, str] = {
    "email": "mask_email",
    "phone": "mask_phone",
    "name": "mask_name",
    "redact": "redact",
    "pseudonym": "pseudonym",
}

_FINGERPRINT_PREFIX = "pgwarden-masking-v1:"


class MaskingError(RuntimeError):
    """Raised for a masking configuration this module refuses to apply."""


@dataclasses.dataclass(frozen=True)
class MaskingAction:
    """One planned statement. ``sql`` is what runs; ``display_sql`` is what --dry-run prints."""

    kind: str
    sql: str
    display_sql: str


@dataclasses.dataclass
class MaskingResult:
    actions: list[MaskingAction] = dataclasses.field(default_factory=list)
    dry_run: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.actions)


async def _run(
    admin: asyncpg.Connection, dry_run: bool, action: MaskingAction, result: MaskingResult
) -> None:
    result.actions.append(action)
    if not dry_run:
        await admin.execute(action.sql)


def _reject_public(names: set[str]) -> None:
    for name in names:
        if name.lower() == "public":
            raise MaskingError(
                "masking.view_grants/raw_access_bundles may not name the PUBLIC pseudo-role "
                f"(got {name!r}); masking apply never grants to PUBLIC"
            )


# -- role, schemas, salt table --------------------------------------------


async def _ensure_masker_role(
    admin: asyncpg.Connection, result: MaskingResult, dry_run: bool
) -> None:
    exists = await admin.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", MASKER_ROLE)
    if exists:
        return
    sql = (
        f"CREATE ROLE {quote_ident(MASKER_ROLE)} NOLOGIN NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOBYPASSRLS"
    )
    await _run(admin, dry_run, MaskingAction("masker-role", sql, sql), result)


async def _ensure_schema(
    admin: asyncpg.Connection, schema: str, kind: str, result: MaskingResult, dry_run: bool
) -> None:
    exists = await admin.fetchval("SELECT to_regnamespace($1) IS NOT NULL", schema)
    if exists:
        return
    sql = f"CREATE SCHEMA {quote_ident(schema)} AUTHORIZATION {quote_ident(MASKER_ROLE)}"
    await _run(admin, dry_run, MaskingAction(kind, sql, sql), result)


async def _ensure_pseudonym_salt(
    admin: asyncpg.Connection, result: MaskingResult, dry_run: bool
) -> None:
    qualified = f"{FUNCTION_SCHEMA}.{SALT_TABLE}"
    table_exists = bool(await admin.fetchval("SELECT to_regclass($1) IS NOT NULL", qualified))
    if not table_exists:
        sql = (
            f"CREATE TABLE {quote_ident(FUNCTION_SCHEMA)}.{quote_ident(SALT_TABLE)} "
            "(salt bytea NOT NULL); "
            f"ALTER TABLE {quote_ident(FUNCTION_SCHEMA)}.{quote_ident(SALT_TABLE)} "
            f"OWNER TO {quote_ident(MASKER_ROLE)}; "
            f"REVOKE ALL ON TABLE {quote_ident(FUNCTION_SCHEMA)}.{quote_ident(SALT_TABLE)} "
            "FROM PUBLIC;"
        )
        await _run(admin, dry_run, MaskingAction("salt-table", sql, sql), result)
        has_row = False
    else:
        has_row = bool(await admin.fetchval(f"SELECT EXISTS (SELECT 1 FROM {qualified})"))

    if has_row:
        return
    salt_hex = os.urandom(32).hex()
    sql = (
        f"INSERT INTO {quote_ident(FUNCTION_SCHEMA)}.{quote_ident(SALT_TABLE)} (salt) "
        f"VALUES (decode({quote_literal(salt_hex)}, 'hex'))"
    )
    display = (
        f"INSERT INTO {quote_ident(FUNCTION_SCHEMA)}.{quote_ident(SALT_TABLE)} "
        "(salt) VALUES (<salt redacted>)"
    )
    await _run(admin, dry_run, MaskingAction("salt-seed", sql, display), result)


# -- masking functions ------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _FunctionDef:
    name: str
    signature: str  # argument-type list, for ALTER/REVOKE/GRANT ON FUNCTION
    body_sql: str  # the full CREATE FUNCTION statement
    comment: str


def _function_defs() -> list[_FunctionDef]:
    fn = quote_ident(FUNCTION_SCHEMA)
    return [
        _FunctionDef(
            name="mask_email",
            signature="text",
            comment="Keeps the domain, masks the local part to its first character: "
            "a***@example.com.",
            body_sql=f"""\
CREATE FUNCTION {fn}.mask_email(p_value text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $mask_email$
    SELECT CASE
        WHEN p_value IS NULL THEN NULL
        WHEN strpos(p_value, '@') > 1 THEN
            left(p_value, 1) || '***@' || split_part(p_value, '@', 2)
        WHEN strpos(p_value, '@') = 1 THEN
            '***@' || split_part(p_value, '@', 2)
        ELSE repeat('*', greatest(length(p_value), 1))
    END
$mask_email$""",
        ),
        _FunctionDef(
            name="mask_phone",
            signature="text",
            comment="Keeps the last 2 characters, masks the rest with '*' (same length).",
            body_sql=f"""\
CREATE FUNCTION {fn}.mask_phone(p_value text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $mask_phone$
    SELECT CASE
        WHEN p_value IS NULL THEN NULL
        WHEN length(p_value) <= 2 THEN repeat('*', length(p_value))
        ELSE repeat('*', length(p_value) - 2) || right(p_value, 2)
    END
$mask_phone$""",
        ),
        _FunctionDef(
            name="mask_name",
            signature="text",
            comment="Reduces a space-separated name to upper-case initials: Elin Vantor -> E.V.",
            body_sql=f"""\
CREATE FUNCTION {fn}.mask_name(p_value text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $mask_name$
    SELECT CASE
        WHEN p_value IS NULL THEN NULL
        WHEN trim(p_value) = '' THEN ''
        ELSE (
            SELECT string_agg(upper(left(word, 1)) || '.', '')
            FROM regexp_split_to_table(trim(p_value), '\\s+') AS word
            WHERE word <> ''
        )
    END
$mask_name$""",
        ),
        _FunctionDef(
            name="redact",
            signature="anyelement",
            comment="Replaces any non-null value with the fixed marker '[REDACTED]'.",
            body_sql=f"""\
CREATE FUNCTION {fn}.redact(p_value anyelement) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $redact$
    SELECT CASE WHEN p_value IS NULL THEN NULL ELSE '[REDACTED]' END
$redact$""",
        ),
        _FunctionDef(
            name="pseudonym",
            signature="text",
            comment="Salted SHA-256 prefix, stable for equal inputs so joins on it still work. "
            "SECURITY DEFINER with a fixed search_path: only this function (owned by "
            "pw_masker) can read pw_fn.pseudonym_salt.",
            body_sql=f"""\
CREATE FUNCTION {fn}.pseudonym(p_value text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = {FUNCTION_SCHEMA}, pg_catalog
AS $pseudonym$
    SELECT CASE
        WHEN p_value IS NULL THEN NULL
        ELSE 'ps_' || left(
            encode(sha256(convert_to(encode(salt, 'hex') || ':' || p_value, 'UTF8')), 'hex'),
            16
        )
    END
    FROM {fn}.{quote_ident(SALT_TABLE)}
    LIMIT 1
$pseudonym$""",
        ),
    ]


async def _ensure_functions(
    admin: asyncpg.Connection, result: MaskingResult, dry_run: bool
) -> None:
    for fn_def in _function_defs():
        exists = await admin.fetchval(
            "SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = $1 AND p.proname = $2",
            FUNCTION_SCHEMA,
            fn_def.name,
        )
        if exists:
            continue
        qualified_sig = f"{FUNCTION_SCHEMA}.{fn_def.name}({fn_def.signature})"
        sql = (
            f"{fn_def.body_sql};\n"
            f"ALTER FUNCTION {qualified_sig} OWNER TO {quote_ident(MASKER_ROLE)};\n"
            f"REVOKE ALL ON FUNCTION {qualified_sig} FROM PUBLIC;\n"
            f"GRANT EXECUTE ON FUNCTION {qualified_sig} TO {quote_ident(MASKER_ROLE)};\n"
            f"COMMENT ON FUNCTION {qualified_sig} IS {quote_literal(fn_def.comment)};"
        )
        await _run(admin, dry_run, MaskingAction(f"function:{fn_def.name}", sql, sql), result)


# -- masked views -------------------------------------------------------


def _tagged_tables(config: Config) -> list[tuple[str, str]]:
    """Every ``(schema, table)`` a masked view must exist for.

    Tables named in ``masking.columns`` (the spec's "tagged table") plus any
    additional table named only in ``masking.view_grants`` (a pass-through
    masked view an operator still wants to grant separately from a raw one).
    """
    tables: set[tuple[str, str]] = set()
    for key in config.masking.columns:
        schema, table, _column = key.split(".")
        tables.add((schema, table))
    for key in config.masking.view_grants:
        schema, table = key.split(".")
        tables.add((schema, table))
    return sorted(tables)


def _fingerprint(columns: list[asyncpg.Record], tag_map: dict[str, MaskTag]) -> str:
    parts = [
        f"{c['column_name']}:{c['data_type']}:{tag_map.get(c['column_name'], '')}" for c in columns
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"{_FINGERPRINT_PREFIX}{digest}"


async def _ensure_masker_base_select(
    admin: asyncpg.Connection, schema: str, table: str, result: MaskingResult, dry_run: bool
) -> None:
    """``pw_masker`` needs raw SELECT on the base table for its own views to run at all.

    Postgres checks a view's underlying-object privileges against the
    *view owner*, not the querying role (that is the whole mechanism this
    module relies on to let a masked person query ``pw_masked.customers``
    without ever holding SELECT on ``public.customers`` themselves) -- so
    without this grant, ``pw_masker`` itself cannot execute its own view.
    Verified by experiment: omitting this grant made every query against
    the masked view fail with `permission denied for table customers`, for
    every role including a superuser query as pw_masker directly, until
    this grant was added. This is exactly the raw access the masking
    invariant (`check_masking_invariant`) exempts pw_masker from.
    """
    full = f"{schema}.{table}"
    already = await admin.fetchval(
        "SELECT has_table_privilege($1, $2, 'SELECT')", MASKER_ROLE, full
    )
    if already:
        return
    sql = (
        f"GRANT SELECT ON {quote_ident(schema)}.{quote_ident(table)} TO {quote_ident(MASKER_ROLE)}"
    )
    await _run(admin, dry_run, MaskingAction(f"masker-select:{full}", sql, sql), result)


async def _ensure_masked_view(
    admin: asyncpg.Connection,
    config: Config,
    schema: str,
    table: str,
    result: MaskingResult,
    dry_run: bool,
) -> set[str]:
    """Create/refresh the view; returns the ``pw_fn`` function names its SELECT list uses.

    Callers use that set to reconcile EXECUTE grants (see
    :func:`_reconcile_function_execute`): unlike a view's underlying *table*
    privileges, which Postgres checks against the *view owner*, a function
    call embedded in the view's SELECT list is checked against the actual
    querying role (verified by experiment -- granting the view owner
    ``pw_masker`` EXECUTE alone left every masked query failing with
    `permission denied for function mask_name` until the querying role's own
    bundle was also granted EXECUTE).
    """
    await _ensure_masker_base_select(admin, schema, table, result, dry_run)
    columns = await admin.fetch(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position",
        schema,
        table,
    )
    if not columns:
        raise MaskingError(
            f"masking: {schema}.{table} is not a real table/view (check masking.columns "
            "and masking.view_grants)"
        )

    select_list: list[str] = []
    tag_map: dict[str, MaskTag] = {}
    used_functions: set[str] = set()
    for col in columns:
        column_name = str(col["column_name"])
        key = f"{schema}.{table}.{column_name}"
        tag = config.masking.columns.get(key)
        ident = quote_ident(column_name)
        if tag is None:
            select_list.append(ident)
            continue
        fn_name = _MASK_FUNCTIONS[tag]
        arg = ident if tag == "redact" else f"{ident}::text"
        select_list.append(f"{quote_ident(FUNCTION_SCHEMA)}.{fn_name}({arg}) AS {ident}")
        tag_map[column_name] = tag
        used_functions.add(fn_name)

    view_ident = f"{quote_ident(VIEW_SCHEMA)}.{quote_ident(table)}"
    base_ident = f"{quote_ident(schema)}.{quote_ident(table)}"
    select_sql = ",\n    ".join(select_list)
    create_sql = (
        f"CREATE OR REPLACE VIEW {view_ident} WITH (security_barrier = true) AS\n"
        f"SELECT\n    {select_sql}\nFROM {base_ident}"
    )

    fingerprint = _fingerprint(columns, tag_map)
    existing_fingerprint = await admin.fetchval(
        "SELECT obj_description(c.oid, 'pg_class') FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = 'v'",
        VIEW_SCHEMA,
        table,
    )
    if existing_fingerprint != fingerprint:
        sql = (
            f"{create_sql};\n"
            f"COMMENT ON VIEW {view_ident} IS {quote_literal(fingerprint)};\n"
            f"ALTER VIEW {view_ident} OWNER TO {quote_ident(MASKER_ROLE)};"
        )
        await _run(admin, dry_run, MaskingAction(f"view:{schema}.{table}", sql, sql), result)

    await _reconcile_view_grants(admin, config, schema, table, result, dry_run)
    return used_functions


async def _reconcile_view_grants(
    admin: asyncpg.Connection,
    config: Config,
    schema: str,
    table: str,
    result: MaskingResult,
    dry_run: bool,
) -> None:
    key = f"{schema}.{table}"
    desired = set(config.masking.view_grants.get(key, []))
    _reject_public(desired)

    rows = await admin.fetch(
        "SELECT DISTINCT g.rolname FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "JOIN LATERAL aclexplode(c.relacl) a ON true "
        "JOIN pg_roles g ON g.oid = a.grantee "
        "WHERE n.nspname = $1 AND c.relname = $2 AND a.privilege_type = 'SELECT'",
        VIEW_SCHEMA,
        table,
    )
    existing = {str(r["rolname"]) for r in rows if r["rolname"] != MASKER_ROLE}
    view_ident = f"{quote_ident(VIEW_SCHEMA)}.{quote_ident(table)}"

    for bundle in sorted(desired - existing):
        sql = f"GRANT SELECT ON {view_ident} TO {quote_ident(bundle)}"
        await _run(admin, dry_run, MaskingAction(f"grant:{key}:{bundle}", sql, sql), result)
    for bundle in sorted(existing - desired):
        sql = f"REVOKE SELECT ON {view_ident} FROM {quote_ident(bundle)}"
        await _run(admin, dry_run, MaskingAction(f"revoke:{key}:{bundle}", sql, sql), result)


async def _reconcile_schema_usage(
    admin: asyncpg.Connection, config: Config, result: MaskingResult, dry_run: bool
) -> None:
    """USAGE on schema ``pw_masked`` for every bundle granted a masked view.

    Without this, Postgres silently skips ``pw_masked`` while resolving an
    unqualified name through ``search_path`` (a schema a role has no USAGE
    on is not even considered), so an unqualified ``SELECT * FROM customers``
    for a masked person would fall through to ``public.customers`` instead
    of the masked view -- and then fail outright, since masked people are
    never granted SELECT on the base table. Verified by experiment against
    the demo config: without this grant, `SELECT * FROM customers` as alice
    raised `permission denied for table customers`, not masked rows.
    """
    desired: set[str] = set()
    for bundles in config.masking.view_grants.values():
        desired.update(bundles)
    _reject_public(desired)

    rows = await admin.fetch(
        "SELECT DISTINCT g.rolname FROM pg_namespace n "
        "JOIN LATERAL aclexplode(n.nspacl) a ON true "
        "JOIN pg_roles g ON g.oid = a.grantee "
        "WHERE n.nspname = $1 AND a.privilege_type = 'USAGE'",
        VIEW_SCHEMA,
    )
    existing = {str(r["rolname"]) for r in rows if r["rolname"] != MASKER_ROLE}
    schema_ident = quote_ident(VIEW_SCHEMA)

    for bundle in sorted(desired - existing):
        sql = f"GRANT USAGE ON SCHEMA {schema_ident} TO {quote_ident(bundle)}"
        await _run(admin, dry_run, MaskingAction(f"schema-usage:{bundle}", sql, sql), result)
    for bundle in sorted(existing - desired):
        sql = f"REVOKE USAGE ON SCHEMA {schema_ident} FROM {quote_ident(bundle)}"
        await _run(admin, dry_run, MaskingAction(f"schema-usage-revoke:{bundle}", sql, sql), result)


async def _reconcile_function_execute(
    admin: asyncpg.Connection,
    function_bundles: dict[str, set[str]],
    result: MaskingResult,
    dry_run: bool,
) -> None:
    """EXECUTE on each used ``pw_fn`` function for exactly the bundles whose view uses it.

    ``function_bundles`` is the union, across every masked view, of the
    bundles declared for a table whose SELECT list calls that function (see
    :func:`_ensure_masked_view`'s docstring for why this grant -- separate
    from ``pw_masker``'s own EXECUTE grant in :func:`_ensure_functions` --
    is required at all).
    """
    signatures = {fn_def.name: fn_def.signature for fn_def in _function_defs()}
    for fn_name, desired in sorted(function_bundles.items()):
        _reject_public(desired)
        qualified_sig = f"{quote_ident(FUNCTION_SCHEMA)}.{fn_name}({signatures[fn_name]})"

        rows = await admin.fetch(
            "SELECT DISTINCT g.rolname FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "JOIN LATERAL aclexplode(p.proacl) a ON true "
            "JOIN pg_roles g ON g.oid = a.grantee "
            "WHERE n.nspname = $1 AND p.proname = $2 AND a.privilege_type = 'EXECUTE'",
            FUNCTION_SCHEMA,
            fn_name,
        )
        existing = {str(r["rolname"]) for r in rows if r["rolname"] != MASKER_ROLE}

        for bundle in sorted(desired - existing):
            sql = f"GRANT EXECUTE ON FUNCTION {qualified_sig} TO {quote_ident(bundle)}"
            action = MaskingAction(f"function-execute:{fn_name}:{bundle}", sql, sql)
            await _run(admin, dry_run, action, result)
        for bundle in sorted(existing - desired):
            sql = f"REVOKE EXECUTE ON FUNCTION {qualified_sig} FROM {quote_ident(bundle)}"
            action = MaskingAction(f"function-execute-revoke:{fn_name}:{bundle}", sql, sql)
            await _run(admin, dry_run, action, result)


# -- entry point ----------------------------------------------------------


async def apply_masking(config: Config, admin_dsn: str, *, dry_run: bool = False) -> MaskingResult:
    """Reconcile ``pw_fn``/``pw_masked`` with ``config.masking``.

    With ``dry_run=True``, nothing is executed; the returned actions show
    the SQL that would run (the salt value is redacted the same way a
    role-sync verifier is). A second call with the same config performs zero
    actions (idempotent) -- functions/role/schemas/salt are created once and
    never touched again; masked views are only re-created when their
    fingerprint (base columns + mask tags) changes; grants are reconciled
    exactly against config every time, so a stray grant made outside this
    tool is revoked on the next run.
    """
    result = MaskingResult(dry_run=dry_run)
    admin = await asyncpg.connect(admin_dsn, timeout=10)
    try:
        await _ensure_masker_role(admin, result, dry_run)
        await _ensure_schema(admin, FUNCTION_SCHEMA, "function-schema", result, dry_run)
        await _ensure_pseudonym_salt(admin, result, dry_run)
        await _ensure_functions(admin, result, dry_run)

        tables = _tagged_tables(config)
        if tables:
            await _ensure_schema(admin, VIEW_SCHEMA, "view-schema", result, dry_run)
            function_bundles: dict[str, set[str]] = {}
            for schema, table in tables:
                used = await _ensure_masked_view(admin, config, schema, table, result, dry_run)
                bundles = set(config.masking.view_grants.get(f"{schema}.{table}", []))
                for fn_name in used:
                    function_bundles.setdefault(fn_name, set()).update(bundles)
            await _reconcile_schema_usage(admin, config, result, dry_run)
            await _reconcile_function_execute(admin, function_bundles, result, dry_run)
        return result
    finally:
        await admin.close()


# -- doctor checks (item 11: masking invariant, masked-view grants, item 7's
# writer-subset invariant) --------------------------------------------------


def _masked_login_roles(config: Config) -> list[str]:
    """Login roles that are *not* exempt from the masking invariant.

    Exempt: any person/machine whose bundles intersect
    ``masking.raw_access_bundles`` (they are meant to see raw data), plus
    ``pw_masker`` itself, which is not a login role and is never in this
    list -- it necessarily holds raw column privileges so the views it owns
    can execute at all (see the module docstring).
    """
    raw_bundles = set(config.masking.raw_access_bundles)
    roles: list[str] = []
    for person in config.people:
        if not raw_bundles & set(person.bundles):
            roles.append(person_role_name(person.role))
    for machine in config.machines:
        if not raw_bundles & set(machine.bundles):
            roles.append(machine_role_name(machine.role))
    return roles


async def check_masking_invariant(ctx: DoctorContext) -> CheckResult:
    """No non-exempt role can ``SELECT`` a tagged base column raw (item 6/11)."""
    if not ctx.config.masking.columns:
        return CheckResult("masking_invariant", "warn", "masking.columns is empty in config")
    roles = _masked_login_roles(ctx.config)
    if not roles:
        return CheckResult(
            "masking_invariant",
            "warn",
            "every configured person/machine is in a raw_access_bundles bundle",
        )

    problems: list[str] = []
    for qualified in ctx.config.masking.columns:
        schema, table, column = qualified.split(".")
        full_table = f"{schema}.{table}"
        for role in roles:
            can_read = await ctx.admin.fetchval(
                "SELECT has_column_privilege($1, $2, $3, 'SELECT')", role, full_table, column
            )
            if can_read:
                problems.append(f"{role} can SELECT raw {qualified}")
    if problems:
        return CheckResult("masking_invariant", "fail", "; ".join(problems))
    return CheckResult(
        "masking_invariant",
        "pass",
        f"{len(roles)} masked role(s) checked against {len(ctx.config.masking.columns)} "
        "tagged column(s): no raw access",
    )


async def check_masked_view_grants(ctx: DoctorContext) -> CheckResult:
    """Every SELECT grant on a ``pw_masked`` view is declared in ``masking.view_grants``."""
    views = await ctx.admin.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = $1 AND c.relkind = 'v'",
        VIEW_SCHEMA,
    )
    if not views:
        return CheckResult("masked_view_grants", "warn", "no masked views exist yet")

    declared_by_view: dict[str, set[str]] = {}
    for key, bundles in ctx.config.masking.view_grants.items():
        _schema, _dot, table = key.partition(".")
        declared_by_view.setdefault(table, set()).update(bundles)

    problems: list[str] = []
    for row in views:
        view_name = str(row["relname"])
        grantees = await ctx.admin.fetch(
            "SELECT DISTINCT g.rolname FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "JOIN LATERAL aclexplode(c.relacl) a ON true "
            "JOIN pg_roles g ON g.oid = a.grantee "
            "WHERE n.nspname = $1 AND c.relname = $2 AND a.privilege_type = 'SELECT'",
            VIEW_SCHEMA,
            view_name,
        )
        actual = {str(r["rolname"]) for r in grantees if r["rolname"] != MASKER_ROLE}
        desired = declared_by_view.get(view_name, set())
        stray = actual - desired
        missing = desired - actual
        if stray or missing:
            problems.append(
                f"pw_masked.{view_name}: stray grant(s) {sorted(stray)}, missing {sorted(missing)}"
            )
    if problems:
        return CheckResult("masked_view_grants", "fail", "; ".join(problems))
    return CheckResult(
        "masked_view_grants", "pass", f"{len(views)} masked view(s) match config exactly"
    )


def _writer_bundle_pairs(config: Config) -> dict[str, set[str]]:
    """writer role -> the union of bundles of every person configured with it.

    Config ties a writer role to a person, not directly to a bundle, so a
    writer's "own bundle" (item 7's invariant) is taken as the union of
    bundles of everyone who has that writer -- in the demo, bob and dana both
    have ``writer: support_writer`` and ``bundles: [support]``, so
    ``support_writer -> {support}``.
    """
    pairs: dict[str, set[str]] = {}
    for person in config.people:
        if person.writer:
            pairs.setdefault(person.writer, set()).update(person.bundles)
    return pairs


async def check_writer_subset(ctx: DoctorContext) -> CheckResult:
    """Each writer role's SELECT privileges are a subset of its bundle(s)' (item 7's invariant).

    A person can ``SET ROLE`` to their own writer role inside a read-only
    query, so the writer role must never be able to see a column its bundle
    itself cannot -- otherwise that ``SET ROLE`` would unlock masked or
    hidden columns. Computed with ``has_column_privilege`` over every base
    column outside the masking-machinery schemas, per column and per role,
    exactly as ``support_writer`` vs. ``support`` in the demo.
    """
    pairs = _writer_bundle_pairs(ctx.config)
    if not pairs:
        return CheckResult("writer_subset", "warn", "no writer roles configured")

    columns = await ctx.admin.fetch(
        "SELECT table_schema, table_name, column_name FROM information_schema.columns "
        "WHERE table_schema NOT IN ('pg_catalog', 'information_schema', $1, $2)",
        VIEW_SCHEMA,
        FUNCTION_SCHEMA,
    )

    problems: list[str] = []
    for writer, bundles in sorted(pairs.items()):
        if not bundles:
            problems.append(f"{writer}: has no bundle to compare its SELECT privileges against")
            continue
        for col in columns:
            full_table = f"{col['table_schema']}.{col['table_name']}"
            column_name = str(col["column_name"])
            writer_can = await ctx.admin.fetchval(
                "SELECT has_column_privilege($1, $2, $3, 'SELECT')", writer, full_table, column_name
            )
            if not writer_can:
                continue
            bundle_can = False
            for bundle in bundles:
                if await ctx.admin.fetchval(
                    "SELECT has_column_privilege($1, $2, $3, 'SELECT')",
                    bundle,
                    full_table,
                    column_name,
                ):
                    bundle_can = True
                    break
            if not bundle_can:
                problems.append(
                    f"{writer} can SELECT {full_table}.{column_name} beyond {sorted(bundles)}"
                )
    if problems:
        return CheckResult("writer_subset", "fail", "; ".join(problems))
    return CheckResult(
        "writer_subset",
        "pass",
        f"{len(pairs)} writer role(s) checked: SELECT stays within their bundle(s)",
    )


def masking_checks(config: Config) -> tuple[CheckFn, ...]:
    """``doctor``'s extra-checks hook (item 6/11's masking checks, item 7's writer-subset).

    Takes ``config`` for a stable, self-describing call site in the CLI even
    though each check reads ``ctx.config`` itself at run time (the same
    config, passed through :class:`~pgwarden.db.doctor.DoctorContext`).
    """
    del config
    return (check_masking_invariant, check_masked_view_grants, check_writer_subset)


__all__: list[str] = [
    "FUNCTION_SCHEMA",
    "MASKER_ROLE",
    "VIEW_SCHEMA",
    "MaskingAction",
    "MaskingError",
    "MaskingResult",
    "apply_masking",
    "check_masked_view_grants",
    "check_masking_invariant",
    "check_writer_subset",
    "masking_checks",
]
