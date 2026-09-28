# ADR-0002: one Postgres login role per person, with derived SCRAM credentials

## Status

Accepted.

## Context

The gateway needs Postgres itself to decide what each person may see, so
that RLS and grants are the real enforcement point, not application code.
There were two ways to shape the connection between the gateway process and
Postgres:

1. One shared gateway login role, granted membership in every person's and
   machine's role, running `SET ROLE`/`SET SESSION AUTHORIZATION` (or
   `set_config('role', ...)`) per request to switch identity on a pooled
   connection.
2. One dedicated Postgres `LOGIN` role per person (`pw_u_<role>`) and per
   machine (`pw_m_<role>`), connected to directly, with its own small
   connection pool (`pgwarden.db.pools`).

Option 1 is the more common pattern for multi-tenant gateways, because it
lets a single connection pool serve every identity. It also has an
attractive-looking property: `session_user` never changes even after `SET
ROLE`, so it looks safe to key RLS on `session_user`. That property is the
trap -- RLS keyed on `session_user` is exactly what a shared login role
defeats, since `session_user` is the same for every request regardless of
who the gateway is currently impersonating; a policy would have to key on
`current_user` or a custom GUC instead, both of which change with `SET
ROLE`/`set_config` and are therefore attacker-influenced from inside a
single SQL statement.

## The experiment

`pgwarden.db.shared_login_experiment` builds option 1's design in a scratch
schema against a real Postgres 16: a login role granted `u_a` and `u_b`
`WITH INHERIT FALSE, SET TRUE`, each owning a table only its own role can
read. After `SET ROLE u_a`, it runs the same request in two shapes:

- **Dynamic SQL in the same statement as the role change** --
  `select set_config('role','u_b',true), query_to_xml('select * from tb', true, true, '')`.
- **A plain static subquery in the same statement** --
  `select set_config('role','u_b',true), (select v from tb limit 1)`.

`tests/integration/test_shared_login_experiment.py` runs this for real and
asserts the observed result:

> Reproduced: with one shared login role granted SET-TRUE membership in two
> person roles, a single statement -- `select set_config('role','u_b',true),
> query_to_xml('select * from tb', true, true, '')` -- switches role and
> reads the other person's table within that one statement, because
> `query_to_xml()` plans and runs its SQL-text argument at call time, after
> `set_config` has already taken effect earlier in the same target list. A
> plain static subquery in the same target list -- `select
> set_config('role','u_b',true), (select v from tb limit 1)` -- does NOT
> leak: Postgres checks every relation's permissions for the whole plan,
> including embedded subqueries, once at executor startup before any
> target-list expression runs, so the danger is specifically dynamic SQL
> evaluated inside the same statement as a role change, not every kind of
> subquery. With a dedicated per-person login role instead, `SET SESSION
> AUTHORIZATION` to another role is rejected outright (SQLSTATE 42501:
> permission denied to set session authorization), so `session_user` --
> and RLS keyed on it -- cannot be spoofed from SQL.

Two things worth being precise about, since they change what the escalation
actually threatens:

- The leak is real, but it needs a function that itself plans and executes
  SQL text at call time (`query_to_xml`, `dblink`, `EXECUTE` of dynamic
  SQL, ...), not "any subquery after `set_config`". A static subquery in
  the same target list is checked against the *pre-`set_config`* role,
  because Postgres validates every range table entry's permissions for the
  whole plan once at executor startup.
- pgwarden's own product surface makes this moot either way: `query` only
  ever runs a single prepared, non-dynamic user statement (item 5's read
  path), and never grants `EXECUTE` on `query_to_xml`/`dblink`/
  `postgres_fdw` to person or machine roles (`doctor`'s
  `check_dblink_fdw`). The experiment is about what a shared-login *design*
  would expose in general, independent of what this particular product
  happens to run today -- the whole point of enforcing access in Postgres
  itself (ADR-0001) is that the guarantee must not depend on the gateway's
  own code staying careful forever.

## Decision

Each person and machine gets its own dedicated Postgres `LOGIN` role,
connected to directly by `pgwarden.db.pools.PoolManager`. The read path never changes role, and nothing in the product
runs `SET SESSION AUTHORIZATION`. The only role switch is the write path's: an
approved write runs, in its own read-write transaction, after pgwarden's fixed
`set_config('role', <writer role>, true)` with a bound value, where the writer role is
a role the person's login role is a member of. `session_user`, which is what row-level
security keys on, never changes. Masking is reached through the person's bundle grants
and the `search_path`, not through role-switching SQL.

- The role's password is never chosen or typed anywhere: it is
  `HMAC-SHA256(PGWARDEN_ROLE_SECRET, role_name)`, sent to Postgres only as a
  pre-computed SCRAM-SHA-256 verifier (`pgwarden.db.scram`), so no
  plaintext password ever appears in SQL text, a server log, or a
  connection string on disk.
- `session_user` is therefore fixed for the lifetime of a physical
  connection and cannot be changed from SQL by anything the gateway or a
  malicious query running through it does. RLS policies in this product's
  demo, and in `docs/own-database.md`'s guidance for a real deployment, key
  on `session_user` (`demo/sql/03_rls.sql`, `internal.can_see_region`) for
  exactly this reason.
- Each person's/machine's pool is small (`pool.max_size`, default 2) and
  independently bounded (idle timeout, maximum lifetime, a global cap with
  LRU eviction of idle pools -- see `pgwarden.db.pools`), rather than one
  large shared pool, because a shared pool is precisely the resource a
  shared login role would need in order to multiplex identities on it.

## Consequences

- More Postgres connections in aggregate than a single shared pool would
  use (bounded by `pool.global_cap`, default 60, sized for `roles sync`'s
  `CONNECTION LIMIT` = `pool.max_size * max_replicas + 1` per role), and
  more Postgres roles to provision (`pgwarden roles sync`) -- an accepted
  cost, not a free design.
- RLS, grants and masking views can be written using `session_user` and
  trust that it is genuinely the connecting identity, with no gateway-side
  discipline required to keep that true.
- `pgwarden doctor` still checks for the attributes that would make even a
  per-person role dangerous on its own (SUPERUSER, BYPASSRLS, CREATEROLE,
  CREATEDB, membership in `pg_read_server_files`/`pg_write_server_files`/
  `pg_execute_server_program`/`pg_signal_backend`, and EXECUTE on
  `dblink`/`postgres_fdw` functions) -- the per-role design closes the
  role-switching escalation this ADR is about, not every possible
  Postgres-level escalation.
