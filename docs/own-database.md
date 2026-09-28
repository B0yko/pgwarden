# Running pgwarden on your own database

pgwarden works on the bundled demo data and, through configuration, on your own
Postgres 16+. Every fenced block below is executed as written by an integration test
(`tests/own_database/`, the `own-database` CI job) against a plain Postgres 16: it
creates the admin role from step 3 (not a superuser), runs the provisioning commands,
starts `pgwarden serve` and makes a real MCP query. The test changes only the host
and port, `sslmode`, and adds a suffix to role and database names so reruns do not
collide. It also fails if this file gains a block it does not run.

The model: **the DBA owns access.** Bundle roles, grants and row-level security are
created by your own migrations; pgwarden only creates the per-person login roles and
the masking machinery, and it enforces nothing that the database does not.

## 1. Bundle roles and RLS (your migration)

Create `NOLOGIN` bundle roles and grant them what each group may read. Enable RLS
with policies that are `TO PUBLIC` and keyed on `session_user`, which is the login
role `pw_u_<role>` (people) or `pw_m_<role>` (machines) and cannot be changed from
SQL. Never key a policy on `current_user` or on a setting such as
`current_setting('app.tenant')`: a query can change those
([ADR-0002](adr/0002-login-role-per-person.md)). A `SECURITY DEFINER` lookup function
with a fixed `search_path` reads the mapping, as `demo/sql/` does.

```sql migration
CREATE ROLE analyst NOLOGIN;
GRANT USAGE ON SCHEMA public TO analyst;

CREATE TABLE public.reports (
    id int PRIMARY KEY,
    team text NOT NULL,
    owner_email text NOT NULL,
    body text NOT NULL
);
INSERT INTO public.reports VALUES
    (1, 'eu', 'anna@example.com', 'EU report'),
    (2, 'us', 'ulf@example.com', 'US report');

-- which team each login role belongs to; people never read this table themselves
CREATE SCHEMA internal;
CREATE TABLE internal.team_of (login_role text PRIMARY KEY, team text NOT NULL);
INSERT INTO internal.team_of VALUES ('pw_u_alice', 'eu'), ('pw_m_reporting_bot', 'eu');

CREATE FUNCTION internal.my_team() RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = internal, pg_catalog
    AS $$ SELECT team FROM internal.team_of WHERE login_role = session_user $$;

ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY team_isolation ON public.reports
    FOR ALL TO PUBLIC
    USING (team = internal.my_team())
    WITH CHECK (team = internal.my_team());
```

`reports` has a PII column, so `analyst` gets no `SELECT` on the table itself: masking
(step 2) grants the bundle `SELECT` on a masked view instead. For a table without
masked columns, `GRANT SELECT` to the bundle directly. Do not grant `CREATE` on
`public` to `PUBLIC`, and keep person roles out of `pg_read_server_files` and friends;
`pgwarden doctor` checks all of this.

## 2. Write `pgwarden.yaml`

List each person and machine explicitly, mapping an identity to a role suffix and one
or more bundles. `masking.columns` tags a column, `view_grants` names the bundles that
may read the masked view, and `rls_required` makes `doctor` verify RLS is on. See
[configuration.md](configuration.md) for every field and
[identity-providers.md](identity-providers.md) for the `upstream` block.

```yaml pgwarden.yaml
public_url: https://pgwarden.example.com
upstream:
  name: corp
  preset: oidc
  issuer: https://idp.example.com
  client_id: pgwarden
people:
  - identity: { email: alice@example.com }
    role: alice
    bundles: [analyst]
machines:
  - name: reporting-bot
    role: reporting_bot
    bundles: [analyst]
approvers:
  - { email: carol@example.com }
admins:
  - { email: carol@example.com }
masking:
  columns:
    public.reports.owner_email: email
  view_grants:
    public.reports: [analyst]
rls_required: [public.reports]
```

## 3. The admin role

`db init`, `roles sync`, `masking apply` and `doctor` use `PGWARDEN_ADMIN_DSN`, which
the running server never holds. That role does not need to be a superuser. Create it
once, as a superuser, connected to your database:

```sql admin
CREATE ROLE pgwarden_admin LOGIN PASSWORD 'admin-password-example' CREATEROLE CREATEDB;
GRANT CREATE ON DATABASE app TO pgwarden_admin;
GRANT analyst TO pgwarden_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
CREATE ROLE pw_masker NOLOGIN;
GRANT pw_masker TO pgwarden_admin WITH INHERIT TRUE, SET TRUE;
GRANT SELECT ON public.reports TO pgwarden_admin WITH GRANT OPTION;
```

Each line is needed, and the test removes them one at a time to show the command that
depends on it then fails:

- `CREATEROLE`: `db init` creates `pgwarden_app`; `roles sync` creates `pw_u_*` and `pw_m_*`.
- `CREATEDB`: `db init` creates the state database.
- `CREATE` on the database: `masking apply` creates the `pw_fn` and `pw_masked` schemas.
- `ADMIN OPTION` on every bundle role in `pgwarden.yaml`: `roles sync` grants the
  bundle to each login role. `INHERIT FALSE, SET FALSE` keeps the admin from picking
  up the bundle's own privileges.
- Membership in `pw_masker` with `INHERIT` and `SET`: `masking apply` creates the
  schemas, functions and views owned by `pw_masker`, the role that owns all masking
  objects. There is one `pw_masker` per cluster; skip the `CREATE ROLE` line if it
  already exists (an earlier `masking apply`, or another database).
- `SELECT ... WITH GRANT OPTION` on each table that has a masked column: `masking
  apply` grants `pw_masker` `SELECT` on it, because a view reads its base table as the
  view's owner.

The gateway host connects as each `pw_u_*` and `pw_m_*` role with its SCRAM password
(`doctor` does too, for its pooler check), so `pg_hba.conf` must allow those logins.

## 4. Provision

Run from one directory holding `pgwarden.yaml`. Choose your own passwords in the two
DSNs: `PGWARDEN_STATE_DSN` names the state database and the `pgwarden_app` role that
`db init` creates.

```bash provision
export PGWARDEN_CONFIG=pgwarden.yaml
export PGWARDEN_TARGET_DSN='postgresql://db.example.com:5432/app?sslmode=verify-full'
export PGWARDEN_ADMIN_DSN='postgresql://pgwarden_admin:admin-password-example@db.example.com:5432/app'
export PGWARDEN_STATE_DSN='postgresql://pgwarden_app:state-password-example@db.example.com:5432/pgwarden_state'
export PGWARDEN_ROLE_SECRET_FILE=secrets/role_secret

pgwarden keys generate --out secrets   # signing key, role secret, session secret; once
pgwarden db init                       # state role, state database, migrations
pgwarden roles sync                    # one login role per person and machine
pgwarden masking apply                 # pw_fn functions and pw_masked views
pgwarden doctor                        # verify the invariants; non-zero on any failure
pgwarden machine secret reporting-bot --out-file secrets/machine-reporting-bot  # for step 6
```

Put the client secret your identity provider issued for pgwarden's OAuth client in
`secrets/oidc_client_secret`.

## 5. Run the gateway

`serve` needs exactly these variables (each secret also works as a plain variable
instead of `*_FILE`). It refuses to start if `PGWARDEN_ADMIN_DSN`, or
`PGWARDEN_ADMIN_DSN_FILE`, is set at all: the running server never holds the
provisioning credential. Start it from a different shell or service than step 4.

```bash serve
export PGWARDEN_CONFIG=pgwarden.yaml
export PGWARDEN_TARGET_DSN='postgresql://db.example.com:5432/app?sslmode=verify-full'
export PGWARDEN_STATE_DSN='postgresql://pgwarden_app:state-password-example@db.example.com:5432/pgwarden_state'
export PGWARDEN_ROLE_SECRET_FILE=secrets/role_secret
export PGWARDEN_SIGNING_KEY_FILE=secrets/signing_key.pem
export PGWARDEN_SESSION_SECRET_FILE=secrets/session_secret
export PGWARDEN_OIDC_CLIENT_SECRET_FILE=secrets/oidc_client_secret

pgwarden serve --host 0.0.0.0 --port 8080
```

## 6. Check it

People sign in through your identity provider in a browser; a machine signs in with its
client secret, so it can check the gateway headless. This gets a token for
`reporting-bot` and calls two tools:

```bash check
URL=https://pgwarden.example.com
TOKEN=$(curl -sSf -u reporting-bot:"$(cat secrets/machine-reporting-bot)" \
  -d grant_type=client_credentials -d resource="$URL/mcp" "$URL/oauth/token" | jq -r .access_token)
mcp() {
  curl -sSf "$URL/mcp" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$1"
}
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' \
  | jq .result.structuredContent
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT team, owner_email FROM reports"}}}' \
  | jq .result.structuredContent
```

`whoami` returns `pw_m_reporting_bot` with the `analyst` bundle and `masking_applies`
true. `query` returns one row, the `eu` team's, with `owner_email` as `a***@example.com`:
Postgres applied the RLS policy (the `us` row never leaves the database) and the masked
view (the role's `search_path` puts `pw_masked` first, so `reports` is the view).

## Poolers

Connect to Postgres directly or through a session-mode pooler. Transaction-mode
poolers, such as PgBouncer with `pool_mode = transaction` or a hosted "transaction
pooler" endpoint, are not supported ([ADR-0004](adr/0004-pooler-mode.md)). Every person
and machine has its own login role and connection pool, and the read path relies on
state that lives on one backend connection: server-side prepared statements, the
`DISCARD ALL` reset when a connection returns to the pool, and session state such as
`LISTEN`, advisory locks and cursors. A transaction-mode pooler can hand the next
statement to a different backend and break each of these without an error.

`pgwarden doctor` detects it. Its `pooler_mode` check connects to the host and port in
`PGWARDEN_TARGET_DSN` as a derived person or machine role (never the admin), opens two
connections, and fails if they share a backend (`pg_backend_pid()`) or if one
connection's backend changes between two transactions. Direct and session-mode
connections pass. Point `PGWARDEN_TARGET_DSN` at the address the gateway really uses.
