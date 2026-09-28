# Running pgwarden on your own database

pgwarden works on the bundled demo data and, through configuration, on your own
Postgres 16+. This document is followed literally by a CI integration test
(`tests/own_database/`) against a plain Postgres 16, so it stays correct.

The model: **the DBA owns access.** Bundle roles, grants and row-level security are
created by your own migrations; pgwarden only creates the per-person login roles and
the masking machinery, and it enforces nothing that the database does not.

## 1. Create bundle roles and RLS (your migration)

Create `NOLOGIN` bundle roles and grant them what each group may read. Enable RLS
with policies that are `TO PUBLIC` and keyed on `session_user` (never `current_user`
or a GUC a query could set — see [ADR-0002](adr/0002-login-role-per-person.md)).

```sql
CREATE ROLE analyst NOLOGIN;
GRANT USAGE ON SCHEMA public TO analyst;
GRANT SELECT ON public.reports TO analyst;

ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.reports
    FOR ALL TO PUBLIC
    USING (tenant = current_setting('app.tenant', true))  -- example; key yours on session_user
    WITH CHECK (tenant = current_setting('app.tenant', true));
```

Key real policies on `session_user` (for example through a `SECURITY DEFINER`
lookup function with a fixed `search_path`, as `demo/sql/` does). Do not grant
`CREATE` on `public` to `PUBLIC`, and keep person roles out of
`pg_read_server_files` and friends — `pgwarden doctor` checks all of this.

## 2. Write `pgwarden.yaml`

List each person and machine explicitly, mapping an identity to a role suffix and
one or more bundles. See [configuration.md](configuration.md) for every field.

```yaml
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
approvers:
  - { email: carol@example.com }
admins:
  - { email: carol@example.com }
```

## 3. Minimal admin privileges

`roles sync`, `masking apply` and `db init` use `PGWARDEN_ADMIN_DSN`, which the
running server never holds. That admin needs: `CREATEROLE`; `ADMIN OPTION` on the
bundle and writer roles it grants; and `CREATE` on the database (for the `pw_fn` and
`pw_masked` schemas). Add a `pg_hba.conf` entry allowing SCRAM logins from the
gateway host for the `pw_u_*` / `pw_m_*` roles.

## 4. Provision and run

```bash
export PGWARDEN_CONFIG=pgwarden.yaml
export PGWARDEN_TARGET_DSN='postgresql://db.example.com:5432/app?sslmode=verify-full'
export PGWARDEN_ADMIN_DSN='postgresql://admin:...@db.example.com:5432/app'
export PGWARDEN_STATE_DSN='postgresql://pgwarden_app:...@db.example.com:5432/pgwarden'
export PGWARDEN_ROLE_SECRET_FILE=/run/secrets/role_secret

pgwarden keys generate --out /run/secrets   # signing key + secrets, once
pgwarden db init          # state role, state database, migrations
pgwarden roles sync       # one login role per person/machine, SCRAM verifiers
pgwarden masking apply    # pw_fn functions and pw_masked views (if masking is configured)
pgwarden doctor           # verify the invariants; exits non-zero on any failure
pgwarden serve --host 0.0.0.0 --port 8080
```

`pgwarden serve` refuses to start if `PGWARDEN_ADMIN_DSN` is set: the running server
never holds the provisioning credential.
