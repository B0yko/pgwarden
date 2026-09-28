-- pgwarden state database: the migration-tracking table plus a minimal,
-- sure-to-be-needed table set. Later steps add their own migrations (audit,
-- tokens, proposals, rate limits, ...) as further numbered files here.
--
-- No transaction-control statements: pgwarden.state.migrate wraps this
-- whole file in one transaction, along with the row that records it as
-- applied.

CREATE SCHEMA IF NOT EXISTS pgwarden;

CREATE TABLE pgwarden.schema_migrations (
    version text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

-- Maps an upstream immutable identity to the config role it is bound to. On
-- the first match pgwarden records the id; a later login asserting the same
-- email with a different id for that person is refused (see the upstream
-- login and identity-binding logic added in a later step).
CREATE TABLE pgwarden.identity_bindings (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider text NOT NULL,
    subject text NOT NULL,
    person_role text NOT NULL,
    email text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);

-- Suspension state per configured person. No row means "not suspended".
-- `pgwarden people suspend|unsuspend` writes it; the auth middleware added
-- in a later step reads it on every token verification.
CREATE TABLE pgwarden.people_status (
    person_role text PRIMARY KEY,
    suspended boolean NOT NULL DEFAULT false,
    suspended_at timestamptz,
    suspended_by text,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Machine (client_credentials) secrets, hashed. `pgwarden machine secret
-- <name>` prints the plaintext once and stores only this hash.
CREATE TABLE pgwarden.machines (
    name text PRIMARY KEY,
    secret_hash text NOT NULL,
    rotated_at timestamptz NOT NULL DEFAULT now()
);
