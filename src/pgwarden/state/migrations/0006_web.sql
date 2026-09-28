-- Browser-facing state (step 7): the gateway's own login sessions for /admin and
-- /approve, the email-to-immutable-id bindings, and the purpose of a pending
-- upstream login.

-- A pending upstream login either completes an MCP client's /oauth/authorize
-- request ('authorize') or signs someone in to the gateway's own pages
-- ('login', returning to next_path). identity_at is when the upstream login
-- returned: the start of the refresh-token family's absolute lifetime.
ALTER TABLE pgwarden.pending_authorizations
    ADD COLUMN purpose text NOT NULL DEFAULT 'authorize',
    ADD COLUMN next_path text,
    ADD COLUMN identity_at timestamptz,
    ADD CONSTRAINT pending_authorizations_purpose_valid CHECK (purpose IN ('authorize', 'login'));

-- Server-side web sessions. The cookie holds a random id; only its sha256 is
-- stored. Idle and absolute expiry are enforced on every read.
CREATE TABLE pgwarden.web_sessions (
    id_hash text PRIMARY KEY,
    provider text NOT NULL,
    subject text NOT NULL,
    email text,
    email_verified boolean NOT NULL,
    csrf_token text NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE INDEX web_sessions_expires_at_idx ON pgwarden.web_sessions (expires_at);

COMMENT ON TABLE pgwarden.web_sessions IS
    'Login sessions for the gateway''s own pages (/admin, /approve); cookie holds the id.';

-- An email-shaped identity entry (in people, approvers or admins) matches only a
-- verified email; on the first match the provider's immutable subject is
-- recorded here, and afterwards the same email with a different subject is
-- refused.
CREATE TABLE pgwarden.email_bindings (
    provider text NOT NULL,
    email text NOT NULL,
    subject text NOT NULL,
    bound_at timestamptz NOT NULL,
    PRIMARY KEY (provider, email)
);

COMMENT ON TABLE pgwarden.email_bindings IS
    'First-seen immutable subject for each verified email used by an email-shaped config entry.';
