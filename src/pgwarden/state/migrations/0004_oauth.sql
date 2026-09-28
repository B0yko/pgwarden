-- OAuth 2.1 authorization-server core (step 6): registered clients, the
-- pending-authorization staging table step 7's /oauth/authorize will drive,
-- single-use authorization codes, refresh-token families and their tokens,
-- and a small table of revoked access-token jtis.
--
-- No transaction-control statements: pgwarden.state.migrate wraps this whole
-- file in one transaction, along with the row that records it as applied.

-- Clients known to this authorization server: either dynamically registered
-- (RFC 7591, kind='dcr') or resolved from a Client ID Metadata Document and
-- cached (kind='cimd', client_id is the https URL it was fetched from).
CREATE TABLE pgwarden.oauth_clients (
    client_id text PRIMARY KEY,
    kind text NOT NULL,
    client_name text NOT NULL,
    redirect_uris jsonb NOT NULL,
    token_endpoint_auth_method text NOT NULL,
    client_secret_hash text,
    registered_ip text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    CONSTRAINT oauth_clients_kind_valid CHECK (kind IN ('dcr', 'cimd')),
    CONSTRAINT oauth_clients_auth_method_valid CHECK (
        token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post')
    )
);

COMMENT ON TABLE pgwarden.oauth_clients IS
    'Registered/cached OAuth clients (RFC 7591 dynamic registration or a cached CIMD document).';

-- One row per in-flight /oauth/authorize request (step 7): the pre-login
-- consent step, then the upstream OIDC leg, then the post-login confirmation
-- step, all keyed by this row's random id. Designed so step 7 can drive its
-- whole state machine off this one table: `stage` names where the request
-- currently is (for example 'consent_pending' -> 'upstream_pending' ->
-- 'confirm_pending' -> 'completed'); the identity_* columns are filled in
-- once the upstream callback returns; `browser_binding_hash` ties the row to
-- the browser's __Host- cookie so a stolen `id` alone is not enough to drive
-- someone else's pending request; `upstream_state_hash`/`upstream_nonce`/
-- `upstream_code_verifier` are this gateway's own state/nonce/PKCE sent to
-- the upstream IdP, checked at the callback.
CREATE TABLE pgwarden.pending_authorizations (
    id text PRIMARY KEY,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    client_state text,
    code_challenge text NOT NULL,
    resource text,
    scope text,
    stage text NOT NULL,
    browser_binding_hash text NOT NULL,
    upstream_state_hash text,
    upstream_nonce text,
    upstream_code_verifier text,
    identity_provider text,
    identity_subject text,
    identity_email text,
    identity_email_verified boolean,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

COMMENT ON TABLE pgwarden.pending_authorizations IS
    'In-flight /oauth/authorize requests: consent, upstream login, confirmation (step 7).';

CREATE INDEX pending_authorizations_expires_at_idx
    ON pgwarden.pending_authorizations (expires_at);

-- Single-use authorization codes (60s TTL). `code_hash` is sha256(code) hex;
-- the plaintext code is only ever handed to the client in the redirect and
-- never stored. `upstream_login_at` is when the person actually signed in
-- upstream (step 7 sets it); the token endpoint uses it, unchanged by later
-- refreshes, as the start of the refresh-token family's 8h absolute
-- lifetime (item 2: rotation never extends it).
CREATE TABLE pgwarden.auth_codes (
    code_hash text PRIMARY KEY,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    resource text,
    principal_subject text NOT NULL,
    identity_email text,
    upstream_login_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

COMMENT ON TABLE pgwarden.auth_codes IS
    'Single-use PKCE authorization codes, 60s TTL, stored as sha256(code).';

CREATE INDEX auth_codes_expires_at_idx ON pgwarden.auth_codes (expires_at);

-- A refresh-token family: everything minted from one authorization_code
-- redemption (and every rotation after it) shares one family_id. Reuse of an
-- already-used refresh token in this family revokes the whole family
-- (revoked_at/revoke_reason set); absolute_expires_at is fixed at creation
-- (login_at + 8h) and rotation never moves it.
CREATE TABLE pgwarden.token_families (
    family_id text PRIMARY KEY,
    principal_subject text NOT NULL,
    client_id text NOT NULL,
    login_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoke_reason text
);

COMMENT ON TABLE pgwarden.token_families IS
    'One row per refresh-token family; absolute_expires_at = upstream login + 8h, never extended.';

-- Individual opaque refresh tokens within a family, stored as sha256(token).
-- Rotated on every use (a new row, same family_id); `used_at` marks the
-- token consumed, and a second attempt to use an already-used token is the
-- reuse signal that revokes the whole family.
CREATE TABLE pgwarden.refresh_tokens (
    token_hash text PRIMARY KEY,
    family_id text NOT NULL REFERENCES pgwarden.token_families (family_id),
    issued_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE INDEX refresh_tokens_family_id_idx ON pgwarden.refresh_tokens (family_id);

-- Revoked access-token jtis (POST /oauth/revoke of an access token, or a
-- suspension). `expires_at` mirrors the token's own exp, so a periodic
-- prune can drop rows for tokens that would have expired anyway.
CREATE TABLE pgwarden.revoked_jtis (
    jti text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

COMMENT ON TABLE pgwarden.revoked_jtis IS
    'jti of every explicitly revoked access token; checked on every /mcp request.';

CREATE INDEX revoked_jtis_expires_at_idx ON pgwarden.revoked_jtis (expires_at);
