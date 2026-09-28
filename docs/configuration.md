# Configuration reference

This file is generated from the pydantic models in `pgwarden.config` by `pgwarden report --config-doc` (CI checks it is in sync). Edit the models, not this file.

## Environment

Secrets accept a `<NAME>_FILE` variant that reads the value from a file (for Docker and Cloud Run secret mounts). Exactly one of `<NAME>` or `<NAME>_FILE` may be set.

| Variable | Used by | Meaning |
| --- | --- | --- |
| `PGWARDEN_CONFIG` | server + CLI | Path to pgwarden.yaml. |
| `PGWARDEN_TARGET_DSN` | server + CLI | Target database host/port/db and sslmode, no user or password. |
| `PGWARDEN_STATE_DSN` | server + CLI | State database DSN as pgwarden_app (also *_FILE). |
| `PGWARDEN_ADMIN_DSN` | CLI only | Admin DSN for provisioning; the server refuses to start if it is set. |
| `PGWARDEN_ROLE_SECRET` | server + provisioning | Secret that derives each role's SCRAM password (also *_FILE). |
| `PGWARDEN_SIGNING_KEY` | server | Ed25519 private key (PEM) that signs access tokens (also *_FILE). |
| `PGWARDEN_SESSION_SECRET` | server | Secret for cookies, CSRF tokens and approval links (also *_FILE). |
| `PGWARDEN_OIDC_CLIENT_SECRET` | server | pgwarden's client secret at the upstream IdP (also *_FILE). |
| `PGWARDEN_SLACK_WEBHOOK_URL` | server | Slack incoming webhook for approval notices (also *_FILE). |
| `PGWARDEN_SMTP_URL` | server | SMTP URL for approval emails (also *_FILE). |
| `PGWARDEN_SERVER_TIMING` | server | Set to 1 to add the Server-Timing header on /mcp. |

## `pgwarden.yaml`

### Config

The whole of ``pgwarden.yaml``.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `public_url` | str | **required** | The gateway's own externally reachable URL (no trailing slash). |
| `demo` | DemoConfig | `DemoConfig(enabled=False)` |  |
| `upstream` | UpstreamConfig | **required** |  |
| `people` | list[PersonConfig] | `[]` |  |
| `machines` | list[MachineConfig] | `[]` |  |
| `approvers` | list[IdentityRef] | `[]` | Identities allowed to approve proposed writes. |
| `admins` | list[IdentityRef] | `[]` | Identities allowed into /admin. |
| `masking` | MaskingConfig | `MaskingConfig(columns={}, view_grants={}, raw_access_bundles=[])` |  |
| `rls_required` | list[str] | `[]` | schema.table entries `doctor` checks have RLS enabled. |
| `pool` | PoolConfig | `PoolConfig(max_size=2, idle_timeout_s=60, max_lifetime_s=300, global_cap=60)` |  |
| `max_replicas` | int | `1` | Used to size each role's CONNECTION LIMIT. |
| `limits` | LimitsConfig | `LimitsConfig(queries_per_minute=60, proposals_per_hour=10, registrations_per_hour=20)` |  |
| `read` | ReadConfig | `ReadConfig(statement_timeout_ms=5000, lock_timeout_ms=1000, idle_in_transaction_timeout_ms=10000, row_cap=500, max_response_bytes=1048576)` |  |
| `write` | WriteConfig | `WriteConfig(statement_timeout_ms=5000, grant_ttl_s=900, pending_ttl_s=86400)` |  |
| `notifications` | NotificationsConfig | `NotificationsConfig(channels=['log'], smtp_from=None, smtp_to=[])` |  |
| `allowed_origins` | list[str] | `[]` | Origin header allowlist checked on /mcp when the header is present. |
| `trusted_proxy_hops` | int | `0` | Reverse proxies in front of the gateway whose X-Forwarded-For entries are trusted when deriving the client IP (for the registration rate limit). 0 uses the socket peer address; set 1 behind Cloud Run or a single load balancer. |

### UpstreamConfig

The single upstream OIDC provider pgwarden logs users in through.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | str | **required** | Provider name; the default for identity.provider when omitted. |
| `preset` | one of 'oidc', 'google', 'entra', 'github' | `'oidc'` | oidc (generic), google, entra or github. |
| `issuer` | str | **required** | OIDC issuer URL, as seen by the browser. |
| `discovery_url` | str | None | `None` | Discovery URL, if it differs from issuer + /.well-known/openid-configuration (for example a container-internal host for a demo IdP). |
| `client_id` | str | **required** | pgwarden's OAuth client id at the upstream provider. |
| `tenant_id` | str | None | `None` | Entra tenant id. Required for, and only meaningful with, the entra preset. |
| `scopes` | list[str] | `['openid', 'email', 'profile']` |  |

### IdentityRef

Ties a config entry to an upstream identity.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `provider` | str | None | `None` | Upstream provider name. Defaults to the single configured upstream.name. |
| `subject` | str | None | `None` | Immutable upstream subject id (the `sub` claim, or the GitHub numeric id). |
| `email` | str | None | `None` | Verified email address. Matched only when the provider asserts it verified. |
| `oid` | str | None | `None` | Entra object id (`oid` claim). Required together with `tid` for entra. |
| `tid` | str | None | `None` | Entra tenant id (`tid` claim). Must equal upstream.tenant_id (single tenant). |

### PersonConfig

One human identity: its login role and the bundles it is granted.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `identity` | IdentityRef | **required** | The upstream identity mapped to this person. |
| `role` | str | **required** | Role suffix; the login role is pw_u_<role>. Matches ^[a-z][a-z0-9_]{0,40}$. |
| `bundles` | list[str] | `[]` | Bundle roles, WITH INHERIT TRUE SET FALSE (created by the DBA's own SQL). |
| `writer` | str | None | `None` | Optional writer role, WITH INHERIT FALSE SET TRUE, used by propose_write. |

### MachineConfig

One machine (service) identity, authenticated with client_credentials.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | str | **required** | Machine identity name, used by `pgwarden machine secret <name>`. |
| `role` | str | **required** | Role suffix; the login role is pw_m_<role>. Matches ^[a-z][a-z0-9_]{0,40}$. |
| `bundles` | list[str] | `[]` | Bundle roles granted to this machine. |
| `rate_overrides` | RateOverrides | None | `None` | Optional per-machine rate limit overrides. |

### RateOverrides

Per-machine overrides of the default rate limits in ``limits``.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `queries_per_minute` | int | None | `None` | Overrides limits.queries_per_minute. |
| `proposals_per_hour` | int | None | `None` | Overrides limits.proposals_per_hour. |

### MaskingConfig

Column masking policy, enforced by generated views (`pgwarden masking apply`).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `columns` | pseudonym | `{}` | schema.table.column -> masking tag (email, phone, name, redact, pseudonym). |
| `view_grants` | dict[str, list[str]] | `{}` | schema.table -> bundle names granted SELECT on the masked view. |
| `raw_access_bundles` | list[str] | `[]` | Bundles that read base tables directly, bypassing masked views. |

### PoolConfig

Per-person/machine connection pool shape (see ADR-0002).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `max_size` | int | `2` | Maximum connections held per person/machine pool. |
| `idle_timeout_s` | int | `60` | A pooled connection idle this long is closed. |
| `max_lifetime_s` | int | `300` | A pooled connection is recycled after this long. |
| `global_cap` | int | `60` | Maximum connections across all pools; LRU-evicts idle pools beyond this. |

### LimitsConfig

Default rate limits, enforced in the state database (see item 9).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `queries_per_minute` | int | `60` | Per identity. |
| `proposals_per_hour` | int | `10` | Per identity. |
| `registrations_per_hour` | int | `20` | Per client-registering IP. |

### ReadConfig

Defaults applied to every `query` call (see the read path, item 5).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `statement_timeout_ms` | int | `5000` |  |
| `lock_timeout_ms` | int | `1000` |  |
| `idle_in_transaction_timeout_ms` | int | `10000` |  |
| `row_cap` | int | `500` | Maximum rows returned by `query`; more rows are truncated. |
| `max_response_bytes` | int | `1048576` | Serialized response byte cap. |

### WriteConfig

Defaults applied to the write path (see item 7).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `statement_timeout_ms` | int | `5000` |  |
| `grant_ttl_s` | int | `900` | How long an approval grant stays executable. |
| `pending_ttl_s` | int | `86400` | How long a pending proposal stays approvable. |

### NotificationsConfig

Where approval notifications go (never SQL or parameters; see item 7).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `channels` | slack | `['log']` |  |
| `smtp_from` | str | None | `None` | From address for the smtp channel. |
| `smtp_to` | list[str] | `[]` | Recipient addresses; defaults to the approvers' emails when empty. |

### DemoConfig

Controls only the landing page's demo-identities list, never authentication.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `False` | Show the demo identities table on the landing page. |
