"""pydantic v2 models for ``pgwarden.yaml`` and process settings from the environment.

``docs/configuration.md`` is generated from the field descriptions on these
models by a later step; keep every field documented here.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from pgwarden.secrets import read_secret

# A bundle/writer role name, or one segment of a schema-qualified name, as an
# unquoted Postgres identifier: lower-case only (this product never quotes
# identifiers), starting with a letter or underscore, at most 63 bytes.
PG_IDENTIFIER_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

# The suffix appended to "pw_u_" or "pw_m_" to form a login role name. Kept
# stricter and shorter than a general Postgres identifier because it also
# has to read well in role names, logs and the admin UI.
ROLE_SUFFIX_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")

# A machine's identity name (used by `pgwarden machine secret <name>` and
# shown in the admin UI). Hyphens are allowed, unlike role suffixes.
MACHINE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")

MASK_TAGS = ("email", "phone", "name", "redact", "pseudonym")
MaskTag = Literal["email", "phone", "name", "redact", "pseudonym"]

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

UpstreamPreset = Literal["oidc", "google", "entra", "github"]
NotificationChannel = Literal["log", "smtp", "slack"]
_DEFAULT_CHANNELS: tuple[NotificationChannel, ...] = ("log",)


class ConfigError(RuntimeError):
    """Raised for an unreadable, unparsable or invalid configuration."""


def person_role_name(suffix: str) -> str:
    """The login role name for a person entry's ``role`` suffix."""
    return f"pw_u_{suffix}"


def machine_role_name(suffix: str) -> str:
    """The login role name for a machine entry's ``role`` suffix."""
    return f"pw_m_{suffix}"


def _check_qualified_name(value: str, segments: int, field: str) -> None:
    parts = value.split(".")
    if len(parts) != segments or not all(PG_IDENTIFIER_RE.match(p) for p in parts):
        kind = "schema.table.column" if segments == 3 else "schema.table"
        raise ValueError(f"{field} entry {value!r} must be a {kind} of valid Postgres identifiers")


class IdentityRef(BaseModel):
    """Ties a config entry to an upstream identity.

    Either ``subject`` or ``email`` for most providers, or ``oid`` + ``tid``
    for the ``entra`` preset (whose ``email`` claim is not verified). Exactly
    one shape may be used; see ``Config`` for the preset-dependent check,
    which needs to know ``upstream.preset``.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str | None = Field(
        default=None,
        description="Upstream provider name. Defaults to the single configured upstream.name.",
    )
    subject: str | None = Field(
        default=None,
        description="Immutable upstream subject id (the `sub` claim, or the GitHub numeric id).",
    )
    email: str | None = Field(
        default=None,
        description="Verified email address. Matched only when the provider asserts it verified.",
    )
    oid: str | None = Field(
        default=None,
        description="Entra object id (`oid` claim). Required together with `tid` for entra.",
    )
    tid: str | None = Field(
        default=None,
        description="Entra tenant id (`tid` claim). Must equal upstream.tenant_id (single tenant).",
    )

    @model_validator(mode="after")
    def _check_shape(self) -> IdentityRef:
        has_entra = self.oid is not None or self.tid is not None
        has_subject = self.subject is not None
        has_email = self.email is not None
        if has_entra:
            if self.oid is None or self.tid is None:
                raise ValueError("identity: oid and tid must both be set together")
            if has_subject or has_email:
                raise ValueError("identity: oid/tid cannot be combined with subject or email")
        elif has_subject == has_email:
            raise ValueError("identity: exactly one of subject or email is required")
        return self

    def key(self) -> tuple[str, ...]:
        """A hashable key for uniqueness checks, independent of which shape was used."""
        if self.oid is not None:
            return ("entra", self.oid, self.tid or "")
        if self.subject is not None:
            return ("subject", self.subject)
        return ("email", (self.email or "").lower())


class RateOverrides(BaseModel):
    """Per-machine overrides of the default rate limits in ``limits``."""

    model_config = ConfigDict(extra="forbid")

    queries_per_minute: int | None = Field(
        default=None, ge=1, description="Overrides limits.queries_per_minute."
    )
    proposals_per_hour: int | None = Field(
        default=None, ge=1, description="Overrides limits.proposals_per_hour."
    )


class PersonConfig(BaseModel):
    """One human identity: its login role and the bundles it is granted."""

    model_config = ConfigDict(extra="forbid")

    identity: IdentityRef = Field(description="The upstream identity mapped to this person.")
    role: str = Field(
        description="Role suffix; the login role is pw_u_<role>. Matches ^[a-z][a-z0-9_]{0,40}$."
    )
    bundles: list[str] = Field(
        default_factory=list,
        description="Bundle roles, WITH INHERIT TRUE SET FALSE (created by the DBA's own SQL).",
    )
    writer: str | None = Field(
        default=None,
        description="Optional writer role, WITH INHERIT FALSE SET TRUE, used by propose_write.",
    )

    @field_validator("role")
    @classmethod
    def _role_suffix(cls, v: str) -> str:
        if not ROLE_SUFFIX_RE.match(v):
            raise ValueError(f"role {v!r} must match {ROLE_SUFFIX_RE.pattern}")
        return v

    @field_validator("bundles")
    @classmethod
    def _bundle_names(cls, v: list[str]) -> list[str]:
        for name in v:
            if not PG_IDENTIFIER_RE.match(name):
                raise ValueError(f"bundle name {name!r} is not a valid Postgres identifier")
        return v

    @field_validator("writer")
    @classmethod
    def _writer_name(cls, v: str | None) -> str | None:
        if v is not None and not PG_IDENTIFIER_RE.match(v):
            raise ValueError(f"writer role {v!r} is not a valid Postgres identifier")
        return v


class MachineConfig(BaseModel):
    """One machine (service) identity, authenticated with client_credentials."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        description="Machine identity name, used by `pgwarden machine secret <name>`."
    )
    role: str = Field(
        description="Role suffix; the login role is pw_m_<role>. Matches ^[a-z][a-z0-9_]{0,40}$."
    )
    bundles: list[str] = Field(
        default_factory=list, description="Bundle roles granted to this machine."
    )
    rate_overrides: RateOverrides | None = Field(
        default=None, description="Optional per-machine rate limit overrides."
    )

    @field_validator("name")
    @classmethod
    def _name_shape(cls, v: str) -> str:
        if not MACHINE_NAME_RE.match(v):
            raise ValueError(f"machine name {v!r} must match {MACHINE_NAME_RE.pattern}")
        return v

    @field_validator("role")
    @classmethod
    def _role_suffix(cls, v: str) -> str:
        if not ROLE_SUFFIX_RE.match(v):
            raise ValueError(f"role {v!r} must match {ROLE_SUFFIX_RE.pattern}")
        return v

    @field_validator("bundles")
    @classmethod
    def _bundle_names(cls, v: list[str]) -> list[str]:
        for name in v:
            if not PG_IDENTIFIER_RE.match(name):
                raise ValueError(f"bundle name {name!r} is not a valid Postgres identifier")
        return v


class UpstreamConfig(BaseModel):
    """The single upstream OIDC provider pgwarden logs users in through."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Provider name; the default for identity.provider when omitted.")
    preset: UpstreamPreset = Field(
        default="oidc", description="oidc (generic), google, entra or github."
    )
    issuer: str = Field(description="OIDC issuer URL, as seen by the browser.")
    discovery_url: str | None = Field(
        default=None,
        description="Discovery URL, if it differs from issuer + /.well-known/openid-configuration "
        "(for example a container-internal host for a demo IdP).",
    )
    client_id: str = Field(description="pgwarden's OAuth client id at the upstream provider.")
    tenant_id: str | None = Field(
        default=None,
        description="Entra tenant id. Required for, and only meaningful with, the entra preset.",
    )
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])

    @model_validator(mode="after")
    def _entra_tenant(self) -> UpstreamConfig:
        if self.preset == "entra" and not self.tenant_id:
            raise ValueError("upstream.tenant_id is required for the entra preset")
        if self.preset != "entra" and self.tenant_id:
            raise ValueError("upstream.tenant_id is only meaningful for the entra preset")
        return self


class MaskingConfig(BaseModel):
    """Column masking policy, enforced by generated views (`pgwarden masking apply`)."""

    model_config = ConfigDict(extra="forbid")

    columns: dict[str, MaskTag] = Field(
        default_factory=dict,
        description="schema.table.column -> masking tag (email, phone, name, redact, pseudonym).",
    )
    view_grants: dict[str, list[str]] = Field(
        default_factory=dict,
        description="schema.table -> bundle names granted SELECT on the masked view.",
    )
    raw_access_bundles: list[str] = Field(
        default_factory=list,
        description="Bundles that read base tables directly, bypassing masked views.",
    )

    @field_validator("columns")
    @classmethod
    def _columns(cls, v: dict[str, MaskTag]) -> dict[str, MaskTag]:
        for key, tag in v.items():
            _check_qualified_name(key, 3, "masking.columns")
            if tag not in MASK_TAGS:
                raise ValueError(f"masking.columns[{key!r}] has unknown tag {tag!r}")
        return v

    @field_validator("view_grants")
    @classmethod
    def _view_grants(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        for key, bundles in v.items():
            _check_qualified_name(key, 2, "masking.view_grants")
            for bundle in bundles:
                if not PG_IDENTIFIER_RE.match(bundle):
                    raise ValueError(
                        f"masking.view_grants[{key!r}] bundle {bundle!r} is not a valid identifier"
                    )
        return v

    @field_validator("raw_access_bundles")
    @classmethod
    def _raw_bundles(cls, v: list[str]) -> list[str]:
        for bundle in v:
            if not PG_IDENTIFIER_RE.match(bundle):
                raise ValueError(
                    f"masking.raw_access_bundles entry {bundle!r} is not a valid identifier"
                )
        return v


class PoolConfig(BaseModel):
    """Per-person/machine connection pool shape (see ADR-0002)."""

    model_config = ConfigDict(extra="forbid")

    max_size: int = Field(
        default=2, ge=1, description="Maximum connections held per person/machine pool."
    )
    idle_timeout_s: int = Field(
        default=60, ge=1, description="A pooled connection idle this long is closed."
    )
    max_lifetime_s: int = Field(
        default=300, ge=1, description="A pooled connection is recycled after this long."
    )
    global_cap: int = Field(
        default=60,
        ge=1,
        description="Maximum connections across all pools; LRU-evicts idle pools beyond this.",
    )


class LimitsConfig(BaseModel):
    """Default rate limits, enforced in the state database (see item 9)."""

    model_config = ConfigDict(extra="forbid")

    queries_per_minute: int = Field(default=60, ge=1, description="Per identity.")
    proposals_per_hour: int = Field(default=10, ge=1, description="Per identity.")
    registrations_per_hour: int = Field(default=20, ge=1, description="Per client-registering IP.")


class ReadConfig(BaseModel):
    """Defaults applied to every `query` call (see the read path, item 5)."""

    model_config = ConfigDict(extra="forbid")

    statement_timeout_ms: int = Field(default=5000, ge=1)
    lock_timeout_ms: int = Field(default=1000, ge=1)
    idle_in_transaction_timeout_ms: int = Field(default=10000, ge=1)
    row_cap: int = Field(
        default=500, ge=1, description="Maximum rows returned by `query`; more rows are truncated."
    )
    max_response_bytes: int = Field(
        default=1_048_576, ge=1, description="Serialized response byte cap."
    )


class WriteConfig(BaseModel):
    """Defaults applied to the write path (see item 7)."""

    model_config = ConfigDict(extra="forbid")

    statement_timeout_ms: int = Field(default=5000, ge=1)
    grant_ttl_s: int = Field(
        default=900, ge=1, description="How long an approval grant stays executable."
    )
    pending_ttl_s: int = Field(
        default=86400, ge=1, description="How long a pending proposal stays approvable."
    )


class NotificationsConfig(BaseModel):
    """Where approval notifications go (never SQL or parameters; see item 7)."""

    model_config = ConfigDict(extra="forbid")

    channels: list[NotificationChannel] = Field(default_factory=lambda: list(_DEFAULT_CHANNELS))
    smtp_from: str | None = Field(default=None, description="From address for the smtp channel.")
    smtp_to: list[str] = Field(
        default_factory=list,
        description="Recipient addresses; defaults to the approvers' emails when empty.",
    )


class DemoConfig(BaseModel):
    """Controls only the landing page's demo-identities list, never authentication."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=False, description="Show the demo identities table on the landing page."
    )


class Config(BaseModel):
    """The whole of ``pgwarden.yaml``."""

    model_config = ConfigDict(extra="forbid")

    public_url: str = Field(
        description="The gateway's own externally reachable URL (no trailing slash)."
    )
    demo: DemoConfig = Field(default_factory=DemoConfig)
    upstream: UpstreamConfig
    people: list[PersonConfig] = Field(default_factory=list)
    machines: list[MachineConfig] = Field(default_factory=list)
    approvers: list[IdentityRef] = Field(
        default_factory=list, description="Identities allowed to approve proposed writes."
    )
    admins: list[IdentityRef] = Field(
        default_factory=list, description="Identities allowed into /admin."
    )
    masking: MaskingConfig = Field(default_factory=MaskingConfig)
    rls_required: list[str] = Field(
        default_factory=list, description="schema.table entries `doctor` checks have RLS enabled."
    )
    pool: PoolConfig = Field(default_factory=PoolConfig)
    max_replicas: int = Field(
        default=1, ge=1, description="Used to size each role's CONNECTION LIMIT."
    )
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    read: ReadConfig = Field(default_factory=ReadConfig)
    write: WriteConfig = Field(default_factory=WriteConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    allowed_origins: list[str] = Field(
        default_factory=list,
        description="Origin header allowlist checked on /mcp when the header is present.",
    )
    trusted_proxy_hops: int = Field(
        default=0,
        ge=0,
        description=(
            "Reverse proxies in front of the gateway whose X-Forwarded-For entries are trusted "
            "when deriving the client IP (for the registration rate limit). 0 uses the socket "
            "peer address; set 1 behind Cloud Run or a single load balancer."
        ),
    )

    @field_validator("public_url")
    @classmethod
    def _https_or_loopback(cls, v: str) -> str:
        parsed = urlsplit(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"public_url {v!r} must be an http(s) URL")
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" and host not in LOOPBACK_HOSTS:
            raise ValueError(
                f"public_url {v!r} must be https unless the host is loopback "
                "(localhost, 127.0.0.1, [::1])"
            )
        return v

    @field_validator("rls_required")
    @classmethod
    def _rls_tables(cls, v: list[str]) -> list[str]:
        for name in v:
            _check_qualified_name(name, 2, "rls_required")
        return v

    @model_validator(mode="after")
    def _cross_checks(self) -> Config:
        self._check_identities()
        return self

    def _check_identity_ref(self, ref: IdentityRef, where: str) -> None:
        if ref.provider is not None and ref.provider != self.upstream.name:
            raise ValueError(
                f"{where}: identity.provider {ref.provider!r} does not match the configured "
                f"upstream {self.upstream.name!r} (v0.1 supports exactly one upstream)"
            )
        is_entra = self.upstream.preset == "entra"
        has_entra_ref = ref.oid is not None
        if is_entra and not has_entra_ref:
            raise ValueError(
                f"{where}: the entra preset requires oid/tid identities, not subject/email"
            )
        if not is_entra and has_entra_ref:
            raise ValueError(f"{where}: oid/tid identities are only valid with the entra preset")
        if has_entra_ref and ref.tid != self.upstream.tenant_id:
            raise ValueError(
                f"{where}: identity.tid {ref.tid!r} does not match upstream.tenant_id "
                f"{self.upstream.tenant_id!r} (only single-tenant Entra is supported)"
            )

    def _check_identities(self) -> None:
        seen_identities: set[tuple[str, ...]] = set()
        seen_person_roles: set[str] = set()
        for i, person in enumerate(self.people):
            where = f"people[{i}]"
            self._check_identity_ref(person.identity, where)
            key = person.identity.key()
            if key in seen_identities:
                raise ValueError(f"{where}: identity is mapped by more than one person")
            seen_identities.add(key)
            if person.role in seen_person_roles:
                raise ValueError(f"{where}: role {person.role!r} is used by more than one person")
            seen_person_roles.add(person.role)

        seen_machine_roles: set[str] = set()
        seen_machine_names: set[str] = set()
        for i, machine in enumerate(self.machines):
            where = f"machines[{i}]"
            if machine.name in seen_machine_names:
                raise ValueError(f"{where}: machine name {machine.name!r} is used more than once")
            seen_machine_names.add(machine.name)
            if machine.role in seen_machine_roles:
                raise ValueError(f"{where}: role {machine.role!r} is used by more than one machine")
            seen_machine_roles.add(machine.role)

        for i, ref in enumerate(self.approvers):
            self._check_identity_ref(ref, f"approvers[{i}]")
        for i, ref in enumerate(self.admins):
            self._check_identity_ref(ref, f"admins[{i}]")


def load_config(path: str | Path) -> Config:
    """Load and validate ``pgwarden.yaml`` from ``path``.

    Raises :class:`ConfigError` for a missing file, invalid YAML, a
    non-mapping document, or a document that fails model validation.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {p}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{p}: the top-level YAML document must be a mapping")
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration in {p}:\n{exc}") from exc


class Settings(BaseModel):
    """Process settings read from the environment (never from pgwarden.yaml)."""

    model_config = ConfigDict(extra="forbid")

    config_path: Path = Field(description="Path to pgwarden.yaml (PGWARDEN_CONFIG).")
    target_dsn: str = Field(
        description="Target Postgres DSN: host, port, database, no user or password "
        "(PGWARDEN_TARGET_DSN)."
    )
    state_dsn: str = Field(
        description="State database DSN, connecting as pgwarden_app "
        "(PGWARDEN_STATE_DSN or PGWARDEN_STATE_DSN_FILE)."
    )
    server_timing: bool = Field(
        default=False,
        description="Emit Server-Timing headers on /mcp responses (PGWARDEN_SERVER_TIMING=1).",
    )

    @classmethod
    def from_env(cls) -> Settings:
        config_path = os.environ.get("PGWARDEN_CONFIG")
        if not config_path:
            raise ConfigError("PGWARDEN_CONFIG is required")
        target_dsn = os.environ.get("PGWARDEN_TARGET_DSN")
        if not target_dsn:
            raise ConfigError("PGWARDEN_TARGET_DSN is required")
        state_dsn = read_secret("PGWARDEN_STATE_DSN")
        if not state_dsn:
            raise ConfigError("PGWARDEN_STATE_DSN (or PGWARDEN_STATE_DSN_FILE) is required")
        server_timing = os.environ.get("PGWARDEN_SERVER_TIMING", "") == "1"
        return cls(
            config_path=Path(config_path),
            target_dsn=target_dsn,
            state_dsn=state_dsn,
            server_timing=server_timing,
        )
