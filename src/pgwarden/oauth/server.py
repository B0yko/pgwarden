"""The authorization-server facade: metadata, client registration, the token
endpoint and revocation.

pgwarden is its own OAuth 2.1 authorization server for the MCP resource at
``<public_url>/mcp``; the upstream IdP only proves who the person is (see
``pgwarden.oauth.authorize``). Access tokens are the gateway's own EdDSA JWTs,
audience-bound to the canonical MCP URL. The service functions here are HTTP
agnostic (``OAuthService``) so they can be tested directly; ``build_oauth_router``
exposes them as FastAPI routes.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime as dt
import hmac
import secrets
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from pgwarden.identity import Principal, machine_subject, resolve_principal
from pgwarden.mcp_server import GatewayDeps
from pgwarden.oauth import pkce, store
from pgwarden.oauth.cimd import (
    CimdError,
    Resolver,
    fetch_client_metadata,
    looks_like_cimd_client_id,
    system_resolver,
)
from pgwarden.oauth.jwt import TokenError, mint_access_token, verify_access_token
from pgwarden.oauth.keys import SigningKey
from pgwarden.oauth.redirects import RedirectUriError, validate_redirect_uri
from pgwarden.state import audit, ratelimit
from pgwarden.state.audit import AuditError
from pgwarden.state.conn import AnyConn

ACCESS_TTL_S = 600
CODE_TTL_S = 60
REFRESH_ABSOLUTE_S = 8 * 3600
CIMD_CACHE_S = 3600

_ALLOWED_DCR_GRANTS = frozenset({"authorization_code", "refresh_token"})
_AUTH_METHODS = frozenset({"none", "client_secret_basic", "client_secret_post"})
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class OAuthError(Exception):
    """An RFC 6749 / 7591 / 8707 error response."""

    def __init__(
        self,
        error: str,
        description: str,
        *,
        status: int = 400,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status
        self.headers = headers or {}


@dataclasses.dataclass(frozen=True)
class ClientAuth:
    client_id: str
    secret: str | None
    method: str  # "basic", "post" or "none"


def canonical_resource(public_url: str) -> str:
    return f"{public_url.rstrip('/')}/mcp"


def _normalize_url(value: str) -> tuple[str, str, int | None, str, str] | None:
    parts = urlsplit(value)
    if parts.fragment or not parts.scheme or not parts.hostname:
        return None
    scheme = parts.scheme.lower()
    port = parts.port
    if (scheme, port) in (("https", 443), ("http", 80)):
        port = None
    return (scheme, parts.hostname.lower(), port, parts.path.rstrip("/"), parts.query)


def resource_matches(value: str | None, canonical: str) -> bool:
    if not value:
        return False
    got = _normalize_url(value)
    return got is not None and got == _normalize_url(canonical)


def _client_ip(request: Request, trusted_proxy_hops: int) -> str:
    if trusted_proxy_hops > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        if len(hops) >= trusted_proxy_hops:
            return hops[-trusted_proxy_hops]
    return request.client.host if request.client else "unknown"


def _parse_client_auth(headers: Any, form: dict[str, str]) -> ClientAuth | None:
    header = headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
        client_id, sep, secret = decoded.partition(":")
        if not sep:
            return None
        return ClientAuth(unquote(client_id), unquote(secret), "basic")
    form_client_id = form.get("client_id")
    if not form_client_id:
        return None
    form_secret = form.get("client_secret")
    return ClientAuth(form_client_id, form_secret, "post" if form_secret is not None else "none")


@dataclasses.dataclass
class OAuthService:
    """HTTP-agnostic authorization-server logic over the state database."""

    gateway: GatewayDeps
    signing_key: SigningKey
    resolver: Resolver = system_resolver
    cimd_transport: httpx.AsyncBaseTransport | None = None
    access_ttl_s: int = ACCESS_TTL_S

    @property
    def issuer(self) -> str:
        return self.gateway.config.public_url.rstrip("/")

    @property
    def resource(self) -> str:
        return canonical_resource(self.gateway.config.public_url)

    def now(self) -> dt.datetime:
        return self.gateway.now()

    # -- metadata -----------------------------------------------------------

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
            "resource_name": "pgwarden",
        }

    def authorization_server_metadata(self) -> dict[str, Any]:
        base = self.issuer
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "revocation_endpoint": f"{base}/oauth/revoke",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": sorted(_AUTH_METHODS),
            "revocation_endpoint_auth_methods_supported": sorted(_AUTH_METHODS),
            "client_id_metadata_document_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }

    # -- audit ----------------------------------------------------------------

    async def _audit(
        self,
        conn: AnyConn,
        *,
        outcome: audit.Outcome,
        tool: str,
        client_id: str | None = None,
        subject: str | None = None,
        email: str | None = None,
        pg_role: str | None = None,
    ) -> None:
        try:
            await audit.record(
                conn,
                event="auth",
                outcome=outcome,
                tool=tool,
                client_id=client_id,
                identity_sub=subject,
                identity_email=email,
                pg_role=pg_role,
            )
        except AuditError as exc:
            # Fail closed: if the event cannot be recorded, the request fails.
            raise OAuthError("server_error", "audit log unavailable", status=500) from exc

    # -- clients --------------------------------------------------------------

    async def resolve_client(self, conn: AnyConn, client_id: str) -> store.ClientRecord | None:
        """A registered client, or a Client ID Metadata Document fetched (and cached) on demand."""
        record = await store.get_client(conn, client_id)
        now = self.now()
        fresh = record is not None and (
            record.kind != "cimd" or (now - record.created_at).total_seconds() < CIMD_CACHE_S
        )
        if record is not None and fresh:
            return record
        if not looks_like_cimd_client_id(client_id):
            return record
        try:
            doc = await fetch_client_metadata(
                client_id, resolver=self.resolver, transport=self.cimd_transport
            )
        except CimdError:
            return None
        await store.upsert_cimd_client(conn, client_id=client_id, doc=doc, now=now)
        return await store.get_client(conn, client_id)

    async def register(
        self, conn: AnyConn, body: dict[str, Any], *, client_ip: str
    ) -> dict[str, Any]:
        config = self.gateway.config
        limit = await ratelimit.check_and_increment(
            conn,
            "registration",
            f"ip:{client_ip}",
            limit=config.limits.registrations_per_hour,
            window_seconds=3600,
            now=self.now(),
        )
        if not limit.allowed:
            await self._audit(conn, outcome="rate_limited", tool="oauth.register")
            raise OAuthError(
                "rate_limited",
                "too many client registrations from this address; retry later",
                status=429,
                headers={"Retry-After": str(limit.retry_after_s)},
            )

        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            raise OAuthError("invalid_redirect_uri", "redirect_uris must be a non-empty list")
        for uri in uris:
            try:
                validate_redirect_uri(uri)
            except RedirectUriError as exc:
                raise OAuthError("invalid_redirect_uri", str(exc)) from exc

        method = body.get("token_endpoint_auth_method", "client_secret_basic")
        if method not in _AUTH_METHODS:
            raise OAuthError(
                "invalid_client_metadata", f"unsupported token_endpoint_auth_method {method!r}"
            )
        grant_types = body.get("grant_types", ["authorization_code", "refresh_token"])
        if not isinstance(grant_types, list) or not set(grant_types) <= _ALLOWED_DCR_GRANTS:
            raise OAuthError(
                "invalid_client_metadata",
                "grant_types may only contain authorization_code and refresh_token",
            )
        response_types = body.get("response_types", ["code"])
        if response_types != ["code"]:
            raise OAuthError("invalid_client_metadata", "response_types must be ['code']")
        name = body.get("client_name")
        if not isinstance(name, str) or not name.strip():
            name = urlsplit(uris[0]).hostname or urlsplit(uris[0]).scheme or "unnamed client"
        name = name.strip()[:200]

        client_id = secrets.token_urlsafe(24)
        secret: str | None = None
        secret_hash: str | None = None
        if method != "none":
            secret = secrets.token_urlsafe(32)
            secret_hash = store.sha256_hex(secret)
        now = self.now()
        metadata = {
            k: v
            for k, v in body.items()
            if k in ("client_uri", "logo_uri", "software_id", "software_version", "scope")
        }
        await store.insert_client(
            conn,
            client_id=client_id,
            kind="dcr",
            client_name=name,
            redirect_uris=list(uris),
            token_endpoint_auth_method=method,
            client_secret_hash=secret_hash,
            registered_ip=client_ip,
            metadata=metadata,
            now=now,
        )
        await self._audit(conn, outcome="ok", tool="oauth.register", client_id=client_id)
        response: dict[str, Any] = {
            "client_id": client_id,
            "client_id_issued_at": int(now.timestamp()),
            "client_name": name,
            "redirect_uris": list(uris),
            "token_endpoint_auth_method": method,
            "grant_types": list(grant_types),
            "response_types": ["code"],
        }
        if secret is not None:
            response["client_secret"] = secret
            response["client_secret_expires_at"] = 0
        return response

    async def _authenticate_client(
        self, conn: AnyConn, auth: ClientAuth | None
    ) -> store.ClientRecord:
        if auth is None:
            raise OAuthError("invalid_client", "client authentication is required", status=401)
        record = await self.resolve_client(conn, auth.client_id)
        if record is None:
            raise OAuthError("invalid_client", "unknown client", status=401)
        if record.token_endpoint_auth_method == "none":
            if auth.secret:
                raise OAuthError(
                    "invalid_client", "public clients must not send a secret", status=401
                )
            return record
        if auth.secret is None or record.client_secret_hash is None:
            raise OAuthError(
                "invalid_client",
                "client secret is required",
                status=401,
                headers={"WWW-Authenticate": 'Basic realm="pgwarden"'},
            )
        if not hmac.compare_digest(store.sha256_hex(auth.secret), record.client_secret_hash):
            raise OAuthError(
                "invalid_client",
                "client authentication failed",
                status=401,
                headers={"WWW-Authenticate": 'Basic realm="pgwarden"'},
            )
        return record

    # -- token endpoint -------------------------------------------------------------

    def _mint(self, subject: str, client_id: str) -> str:
        return mint_access_token(
            self.signing_key.private_key,
            self.signing_key.kid,
            issuer=self.issuer,
            audience=self.resource,
            subject=subject,
            client_id=client_id,
            now=self.now(),
            ttl_seconds=self.access_ttl_s,
        )

    async def _principal_or_error(self, conn: AnyConn, subject: str) -> Principal:
        principal = resolve_principal(self.gateway.config, subject)
        if principal is None:
            raise OAuthError("invalid_grant", "this identity is no longer mapped")
        if await store.is_suspended(conn, principal.role_name):
            raise OAuthError("invalid_grant", "this identity is suspended")
        return principal

    async def token(
        self, conn: AnyConn, form: dict[str, str], auth: ClientAuth | None
    ) -> dict[str, Any]:
        grant = form.get("grant_type")
        if grant == "authorization_code":
            return await self._grant_authorization_code(conn, form, auth)
        if grant == "refresh_token":
            return await self._grant_refresh_token(conn, form, auth)
        if grant == "client_credentials":
            return await self._grant_client_credentials(conn, form, auth)
        raise OAuthError("unsupported_grant_type", f"grant_type {grant!r} is not supported")

    async def _grant_authorization_code(
        self, conn: AnyConn, form: dict[str, str], auth: ClientAuth | None
    ) -> dict[str, Any]:
        client = await self._authenticate_client(conn, auth)
        if not resource_matches(form.get("resource"), self.resource):
            raise OAuthError("invalid_target", f"resource must be {self.resource}")
        code = form.get("code")
        if not code:
            raise OAuthError("invalid_request", "code is required")
        now = self.now()
        stored = await store.consume_auth_code(conn, code, now)
        if stored is None:
            await self._audit(
                conn, outcome="denied", tool="oauth.token", client_id=client.client_id
            )
            raise OAuthError("invalid_grant", "authorization code is invalid, expired or used")
        if stored.client_id != client.client_id:
            raise OAuthError("invalid_grant", "authorization code was issued to another client")
        if form.get("redirect_uri") != stored.redirect_uri:
            raise OAuthError(
                "invalid_grant", "redirect_uri does not match the authorization request"
            )
        if not pkce.verify(form.get("code_verifier"), stored.code_challenge):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        if not resource_matches(stored.resource, self.resource):
            raise OAuthError("invalid_target", "authorization was not issued for this resource")

        principal = await self._principal_or_error(conn, stored.principal_subject)
        absolute = stored.upstream_login_at + dt.timedelta(seconds=REFRESH_ABSOLUTE_S)
        if absolute <= now:
            raise OAuthError("invalid_grant", "the upstream login is too old; sign in again")

        family_id = secrets.token_urlsafe(18)
        refresh = secrets.token_urlsafe(32)
        await store.create_family(
            conn,
            family_id=family_id,
            principal_subject=principal.subject,
            client_id=client.client_id,
            login_at=stored.upstream_login_at,
            absolute_expires_at=absolute,
        )
        await store.insert_refresh_token(conn, token=refresh, family_id=family_id, issued_at=now)
        await store.touch_client(conn, client.client_id, now)
        access = self._mint(principal.subject, client.client_id)
        await self._audit(
            conn,
            outcome="ok",
            tool="oauth.token",
            client_id=client.client_id,
            subject=principal.subject,
            email=principal.email,
            pg_role=principal.role_name,
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_ttl_s,
            "refresh_token": refresh,
        }

    async def _grant_refresh_token(
        self, conn: AnyConn, form: dict[str, str], auth: ClientAuth | None
    ) -> dict[str, Any]:
        client = await self._authenticate_client(conn, auth)
        resource = form.get("resource")
        if resource is not None and not resource_matches(resource, self.resource):
            raise OAuthError("invalid_target", f"resource must be {self.resource}")
        token = form.get("refresh_token")
        if not token:
            raise OAuthError("invalid_request", "refresh_token is required")
        now = self.now()
        use = await store.use_refresh_token(conn, token, now)
        family = use.family
        if family is None:
            raise OAuthError("invalid_grant", "unknown refresh token")
        if use.reused:
            await store.revoke_family(conn, family.family_id, "refresh token reuse", now)
            await self._audit(
                conn,
                outcome="denied",
                tool="oauth.refresh_reuse",
                client_id=client.client_id,
                subject=family.principal_subject,
            )
            raise OAuthError("invalid_grant", "refresh token reuse detected; session revoked")
        if family.client_id != client.client_id:
            raise OAuthError("invalid_grant", "refresh token was issued to another client")
        if family.revoked_at is not None:
            raise OAuthError("invalid_grant", "this session has been revoked")
        if now >= family.absolute_expires_at:
            raise OAuthError("invalid_grant", "this session reached its absolute lifetime")
        principal = await self._principal_or_error(conn, family.principal_subject)

        refresh = secrets.token_urlsafe(32)
        await store.insert_refresh_token(
            conn, token=refresh, family_id=family.family_id, issued_at=now
        )
        access = self._mint(principal.subject, client.client_id)
        await self._audit(
            conn,
            outcome="ok",
            tool="oauth.refresh",
            client_id=client.client_id,
            subject=principal.subject,
            pg_role=principal.role_name,
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_ttl_s,
            "refresh_token": refresh,
        }

    async def _grant_client_credentials(
        self, conn: AnyConn, form: dict[str, str], auth: ClientAuth | None
    ) -> dict[str, Any]:
        if auth is None or auth.secret is None:
            raise OAuthError(
                "invalid_client",
                "machine clients authenticate with client_id and client_secret",
                status=401,
                headers={"WWW-Authenticate": 'Basic realm="pgwarden"'},
            )
        machine = next((m for m in self.gateway.config.machines if m.name == auth.client_id), None)
        stored_hash = await store.machine_secret_hash(conn, auth.client_id) if machine else None
        if (
            machine is None
            or stored_hash is None
            or not hmac.compare_digest(store.sha256_hex(auth.secret), stored_hash)
        ):
            await self._audit(
                conn, outcome="denied", tool="oauth.client_credentials", client_id=auth.client_id
            )
            raise OAuthError(
                "invalid_client",
                "client authentication failed",
                status=401,
                headers={"WWW-Authenticate": 'Basic realm="pgwarden"'},
            )
        if not resource_matches(form.get("resource"), self.resource):
            raise OAuthError("invalid_target", f"resource must be {self.resource}")
        principal = await self._principal_or_error(conn, machine_subject(machine.name))
        access = self._mint(principal.subject, machine.name)
        await self._audit(
            conn,
            outcome="ok",
            tool="oauth.client_credentials",
            client_id=machine.name,
            subject=principal.subject,
            pg_role=principal.role_name,
        )
        return {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl_s}

    # -- revocation -------------------------------------------------------------------

    async def revoke(self, conn: AnyConn, form: dict[str, str], auth: ClientAuth | None) -> None:
        """RFC 7009: revoke a refresh token (its whole family) or an access token."""
        token = form.get("token")
        if not token:
            raise OAuthError("invalid_request", "token is required")
        is_machine = auth is not None and any(
            m.name == auth.client_id for m in self.gateway.config.machines
        )
        client_id = auth.client_id if (auth is not None and is_machine) else None
        if client_id is None:
            client_id = (await self._authenticate_client(conn, auth)).client_id
        now = self.now()
        family = await store.family_for_refresh_token(conn, token)
        if family is not None:
            if family.client_id == client_id:
                await store.revoke_family(conn, family.family_id, "revoked by client", now)
                await self._audit(conn, outcome="ok", tool="oauth.revoke", client_id=client_id)
            return
        try:
            # Verify signature, typ, iss and aud but not the clock: an expired
            # token may still be revoked (RFC 7009 does not forbid it).
            claims = verify_access_token(
                token,
                {self.signing_key.kid: self.signing_key.public_key},
                issuer=self.issuer,
                audience=self.resource,
                now=dt.datetime(1970, 1, 1, tzinfo=dt.UTC),
            )
        except TokenError:
            return  # not one of ours: 200 per RFC 7009
        if claims.client_id == client_id:
            await store.revoke_jti(conn, claims.jti, claims.expires_at)
            await self._audit(conn, outcome="ok", tool="oauth.revoke", client_id=client_id)


def _error_response(err: OAuthError) -> JSONResponse:
    return JSONResponse(
        {"error": err.error, "error_description": err.description},
        status_code=err.status,
        headers={**_NO_STORE, **err.headers},
    )


async def _form(request: Request) -> dict[str, str]:
    form = await request.form()
    return {k: v for k, v in form.items() if isinstance(v, str)}


def build_oauth_router(service: OAuthService) -> APIRouter:
    router = APIRouter()
    trusted_hops = service.gateway.config.trusted_proxy_hops

    @router.get("/.well-known/oauth-protected-resource/mcp")
    @router.get("/.well-known/oauth-protected-resource")
    async def protected_resource() -> JSONResponse:
        return JSONResponse(service.protected_resource_metadata())

    @router.get("/.well-known/oauth-authorization-server")
    async def authorization_server() -> JSONResponse:
        return JSONResponse(service.authorization_server_metadata())

    @router.post("/oauth/register")
    async def register(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except ValueError:
            return _error_response(OAuthError("invalid_client_metadata", "body must be JSON"))
        if not isinstance(body, dict):
            return _error_response(OAuthError("invalid_client_metadata", "body must be an object"))
        try:
            async with service.gateway.require_state_pool().acquire() as conn:
                result = await service.register(
                    conn, body, client_ip=_client_ip(request, trusted_hops)
                )
        except OAuthError as err:
            return _error_response(err)
        return JSONResponse(result, status_code=201, headers=_NO_STORE)

    @router.post("/oauth/token")
    async def token(request: Request) -> JSONResponse:
        form = await _form(request)
        auth = _parse_client_auth(request.headers, form)
        try:
            async with service.gateway.require_state_pool().acquire() as conn:
                result = await service.token(conn, form, auth)
        except OAuthError as err:
            return _error_response(err)
        return JSONResponse(result, headers=_NO_STORE)

    @router.post("/oauth/revoke")
    async def revoke(request: Request) -> JSONResponse:
        form = await _form(request)
        auth = _parse_client_auth(request.headers, form)
        try:
            async with service.gateway.require_state_pool().acquire() as conn:
                await service.revoke(conn, form, auth)
        except OAuthError as err:
            return _error_response(err)
        return JSONResponse({}, headers=_NO_STORE)

    return router


__all__ = [
    "ACCESS_TTL_S",
    "CODE_TTL_S",
    "REFRESH_ABSOLUTE_S",
    "ClientAuth",
    "OAuthError",
    "OAuthService",
    "build_oauth_router",
    "canonical_resource",
    "resource_matches",
]
