"""The FastAPI application: the MCP mount, the auth middleware that establishes
the per-request principal, the ``Server-Timing`` header, and health probes.

Auth runs as ASGI middleware on the ``/mcp`` mount: it verifies the gateway's
own access token, resolves it to a :class:`~pgwarden.identity.Principal`, and
puts the principal (plus a per-request :class:`~pgwarden.timing.Timing`) into the
request scope's ``state``, where the MCP tools read it. An unauthenticated
request gets a 401 whose ``WWW-Authenticate`` header points at the resource
metadata; a valid token for an unmapped identity gets a 403.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import json
import secrets
from collections.abc import AsyncIterator, Callable
from typing import Any

from fastapi import FastAPI
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from pgwarden.config import Config
from pgwarden.identity import Principal, resolve_principal
from pgwarden.mcp_server import GatewayDeps, build_mcp_server
from pgwarden.oauth.jwt import TokenError, verify_access_token
from pgwarden.oauth.keys import SigningKey
from pgwarden.timing import Timing, render_server_timing

MCP_PATH = "/mcp"


@dataclasses.dataclass
class Authenticator:
    """Verifies the gateway's own access tokens and resolves principals."""

    config: Config
    signing_key: SigningKey
    issuer: str
    audience: str
    now: Callable[[], dt.datetime]

    def resource_metadata_url(self) -> str:
        return f"{self.config.public_url}/.well-known/oauth-protected-resource"

    def authenticate(self, token: str) -> tuple[Principal | None, str]:
        """Verify a token; return ``(principal, client_id)``, principal ``None`` if unmapped.

        Raises :class:`~pgwarden.oauth.jwt.TokenError` if the token itself is
        invalid (bad signature/typ/alg/aud/iss/exp).
        """
        claims = verify_access_token(
            token,
            {self.signing_key.kid: self.signing_key.public_key},
            issuer=self.issuer,
            audience=self.audience,
            now=self.now(),
        )
        return resolve_principal(self.config, claims.subject), claims.client_id


class _PrincipalMiddleware:
    """ASGI middleware guarding ``/mcp``: token -> principal into scope state."""

    def __init__(self, app: ASGIApp, authenticator: Authenticator, *, server_timing: bool) -> None:
        self.app = app
        self.auth = authenticator
        self.server_timing = server_timing

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != MCP_PATH:
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}

        origin = headers.get("origin")
        allowed = self.auth.config.allowed_origins
        if origin is not None and allowed and origin not in allowed:
            await _json(
                send, 403, {"error": "forbidden", "error_description": "origin not allowed"}
            )
            return

        auth_header = headers.get("authorization", "")
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            await self._unauthorized(send, "missing bearer token")
            return

        timing = Timing()
        try:
            with timing.span("auth"):
                resolved = self.auth.authenticate(token.strip())
        except TokenError as exc:
            await self._unauthorized(send, str(exc), error="invalid_token")
            return
        principal, client_id = resolved
        if principal is None:
            await _json(
                send,
                403,
                {
                    "error": "forbidden",
                    "error_description": "your identity is not mapped; ask an administrator",
                },
            )
            return

        state = scope.setdefault("state", {})
        state["principal"] = principal
        state["timing"] = timing
        state["request_id"] = secrets.token_hex(8)
        state["client_id"] = client_id

        send_wrapper = _make_send_wrapper(send, timing) if self.server_timing else send
        await self.app(scope, receive, send_wrapper)

    async def _unauthorized(
        self, send: Send, detail: str, *, error: str = "invalid_request"
    ) -> None:
        challenge = f'Bearer resource_metadata="{self.auth.resource_metadata_url()}"'
        if error != "invalid_request":
            challenge = f'{challenge}, error="{error}"'
        await _json(
            send,
            401,
            {"error": error, "error_description": detail},
            extra_headers=[(b"www-authenticate", challenge.encode("latin-1"))],
        )


def _make_send_wrapper(send: Send, timing: Timing) -> Send:
    async def wrapped(message: Message) -> None:
        if message["type"] == "http.response.start" and timing.spans:
            header_value = render_server_timing(timing)
            if header_value:
                headers = list(message.get("headers", []))
                headers.append((b"server-timing", header_value.encode("latin-1")))
                message = {**message, "headers": headers}
        await send(message)

    return wrapped


async def _json(
    send: Send,
    status: int,
    body: dict[str, Any],
    *,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    payload = json.dumps(body).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode()),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


def _transport_security(config: Config) -> TransportSecuritySettings:
    """Allow the configured public host plus loopback; reject anything else (DNS rebinding)."""
    from urllib.parse import urlsplit

    parsed = urlsplit(config.public_url)
    host = parsed.hostname or "localhost"
    port = parsed.port
    host_with_port = f"{host}:{port}" if port else host
    allowed_hosts = [
        host_with_port,
        host,
        "127.0.0.1:*",
        "localhost:*",
        "[::1]:*",
    ]
    allowed_origins = [
        config.public_url,
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
        *config.allowed_origins,
    ]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def _probe_role(config: Config) -> str | None:
    if config.machines:
        from pgwarden.config import machine_role_name

        return machine_role_name(config.machines[0].role)
    if config.people:
        from pgwarden.config import person_role_name

        return person_role_name(config.people[0].role)
    return None


def create_app(
    deps: GatewayDeps,
    authenticator: Authenticator,
    *,
    server_timing: bool = False,
) -> FastAPI:
    """Build the FastAPI app: the MCP mount, auth middleware, and health probes."""
    mcp = build_mcp_server(deps)
    mcp_asgi = mcp.streamable_http_app(
        streamable_http_path=MCP_PATH,
        json_response=True,
        stateless_http=True,
        transport_security=_transport_security(deps.config),
    )

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        import asyncpg

        deps.state_pool = await asyncpg.create_pool(deps.state_dsn, min_size=1, max_size=8)
        await deps.pool_manager.start()
        try:
            async with mcp_asgi.router.lifespan_context(_app):
                yield
        finally:
            await deps.pool_manager.aclose()
            if deps.state_pool is not None:
                await deps.state_pool.close()
                deps.state_pool = None

    app = FastAPI(lifespan=lifespan, title="pgwarden")
    probe_role = _probe_role(deps.config)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:  # pragma: no cover - trivial
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> Any:
        checks: dict[str, str] = {}
        ok = True
        try:
            async with deps.require_state_pool().acquire() as conn:
                await conn.fetchval("SELECT 1")
            checks["state_db"] = "ok"
        except Exception as exc:  # noqa: BLE001 - report, do not crash the probe
            ok = False
            checks["state_db"] = f"error: {exc}"
        if probe_role is not None:
            try:
                async with deps.pool_manager.acquire(probe_role) as conn:
                    await conn.fetchval("SELECT 1")
                checks["target_db"] = "ok"
            except Exception as exc:  # noqa: BLE001
                ok = False
                checks["target_db"] = f"error: {exc}"
        else:
            checks["target_db"] = "skipped: no roles configured"
        status = 200 if ok else 503
        return JSONResponse({"status": "ok" if ok else "not ready", "checks": checks}, status)

    app.mount("/", mcp_asgi)
    app.add_middleware(
        _PrincipalMiddleware, authenticator=authenticator, server_timing=server_timing
    )
    return app


__all__ = ["Authenticator", "MCP_PATH", "create_app"]
