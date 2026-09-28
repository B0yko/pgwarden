"""A real gateway for integration tests: the FastAPI app (MCP + OAuth routers) in
a uvicorn thread, plus a tests-only access-token minter.

The app runs on its own thread and event loop because the MCP session manager
uses anyio cancel scopes that must be entered and exited in the same task, which
a pytest-asyncio fixture spanning setup and teardown cannot guarantee. Tokens
minted here exist only in tests; production code has no minting flag.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import socket
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import uvicorn
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from pgwarden.app import Authenticator, create_app
from pgwarden.approvals.service import ApprovalService
from pgwarden.config import Config
from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig
from pgwarden.mcp_server import GatewayDeps
from pgwarden.oauth.jwt import mint_access_token
from pgwarden.oauth.keys import SigningKey, generate_signing_key_pem, load_signing_key
from pgwarden.oauth.server import OAuthService, build_oauth_router

NOW = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.UTC)
TEST_SESSION_SECRET = "gateway-harness-session-secret"  # noqa: S105 (tests only)


@dataclasses.dataclass
class Clock:
    """A settable clock shared by the app and the test."""

    now: dt.datetime = NOW

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now = self.now + dt.timedelta(**kwargs)


class BearerAuth(httpx2.Auth):
    def __init__(self, token: str) -> None:
        self.token = token

    def auth_flow(self, request: Any) -> Any:
        request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


@dataclasses.dataclass
class Harness:
    base_url: str
    config: Config
    signing: SigningKey
    audience: str
    clock: Clock
    deps: GatewayDeps

    def token(self, subject: str, *, client_id: str = "test-client") -> str:
        return mint_access_token(
            self.signing.private_key,
            self.signing.kid,
            issuer=self.config.public_url,
            audience=self.audience,
            subject=subject,
            client_id=client_id,
            now=self.clock.now,
        )

    def client(self, token: str | None) -> Client:
        auth = BearerAuth(token) if token else None
        http_client = httpx2.AsyncClient(auth=auth)
        return Client(
            streamable_http_client(f"{self.base_url}/mcp", http_client=http_client), mode="auto"
        )

    def raw(self, token: str | None = None) -> httpx2.AsyncClient:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx2.AsyncClient(base_url=self.base_url, headers=headers)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def run_gateway(
    config: Config,
    target_dsn: str,
    state_dsn: str,
    role_secret: str,
    *,
    clock: Clock | None = None,
) -> AsyncIterator[Harness]:
    clock = clock or Clock()
    signing = load_signing_key(generate_signing_key_pem())
    deps = GatewayDeps(
        config=config,
        pool_manager=PoolManager(target_dsn=target_dsn, role_secret=role_secret),
        state_dsn=state_dsn,
        read_config=ReadConfig(**config.read.model_dump()),
        now=clock,
    )
    audience = f"{config.public_url}/mcp"
    authenticator = Authenticator(
        config=config, signing_key=signing, issuer=config.public_url, audience=audience, now=clock
    )
    oauth = OAuthService(gateway=deps, signing_key=signing)
    deps.approvals = ApprovalService(gateway=deps, session_secret=TEST_SESSION_SECRET)
    app = create_app(deps, authenticator, server_timing=True, routers=[build_oauth_router(oauth)])

    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    async with httpx2.AsyncClient() as probe:
        while time.time() < deadline:
            with contextlib.suppress(Exception):
                if (await probe.get(f"{base_url}/healthz")).status_code == 200:
                    break
            time.sleep(0.05)
        else:  # pragma: no cover - only on a startup failure
            raise RuntimeError("gateway did not become ready")
    try:
        yield Harness(
            base_url=base_url,
            config=config,
            signing=signing,
            audience=audience,
            clock=clock,
            deps=deps,
        )
    finally:
        server.should_exit = True
        thread.join(timeout=10)
