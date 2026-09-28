"""Browserless end-to-end test of the whole OAuth flow.

The in-repo mock IdP and the gateway each run in a uvicorn thread; an httpx
client plays the browser and the MCP client: register (DCR), /oauth/authorize
with PKCE + resource + state, the pre-login consent POST, the IdP's user picker,
the callback, the confirmation POST, the code exchange, and an MCP call.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import importlib.util
import re
import secrets
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import asyncpg
import httpx
import pytest
import pytest_asyncio
import uvicorn

from helpers.gateway import BearerAuth, free_port
from pgwarden.app import Authenticator, create_app
from pgwarden.approvals.service import ApprovalService
from pgwarden.config import Config, IdentityRef, PersonConfig, UpstreamConfig
from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig
from pgwarden.mcp_server import GatewayDeps
from pgwarden.oauth import pkce
from pgwarden.oauth.authorize import WebAuth, build_authorize_router
from pgwarden.oauth.keys import generate_signing_key_pem, load_signing_key
from pgwarden.oauth.server import OAuthService, build_oauth_router
from pgwarden.oauth.upstream import UpstreamProvider

pytestmark = pytest.mark.pg

REPO_ROOT = Path(__file__).parent.parent.parent
IDP_CLIENT_ID = "pgwarden-e2e"
IDP_CLIENT_SECRET = "e2e-idp-client-secret"  # noqa: S105 (tests only)
CLIENT_REDIRECT = "http://127.0.0.1:9/callback"  # never listened on; we read Location


def _utcnow() -> dt.datetime:
    return dt.datetime.now(tz=dt.UTC)


def _serve(app: Any, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while time.time() < deadline:
        with contextlib.suppress(Exception):
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1).status_code == 200:
                return server, thread
        time.sleep(0.05)
    raise RuntimeError(f"server on {port} did not start")


@pytest.fixture
def mock_idp(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, int]]:
    idp_port, gw_port = free_port(), free_port()
    base = f"http://127.0.0.1:{idp_port}"
    monkeypatch.setenv("MOCK_IDP_DEV_ONLY", "1")
    monkeypatch.setenv("MOCK_IDP_ISSUER", base)
    monkeypatch.setenv("MOCK_IDP_INTERNAL_URL", base)
    monkeypatch.setenv("MOCK_IDP_CLIENT_ID", IDP_CLIENT_ID)
    monkeypatch.setenv("MOCK_IDP_CLIENT_SECRET", IDP_CLIENT_SECRET)
    monkeypatch.setenv("MOCK_IDP_REDIRECT_URIS", f"http://127.0.0.1:{gw_port}/oauth/callback")
    spec = importlib.util.spec_from_file_location(
        f"mock_idp_{idp_port}", REPO_ROOT / "devtools" / "mock_idp" / "app.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    try:
        spec.loader.exec_module(module)
        server, thread = _serve(module.app, idp_port)
        try:
            yield base, gw_port
        finally:
            server.should_exit = True
            thread.join(timeout=10)
    finally:
        sys.modules.pop(spec.name, None)


@dataclasses.dataclass
class Gateway:
    base: str
    idp: str
    config: Config


@pytest_asyncio.fixture
async def gateway(
    mock_idp: tuple[str, int],
    pg_demo_masking: None,
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_role_secret: str,
    pg_demo_config: object,
) -> AsyncIterator[Gateway]:
    assert isinstance(pg_demo_config, Config)
    idp_base, gw_port = mock_idp
    public_url = f"http://127.0.0.1:{gw_port}"
    eve = PersonConfig(identity=IdentityRef(email="eve@example.net"), role="eve", bundles=[])
    config = pg_demo_config.model_copy(
        update={
            "public_url": public_url,
            "upstream": UpstreamConfig(name="mock-idp", issuer=idp_base, client_id=IDP_CLIENT_ID),
            "people": [*pg_demo_config.people, eve],
        }
    )
    signing = load_signing_key(generate_signing_key_pem())
    deps = GatewayDeps(
        config=config,
        pool_manager=PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret),
        state_dsn=pg_state_dsn,
        read_config=ReadConfig(),
        now=_utcnow,
    )
    deps.approvals = ApprovalService(gateway=deps, session_secret="e2e-session-secret")
    oauth = OAuthService(gateway=deps, signing_key=signing)
    upstream = UpstreamProvider(
        config.upstream,
        client_secret=IDP_CLIENT_SECRET,
        redirect_uri=f"{public_url}/oauth/callback",
    )
    web = WebAuth(gateway=deps, oauth=oauth, upstream=upstream, session_secret="e2e-session-secret")
    auth = Authenticator(
        config=config,
        signing_key=signing,
        issuer=public_url,
        audience=f"{public_url}/mcp",
        now=_utcnow,
    )
    app = create_app(deps, auth, routers=[build_oauth_router(oauth), build_authorize_router(web)])
    server, thread = _serve(app, gw_port)
    try:
        yield Gateway(base=public_url, idp=idp_base, config=config)
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _hidden(html: str, name: str) -> str:
    match = re.search(rf'name="{name}" value="([^"]+)"', html)
    assert match, f"no hidden field {name!r} in page"
    return match.group(1)


@dataclasses.dataclass
class Flow:
    verifier: str
    state: str
    client_id: str


async def _register(http: httpx.AsyncClient, gw: Gateway) -> str:
    resp = await http.post(
        f"{gw.base}/oauth/register",
        json={
            "client_name": "E2E Client",
            "redirect_uris": [CLIENT_REDIRECT],
            "token_endpoint_auth_method": "none",
        },
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["client_id"])


def _authorize_url(gw: Gateway, client_id: str, **overrides: str) -> tuple[str, Flow]:
    verifier = secrets.token_urlsafe(48)[:64]
    state = secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": CLIENT_REDIRECT,
        "code_challenge": pkce.s256_challenge(verifier),
        "code_challenge_method": "S256",
        "state": state,
        "resource": f"{gw.base}/mcp",
    }
    params.update(overrides)
    return f"{gw.base}/oauth/authorize?{urlencode(params)}", Flow(verifier, state, client_id)


async def _login_at_idp(http: httpx.AsyncClient, idp_url: str, sub: str) -> str:
    picker = await http.get(idp_url)
    assert picker.status_code == 200, picker.text
    request_id = _hidden(picker.text, "request_id")
    origin = "{0.scheme}://{0.netloc}".format(urlsplit(idp_url))
    resp = await http.post(f"{origin}/authorize/login", data={"request_id": request_id, "sub": sub})
    assert resp.status_code == 302, resp.text
    return str(resp.headers["location"])


async def _run_to_confirmation(
    http: httpx.AsyncClient, gw: Gateway, sub: str
) -> tuple[httpx.Response, Flow, str]:
    client_id = await _register(http, gw)
    url, flow = _authorize_url(gw, client_id)
    consent = await http.get(url)
    assert consent.status_code == 200, consent.text
    assert "E2E Client" in consent.text and "127.0.0.1:9" in consent.text
    to_idp = await http.post(
        f"{gw.base}/oauth/authorize/consent",
        data={
            "pending_id": _hidden(consent.text, "pending_id"),
            "csrf": _hidden(consent.text, "csrf"),
            "decision": "approve",
        },
    )
    assert to_idp.status_code == 303, to_idp.text
    assert to_idp.headers["location"].startswith(f"{gw.idp}/authorize?")
    callback_url = await _login_at_idp(http, to_idp.headers["location"], sub)
    confirmation = await http.get(callback_url)
    return confirmation, flow, callback_url


async def _confirm(http: httpx.AsyncClient, gw: Gateway, page: httpx.Response) -> dict[str, str]:
    resp = await http.post(
        f"{gw.base}/oauth/authorize/confirm",
        data={
            "pending_id": _hidden(page.text, "pending_id"),
            "csrf": _hidden(page.text, "csrf"),
            "decision": "confirm",
        },
    )
    assert resp.status_code == 303, resp.text
    location = resp.headers["location"]
    assert location.startswith(CLIENT_REDIRECT)
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


async def _mcp_whoami(gw: Gateway, token: str) -> dict[str, Any]:
    import httpx2
    from mcp.client import Client
    from mcp.client.streamable_http import streamable_http_client

    http_client = httpx2.AsyncClient(auth=BearerAuth(token))
    async with Client(
        streamable_http_client(f"{gw.base}/mcp", http_client=http_client), mode="auto"
    ) as client:
        result = await client.call_tool("whoami", {})
    return dict(result.structured_content or {})


async def test_full_flow_as_bob(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        page, flow, _ = await _run_to_confirmation(http, gateway, "usr_bob")
        assert page.status_code == 200, page.text
        assert "pw_u_bob" in page.text and "bob@example.com" in page.text
        csp = page.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in csp and "script-src" not in csp
        cookie = page.headers.get("set-cookie", "") or ""
        assert "__Host-" not in cookie  # loopback http: no prefix possible

        params = await _confirm(http, gateway, page)
        assert params["state"] == flow.state
        assert params["iss"] == gateway.base

        token = await http.post(
            f"{gateway.base}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": params["code"],
                "redirect_uri": CLIENT_REDIRECT,
                "code_verifier": flow.verifier,
                "client_id": flow.client_id,
                "resource": f"{gateway.base}/mcp",
            },
        )
        assert token.status_code == 200, token.text
        tokens = token.json()

        refreshed = await http.post(
            f"{gateway.base}/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": flow.client_id,
            },
        )
        assert refreshed.status_code == 200, refreshed.text

    who = await _mcp_whoami(gateway, tokens["access_token"])
    assert who["pg_role"] == "pw_u_bob"


async def test_consent_and_binding_cookies_are_httponly_lax(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        client_id = await _register(http, gateway)
        url, _ = _authorize_url(gateway, client_id)
        consent = await http.get(url)
    cookie = consent.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie


async def test_unmapped_identity_gets_403(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        page, _, _ = await _run_to_confirmation(http, gateway, "usr_mallory")
    assert page.status_code == 403
    assert "administrator" in page.text


async def test_unverified_email_does_not_match(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        page, _, _ = await _run_to_confirmation(http, gateway, "usr_eve")
    assert page.status_code == 403


async def test_upstream_state_is_single_use(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        page, _, callback_url = await _run_to_confirmation(http, gateway, "usr_bob")
        assert page.status_code == 200
        replay = await http.get(callback_url)
    assert replay.status_code == 400 and "already used" in replay.text


async def test_authorize_request_validation(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        client_id = await _register(http, gateway)

        other_port, _ = _authorize_url(
            gateway, client_id, redirect_uri="http://127.0.0.1:5555/callback"
        )
        assert (await http.get(other_port)).status_code == 200  # loopback port ignored

        wrong_path, _ = _authorize_url(gateway, client_id, redirect_uri="http://127.0.0.1:9/other")
        bad = await http.get(wrong_path)
        assert bad.status_code == 400  # never redirected to an unregistered URI

        plain, _ = _authorize_url(gateway, client_id, code_challenge_method="plain")
        resp = await http.get(plain)
        assert resp.status_code == 303 and "error=invalid_request" in resp.headers["location"]

        wrong_resource, _ = _authorize_url(
            gateway, client_id, resource="https://evil.example.com/mcp"
        )
        resp = await http.get(wrong_resource)
        assert resp.status_code == 303 and "error=invalid_target" in resp.headers["location"]

        unknown, _ = _authorize_url(gateway, "no-such-client")
        assert (await http.get(unknown)).status_code == 400


async def test_consent_csrf_and_browser_binding(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        client_id = await _register(http, gateway)
        url, _ = _authorize_url(gateway, client_id)
        consent = await http.get(url)
        pending_id = _hidden(consent.text, "pending_id")
        tampered = await http.post(
            f"{gateway.base}/oauth/authorize/consent",
            data={"pending_id": pending_id, "csrf": "0" * 64, "decision": "approve"},
        )
        assert tampered.status_code == 400
    # a different browser (no binding cookie) cannot drive the same request
    async with httpx.AsyncClient(follow_redirects=False) as other_browser:
        stolen = await other_browser.post(
            f"{gateway.base}/oauth/authorize/consent",
            data={
                "pending_id": pending_id,
                "csrf": _hidden(consent.text, "csrf"),
                "decision": "approve",
            },
        )
    assert stolen.status_code == 400


async def test_deny_redirects_with_access_denied(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        client_id = await _register(http, gateway)
        url, flow = _authorize_url(gateway, client_id)
        consent = await http.get(url)
        resp = await http.post(
            f"{gateway.base}/oauth/authorize/consent",
            data={
                "pending_id": _hidden(consent.text, "pending_id"),
                "csrf": _hidden(consent.text, "csrf"),
                "decision": "deny",
            },
        )
    assert resp.status_code == 303
    params = parse_qs(urlsplit(resp.headers["location"]).query)
    assert params["error"] == ["access_denied"] and params["state"] == [flow.state]


async def test_suspended_person_is_refused_at_mcp(gateway: Gateway, pg_state_dsn: str) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        page, flow, _ = await _run_to_confirmation(http, gateway, "usr_dana")
        params = await _confirm(http, gateway, page)
        tokens = (
            await http.post(
                f"{gateway.base}/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": params["code"],
                    "redirect_uri": CLIENT_REDIRECT,
                    "code_verifier": flow.verifier,
                    "client_id": flow.client_id,
                    "resource": f"{gateway.base}/mcp",
                },
            )
        ).json()
        conn = await asyncpg.connect(pg_state_dsn, timeout=5)
        try:
            await conn.execute(
                "INSERT INTO pgwarden.people_status (person_role, suspended) VALUES ('pw_u_dana', "
                "true) ON CONFLICT (person_role) DO UPDATE SET suspended = true"
            )
            mcp = await http.post(
                f"{gateway.base}/mcp",
                headers={
                    "Authorization": f"Bearer {tokens['access_token']}",
                    "Accept": "application/json, text/event-stream",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
            assert mcp.status_code == 401
            refresh = await http.post(
                f"{gateway.base}/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": flow.client_id,
                },
            )
            assert refresh.status_code == 400
        finally:
            await conn.execute(
                "UPDATE pgwarden.people_status SET suspended = false "
                "WHERE person_role = 'pw_u_dana'"
            )
            await conn.close()


async def test_login_creates_a_web_session(gateway: Gateway) -> None:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        start = await http.get(f"{gateway.base}/login?next=/admin/audit")
        assert start.status_code == 303
        callback_url = await _login_at_idp(http, start.headers["location"], "usr_carol")
        done = await http.get(callback_url)
        assert done.status_code == 303 and done.headers["location"] == "/admin/audit"
        session_cookie = done.headers["set-cookie"]
        assert "pgw_session=" in session_cookie
        lowered = session_cookie.lower()
        assert "httponly" in lowered and "samesite=lax" in lowered and "path=/" in lowered
        assert "secure" not in lowered  # loopback http cannot set Secure
        # an open-redirect attempt collapses to "/"
        evil = await http.get(f"{gateway.base}/login?next=//evil.example.com/x")
        assert evil.status_code == 303 and evil.headers["location"] == "/"
