"""Integration tests for the authorization-server core: registration,
the token endpoint (authorization_code + PKCE, refresh families, client
credentials), revocation, and what /mcp accepts.

Service-level tests drive :class:`OAuthService` directly with an injectable
clock; HTTP tests use the real gateway in a uvicorn thread. Authorization codes
are inserted with ``store.insert_auth_code`` because the browser flow that
normally issues them is tested separately.
"""

from __future__ import annotations

import base64
import datetime as dt
import secrets
from collections.abc import AsyncIterator
from typing import Any

import asyncpg
import jwt as pyjwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa

from helpers.gateway import Clock, Harness, run_gateway
from pgwarden.config import Config
from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig
from pgwarden.identity import person_subject
from pgwarden.mcp_server import GatewayDeps
from pgwarden.oauth import pkce, store
from pgwarden.oauth.jwt import verify_access_token
from pgwarden.oauth.keys import generate_signing_key_pem, load_signing_key
from pgwarden.oauth.server import ClientAuth, OAuthError, OAuthService

pytestmark = pytest.mark.pg

VERIFIER = secrets.token_urlsafe(48)[:64]
CHALLENGE = pkce.s256_challenge(VERIFIER)
REDIRECT = "http://127.0.0.1:7777/callback"


def _service(config: Config, state_dsn: str, clock: Clock) -> OAuthService:
    deps = GatewayDeps(
        config=config,
        pool_manager=PoolManager(target_dsn="postgresql://127.0.0.1/unused", role_secret="x"),
        state_dsn=state_dsn,
        read_config=ReadConfig(),
        now=clock,
    )
    return OAuthService(gateway=deps, signing_key=load_signing_key(generate_signing_key_pem()))


@pytest_asyncio.fixture
async def conn(pg_state_dsn: str) -> AsyncIterator[asyncpg.Connection]:
    c = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        yield c
    finally:
        await c.close()


async def _public_client(svc: OAuthService, conn: asyncpg.Connection) -> str:
    reg = await svc.register(
        conn,
        {"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "client_name": "T"},
        client_ip=f"test-{secrets.token_hex(4)}",
    )
    return str(reg["client_id"])


async def _code(
    svc: OAuthService,
    conn: asyncpg.Connection,
    client_id: str,
    *,
    subject: str = "person:bob",
    login_at: dt.datetime | None = None,
) -> str:
    code = secrets.token_urlsafe(24)
    now = svc.now()
    await store.insert_auth_code(
        conn,
        code=code,
        client_id=client_id,
        redirect_uri=REDIRECT,
        code_challenge=CHALLENGE,
        resource=svc.resource,
        principal_subject=subject,
        identity_email="bob@example.com",
        upstream_login_at=login_at or now,
        expires_at=now + dt.timedelta(seconds=60),
    )
    return code


def _redeem_form(svc: OAuthService, code: str, **overrides: str) -> dict[str, str]:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": VERIFIER,
        "resource": svc.resource,
    }
    form.update(overrides)
    return form


# -- registration ------------------------------------------------------------------


async def test_register_public_and_confidential(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    svc = _service(pg_demo_config, pg_state_dsn, Clock())
    public = await svc.register(
        conn,
        {"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"},
        client_ip="test-reg-1",
    )
    assert "client_secret" not in public
    confidential = await svc.register(
        conn, {"redirect_uris": ["https://app.example.com/cb"]}, client_ip="test-reg-1"
    )
    assert confidential["token_endpoint_auth_method"] == "client_secret_basic"
    assert confidential["client_secret"]
    stored = await store.get_client(conn, confidential["client_id"])
    assert stored is not None and stored.client_secret_hash != confidential["client_secret"]


@pytest.mark.parametrize(
    "uri", ["javascript:alert(1)", "data:text/html,x", "file:///x", "http://evil.example.com/cb"]
)
async def test_register_rejects_bad_redirects(
    uri: str, pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    svc = _service(pg_demo_config, pg_state_dsn, Clock())
    with pytest.raises(OAuthError) as exc:
        await svc.register(conn, {"redirect_uris": [uri]}, client_ip="test-reg-bad")
    assert exc.value.error == "invalid_redirect_uri"


async def test_register_rate_limit(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    limited = pg_demo_config.model_copy(
        update={"limits": pg_demo_config.limits.model_copy(update={"registrations_per_hour": 2})}
    )
    svc = _service(limited, pg_state_dsn, Clock())
    ip = f"test-flood-{secrets.token_hex(4)}"
    body = {"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"}
    await svc.register(conn, body, client_ip=ip)
    await svc.register(conn, body, client_ip=ip)
    with pytest.raises(OAuthError) as exc:
        await svc.register(conn, body, client_ip=ip)
    assert exc.value.status == 429 and "Retry-After" in exc.value.headers


# -- authorization_code -------------------------------------------------------------


async def test_authorization_code_happy_path(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    clock = Clock()
    svc = _service(pg_demo_config, pg_state_dsn, clock)
    client_id = await _public_client(svc, conn)
    code = await _code(svc, conn, client_id)
    tokens = await svc.token(conn, _redeem_form(svc, code), ClientAuth(client_id, None, "none"))
    assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 600
    claims = verify_access_token(
        tokens["access_token"],
        {svc.signing_key.kid: svc.signing_key.public_key},
        issuer=svc.issuer,
        audience=svc.resource,
        now=clock.now,
    )
    assert claims.subject == "person:bob" and claims.client_id == client_id
    header = pyjwt.get_unverified_header(tokens["access_token"])
    assert header["typ"] == "at+jwt" and header["alg"] == "EdDSA"
    assert tokens["refresh_token"]


async def test_authorization_code_is_single_use(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    svc = _service(pg_demo_config, pg_state_dsn, Clock())
    client_id = await _public_client(svc, conn)
    code = await _code(svc, conn, client_id)
    auth = ClientAuth(client_id, None, "none")
    await svc.token(conn, _redeem_form(svc, code), auth)
    with pytest.raises(OAuthError) as exc:
        await svc.token(conn, _redeem_form(svc, code), auth)
    assert exc.value.error == "invalid_grant"


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"code_verifier": "x" * 50}, "invalid_grant"),
        ({"redirect_uri": "http://127.0.0.1:7777/other"}, "invalid_grant"),
        ({"resource": "https://other.example.com/mcp"}, "invalid_target"),
        ({"resource": ""}, "invalid_target"),
    ],
)
async def test_authorization_code_rejections(
    overrides: dict[str, str],
    error: str,
    pg_demo_config: object,
    pg_state_dsn: str,
    conn: asyncpg.Connection,
) -> None:
    assert isinstance(pg_demo_config, Config)
    svc = _service(pg_demo_config, pg_state_dsn, Clock())
    client_id = await _public_client(svc, conn)
    code = await _code(svc, conn, client_id)
    form = _redeem_form(svc, code, **overrides)
    if overrides.get("resource") == "":
        form.pop("resource")
    with pytest.raises(OAuthError) as exc:
        await svc.token(conn, form, ClientAuth(client_id, None, "none"))
    assert exc.value.error == error


async def test_code_for_another_client_or_unmapped_subject_is_rejected(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    svc = _service(pg_demo_config, pg_state_dsn, Clock())
    owner = await _public_client(svc, conn)
    other = await _public_client(svc, conn)
    code = await _code(svc, conn, owner)
    with pytest.raises(OAuthError) as exc:
        await svc.token(conn, _redeem_form(svc, code), ClientAuth(other, None, "none"))
    assert exc.value.error == "invalid_grant"

    unmapped = await _code(svc, conn, owner, subject=person_subject("nobody"))
    with pytest.raises(OAuthError) as exc:
        await svc.token(conn, _redeem_form(svc, unmapped), ClientAuth(owner, None, "none"))
    assert exc.value.error == "invalid_grant"


# -- refresh tokens -----------------------------------------------------------------


async def test_refresh_rotates_and_reuse_revokes_the_family(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    svc = _service(pg_demo_config, pg_state_dsn, Clock())
    client_id = await _public_client(svc, conn)
    auth = ClientAuth(client_id, None, "none")
    first = await svc.token(conn, _redeem_form(svc, await _code(svc, conn, client_id)), auth)
    second = await svc.token(
        conn, {"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}, auth
    )
    assert second["refresh_token"] != first["refresh_token"]

    # replaying the already-used token revokes the whole family ...
    with pytest.raises(OAuthError) as exc:
        await svc.token(
            conn, {"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}, auth
        )
    assert exc.value.error == "invalid_grant"
    # ... so even the newest token no longer works
    with pytest.raises(OAuthError):
        await svc.token(
            conn, {"grant_type": "refresh_token", "refresh_token": second["refresh_token"]}, auth
        )


async def test_refresh_chain_cannot_pass_eight_hours(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    clock = Clock()
    svc = _service(pg_demo_config, pg_state_dsn, clock)
    client_id = await _public_client(svc, conn)
    auth = ClientAuth(client_id, None, "none")
    login_at = clock.now
    tokens = await svc.token(conn, _redeem_form(svc, await _code(svc, conn, client_id)), auth)
    family = await store.family_for_refresh_token(conn, tokens["refresh_token"])
    assert family is not None
    assert family.absolute_expires_at == login_at + dt.timedelta(hours=8)

    for _ in range(7):  # refreshes at +1h ... +7h succeed
        clock.advance(hours=1)
        tokens = await svc.token(
            conn, {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, auth
        )
    after = await store.family_for_refresh_token(conn, tokens["refresh_token"])
    assert after is not None and after.absolute_expires_at == family.absolute_expires_at

    clock.advance(hours=1)  # +8h: the absolute lifetime is reached
    with pytest.raises(OAuthError) as exc:
        await svc.token(
            conn, {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, auth
        )
    assert exc.value.error == "invalid_grant"


async def test_suspended_person_cannot_refresh(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    svc = _service(pg_demo_config, pg_state_dsn, Clock())
    client_id = await _public_client(svc, conn)
    auth = ClientAuth(client_id, None, "none")
    code = await _code(svc, conn, client_id, subject="person:dana")
    tokens = await svc.token(conn, _redeem_form(svc, code), auth)
    await conn.execute(
        "INSERT INTO pgwarden.people_status (person_role, suspended) VALUES ('pw_u_dana', true) "
        "ON CONFLICT (person_role) DO UPDATE SET suspended = true"
    )
    try:
        with pytest.raises(OAuthError) as exc:
            await svc.token(
                conn,
                {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
                auth,
            )
        assert "suspended" in exc.value.description
    finally:
        await conn.execute(
            "UPDATE pgwarden.people_status SET suspended = false WHERE person_role = 'pw_u_dana'"
        )


# -- client_credentials ----------------------------------------------------------------


async def test_client_credentials_for_a_machine(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    clock = Clock()
    svc = _service(pg_demo_config, pg_state_dsn, clock)
    secret = secrets.token_urlsafe(32)
    await store.set_machine_secret(conn, "nightly-report", secret, clock.now)
    form = {"grant_type": "client_credentials", "resource": svc.resource}
    tokens = await svc.token(conn, form, ClientAuth("nightly-report", secret, "basic"))
    assert "refresh_token" not in tokens
    claims = verify_access_token(
        tokens["access_token"],
        {svc.signing_key.kid: svc.signing_key.public_key},
        issuer=svc.issuer,
        audience=svc.resource,
        now=clock.now,
    )
    assert claims.subject == "machine:nightly-report"

    for bad in (ClientAuth("nightly-report", "wrong", "basic"), ClientAuth("nope", secret, "post")):
        with pytest.raises(OAuthError) as exc:
            await svc.token(conn, form, bad)
        assert exc.value.error == "invalid_client"
    with pytest.raises(OAuthError) as exc:
        await svc.token(
            conn,
            {"grant_type": "client_credentials"},
            ClientAuth("nightly-report", secret, "basic"),
        )
    assert exc.value.error == "invalid_target"


# -- revocation -------------------------------------------------------------------------


async def test_revoke_refresh_and_access_tokens(
    pg_demo_config: object, pg_state_dsn: str, conn: asyncpg.Connection
) -> None:
    assert isinstance(pg_demo_config, Config)
    clock = Clock()
    svc = _service(pg_demo_config, pg_state_dsn, clock)
    client_id = await _public_client(svc, conn)
    auth = ClientAuth(client_id, None, "none")
    tokens = await svc.token(conn, _redeem_form(svc, await _code(svc, conn, client_id)), auth)

    await svc.revoke(conn, {"token": tokens["refresh_token"]}, auth)
    with pytest.raises(OAuthError):
        await svc.token(
            conn, {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, auth
        )

    await svc.revoke(conn, {"token": tokens["access_token"]}, auth)
    claims = verify_access_token(
        tokens["access_token"],
        {svc.signing_key.kid: svc.signing_key.public_key},
        issuer=svc.issuer,
        audience=svc.resource,
        now=clock.now,
    )
    reason = await store.access_denial_reason(conn, jti=claims.jti, role_name="pw_u_bob")
    assert reason == "token has been revoked"

    # an unknown token is not an error (RFC 7009)
    await svc.revoke(conn, {"token": "not-a-token"}, auth)


# -- HTTP: metadata, registration, and what /mcp accepts --------------------------------


@pytest_asyncio.fixture
async def harness(
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_demo_masking: None,
    pg_role_secret: str,
    pg_demo_config: object,
) -> AsyncIterator[Harness]:
    assert isinstance(pg_demo_config, Config)
    async for h in run_gateway(pg_demo_config, pg_target_dsn, pg_state_dsn, pg_role_secret):
        yield h


_JSONRPC = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
_ACCEPT = {"Accept": "application/json, text/event-stream"}


async def test_http_metadata(harness: Harness) -> None:
    async with harness.raw() as http:
        prm = (await http.get("/.well-known/oauth-protected-resource/mcp")).json()
        root = (await http.get("/.well-known/oauth-protected-resource")).json()
        asm = (await http.get("/.well-known/oauth-authorization-server")).json()
    assert prm["resource"] == harness.audience == root["resource"]
    assert prm["authorization_servers"] == [harness.config.public_url]
    assert asm["issuer"] == harness.config.public_url
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["client_id_metadata_document_supported"] is True


async def test_http_401_points_at_path_suffixed_metadata(harness: Harness) -> None:
    async with harness.raw() as http:
        resp = await http.post("/mcp", headers=_ACCEPT, json=_JSONRPC)
    assert resp.status_code == 401
    assert "/.well-known/oauth-protected-resource/mcp" in resp.headers["www-authenticate"]


async def test_http_register_returns_201(harness: Harness) -> None:
    async with harness.raw() as http:
        resp = await http.post(
            "/oauth/register",
            json={"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"},
        )
        bad = await http.post("/oauth/register", json={"redirect_uris": ["javascript:x"]})
    assert resp.status_code == 201 and resp.json()["client_id"]
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_redirect_uri"


async def test_http_client_credentials_token_works_at_mcp(
    harness: Harness, pg_state_dsn: str
) -> None:
    secret = secrets.token_urlsafe(32)
    c = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        await store.set_machine_secret(c, "nightly-report", secret, harness.clock.now)
    finally:
        await c.close()
    basic = base64.b64encode(f"nightly-report:{secret}".encode()).decode()
    async with harness.raw() as http:
        resp = await http.post(
            "/oauth/token",
            headers={"Authorization": f"Basic {basic}"},
            data={"grant_type": "client_credentials", "resource": harness.audience},
        )
    assert resp.status_code == 200, resp.text
    assert resp.headers["cache-control"] == "no-store"
    token = resp.json()["access_token"]
    async with harness.client(token) as client:
        result = await client.call_tool("whoami", {})
    who: dict[str, Any] = result.structured_content or {}
    assert who.get("pg_role") == "pw_m_nightly_report"


async def test_mcp_rejects_upstream_style_and_unsigned_tokens(harness: Harness) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = {
        "iss": harness.config.public_url,
        "aud": harness.audience,
        "sub": "person:alice",
        "client_id": "x",
        "iat": int(harness.clock.now.timestamp()),
        "exp": int(harness.clock.now.timestamp()) + 600,
    }
    upstream = pyjwt.encode(claims, rsa_key, algorithm="RS256", headers={"typ": "at+jwt"})
    unsigned = pyjwt.encode(claims, None, algorithm="none", headers={"typ": "at+jwt"})
    for token in (upstream, unsigned):
        async with harness.raw(token) as http:
            resp = await http.post("/mcp", headers=_ACCEPT, json=_JSONRPC)
        assert resp.status_code == 401


async def test_mcp_rejects_revoked_and_suspended(harness: Harness, pg_state_dsn: str) -> None:
    revoked = harness.token(person_subject("alice"))
    claims = verify_access_token(
        revoked,
        {harness.signing.kid: harness.signing.public_key},
        issuer=harness.config.public_url,
        audience=harness.audience,
        now=harness.clock.now,
    )
    c = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        await store.revoke_jti(c, claims.jti, claims.expires_at)
        async with harness.raw(revoked) as http:
            resp = await http.post("/mcp", headers=_ACCEPT, json=_JSONRPC)
        assert resp.status_code == 401 and "revoked" in resp.text

        await c.execute(
            "INSERT INTO pgwarden.people_status (person_role, suspended) "
            "VALUES ('pw_u_dana', true) ON CONFLICT (person_role) DO UPDATE SET suspended = true"
        )
        async with harness.raw(harness.token(person_subject("dana"))) as http:
            resp = await http.post("/mcp", headers=_ACCEPT, json=_JSONRPC)
        assert resp.status_code == 401 and "suspended" in resp.text
    finally:
        await c.execute(
            "UPDATE pgwarden.people_status SET suspended = false WHERE person_role = 'pw_u_dana'"
        )
        await c.close()
