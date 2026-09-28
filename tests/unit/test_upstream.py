"""Upstream provider presets against hand-written minimal responses (no network).

The discovery documents, JWKS, tokens and GitHub API bodies here are written for
these tests; tenant ids are obviously fake.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any

import httpx2 as httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pgwarden.config import UpstreamConfig
from pgwarden.oauth.upstream import UpstreamError, UpstreamProvider

TENANT = "00000000-0000-0000-0000-00000000c0de"
CLIENT_ID = "pgwarden-test-client"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "test-key-1"


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": KID,
            "use": "sig",
            "alg": "RS256",
            "n": _b64(KEY.public_key().public_numbers().n),
            "e": _b64(KEY.public_key().public_numbers().e),
        }
    ]
}


def _id_token(claims: dict[str, Any], *, alg: str = "RS256", key: Any = KEY) -> str:
    now = int(time.time())
    body = {"aud": CLIENT_ID, "iat": now, "exp": now + 300, **claims}
    return jwt.encode(body, key, algorithm=alg, headers={"kid": KID})


def _oidc_transport(issuer: str, discovery_url: str, id_token: str) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == discovery_url:
            return httpx.Response(
                200,
                json={
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks",
                    "code_challenge_methods_supported": ["S256"],
                },
            )
        if url == "https://idp.example.com/jwks":
            return httpx.Response(200, json=JWKS)
        if url == "https://idp.example.com/token":
            body = request.content.decode()
            assert "code_verifier=" in body and "code=the-code" in body
            return httpx.Response(
                200, json={"access_token": "at", "token_type": "Bearer", "id_token": id_token}
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _provider(config: UpstreamConfig, transport: httpx.MockTransport) -> UpstreamProvider:
    return UpstreamProvider(
        config,
        client_secret="test-secret",
        redirect_uri="http://localhost:8080/oauth/callback",
        transport=transport,
    )


def _exchange(provider: UpstreamProvider, nonce: str = "n-1") -> Any:
    return asyncio.run(provider.exchange(code="the-code", code_verifier="v" * 50, nonce=nonce))


def test_google_identity_uses_sub_and_verified_email() -> None:
    issuer = "https://accounts.google.com"
    token = _id_token(
        {
            "iss": issuer,
            "sub": "10987654321",
            "email": "ann@example.com",
            "email_verified": True,
            "nonce": "n-1",
        }
    )
    config = UpstreamConfig(name="google", preset="google", issuer=issuer, client_id=CLIENT_ID)
    transport = _oidc_transport(
        issuer, "https://accounts.google.com/.well-known/openid-configuration", token
    )
    ident = _exchange(_provider(config, transport))
    assert (ident.provider, ident.subject, ident.email, ident.email_verified) == (
        "google",
        "10987654321",
        "ann@example.com",
        True,
    )


def test_authorization_url_has_pkce_state_and_nonce() -> None:
    issuer = "https://accounts.google.com"
    config = UpstreamConfig(name="google", preset="google", issuer=issuer, client_id=CLIENT_ID)
    transport = _oidc_transport(
        issuer, "https://accounts.google.com/.well-known/openid-configuration", "unused"
    )
    url = asyncio.run(
        _provider(config, transport).authorization_url(
            state="s-1", nonce="n-1", code_verifier="v" * 50
        )
    )
    assert "code_challenge_method=S256" in url and "state=s-1" in url and "nonce=n-1" in url


def test_entra_identity_is_tid_oid_and_email_never_verified() -> None:
    issuer = f"https://login.microsoftonline.com/{TENANT}/v2.0"
    token = _id_token(
        {
            "iss": issuer,
            "sub": "pairwise-sub",
            "tid": TENANT,
            "oid": "11111111-2222-3333-4444-555555555555",
            "email": "ann@example.com",
            "nonce": "n-1",
        }
    )
    config = UpstreamConfig(
        name="entra", preset="entra", issuer=issuer, client_id=CLIENT_ID, tenant_id=TENANT
    )
    transport = _oidc_transport(issuer, f"{issuer}/.well-known/openid-configuration", token)
    ident = _exchange(_provider(config, transport))
    assert ident.subject == f"{TENANT}:11111111-2222-3333-4444-555555555555"
    assert ident.email_verified is False


def test_entra_token_from_another_tenant_is_rejected() -> None:
    issuer = f"https://login.microsoftonline.com/{TENANT}/v2.0"
    token = _id_token(
        {
            "iss": issuer,
            "sub": "s",
            "tid": "00000000-0000-0000-0000-00000000beef",
            "oid": "o",
            "nonce": "n-1",
        }
    )
    config = UpstreamConfig(
        name="entra", preset="entra", issuer=issuer, client_id=CLIENT_ID, tenant_id=TENANT
    )
    transport = _oidc_transport(issuer, f"{issuer}/.well-known/openid-configuration", token)
    with pytest.raises(UpstreamError, match="tenant"):
        _exchange(_provider(config, transport))


@pytest.mark.parametrize(
    ("claims", "alg", "nonce", "match"),
    [
        ({"sub": "u1", "nonce": "n-1", "aud": "someone-else"}, "RS256", "n-1", "rejected"),
        ({"sub": "u1", "nonce": "other"}, "RS256", "n-1", "nonce"),
        (
            {"sub": "u1", "nonce": "n-1", "iss": "https://evil.example.com"},
            "RS256",
            "n-1",
            "rejected",
        ),
        ({"sub": "u1", "nonce": "n-1"}, "HS256", "n-1", "algorithm"),
    ],
)
def test_generic_oidc_id_token_rejections(
    claims: dict[str, Any], alg: str, nonce: str, match: str
) -> None:
    issuer = "https://idp.example.com"
    full = {"iss": issuer, **claims}
    token = _id_token(full, alg=alg, key=("x" * 32 if alg == "HS256" else KEY))
    config = UpstreamConfig(name="corp", issuer=issuer, client_id=CLIENT_ID)
    transport = _oidc_transport(issuer, f"{issuer}/.well-known/openid-configuration", token)
    with pytest.raises(UpstreamError, match=match):
        _exchange(_provider(config, transport), nonce=nonce)


def test_discovery_issuer_mismatch_is_rejected() -> None:
    config = UpstreamConfig(name="corp", issuer="https://idp.example.com", client_id=CLIENT_ID)
    transport = _oidc_transport(
        "https://other.example.com", "https://idp.example.com/.well-known/openid-configuration", "x"
    )
    with pytest.raises(UpstreamError, match="issuer"):
        _exchange(_provider(config, transport))


def test_github_identity_uses_numeric_id_and_verified_primary_email() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://github.com/login/oauth/access_token":
            assert request.headers["accept"].startswith("application/json")
            return httpx.Response(
                200, json={"access_token": "test-gh-token", "token_type": "bearer"}
            )
        if url == "https://api.github.com/user":
            assert request.headers["authorization"] == "Bearer test-gh-token"
            return httpx.Response(200, json={"id": 424242, "login": "octo-example"})
        if url == "https://api.github.com/user/emails":
            return httpx.Response(
                200,
                json=[
                    {"email": "old@example.com", "primary": False, "verified": True},
                    {"email": "octo@example.com", "primary": True, "verified": True},
                ],
            )
        return httpx.Response(404)

    config = UpstreamConfig(
        name="github", preset="github", issuer="https://github.com", client_id=CLIENT_ID
    )
    ident = _exchange(_provider(config, httpx.MockTransport(handler)))
    assert (ident.subject, ident.email, ident.email_verified) == (
        "424242",
        "octo@example.com",
        True,
    )


def test_github_unverified_primary_email_is_not_used() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/access_token"):
            return httpx.Response(200, json={"access_token": "t", "token_type": "bearer"})
        if url.endswith("/user"):
            return httpx.Response(200, json={"id": 7})
        return httpx.Response(
            200, json=[{"email": "x@example.com", "primary": True, "verified": False}]
        )

    config = UpstreamConfig(
        name="github", preset="github", issuer="https://github.com", client_id=CLIENT_ID
    )
    ident = _exchange(_provider(config, httpx.MockTransport(handler)))
    assert ident.email is None and ident.email_verified is False


def test_serve_refuses_when_the_admin_dsn_is_present(monkeypatch: pytest.MonkeyPatch) -> None:
    from pgwarden.wiring import WiringError, build_app

    monkeypatch.setenv("PGWARDEN_ADMIN_DSN", "postgresql://admin@db/x")
    with pytest.raises(WiringError, match="PGWARDEN_ADMIN_DSN"):
        build_app()
    monkeypatch.delenv("PGWARDEN_ADMIN_DSN")
    monkeypatch.setenv("PGWARDEN_ADMIN_DSN_FILE", "/run/secrets/admin_dsn")
    with pytest.raises(WiringError, match="PGWARDEN_ADMIN_DSN_FILE"):
        build_app()


def test_json_fixtures_are_minimal() -> None:
    # The fixtures are hand-written: no real tenant ids.
    assert TENANT.startswith("00000000-")
    assert json.dumps(JWKS)
