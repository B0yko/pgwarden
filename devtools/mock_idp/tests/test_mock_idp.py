"""Tests for the pgwarden mock OIDC provider.

Run with: uv run --project devtools/mock_idp pytest devtools/mock_idp/tests
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
from conftest import CLIENT_ID, CLIENT_SECRET, INTERNAL_URL, ISSUER, REDIRECT_URI

APP_DIR = Path(__file__).resolve().parent.parent
REQUEST_ID_RE = re.compile(r'name="request_id" value="([^"]+)"')


def _make_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _authorize_params(**overrides: str) -> dict[str, str]:
    _verifier, challenge = _make_pkce_pair()
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "state-123",
        "nonce": "nonce-123",
        "scope": "openid email profile",
    }
    params.update(overrides)
    return params


async def _full_login(client: httpx.AsyncClient, *, sub: str = "usr_alice") -> tuple[str, str, str]:
    """Drive /authorize (picker) + /authorize/login. Returns (code, state, verifier)."""
    verifier, challenge = _make_pkce_pair()
    params = _authorize_params(code_challenge=challenge)
    resp = await client.get("/authorize", params=params)
    assert resp.status_code == 200
    request_id_match = REQUEST_ID_RE.search(resp.text)
    assert request_id_match is not None
    request_id = request_id_match.group(1)

    login_resp = await client.post(
        "/authorize/login",
        data={"request_id": request_id, "sub": sub},
        follow_redirects=False,
    )
    assert login_resp.status_code == 302
    location = login_resp.headers["location"]
    query = parse_qs(urlparse(location).query)
    assert query["state"] == [params["state"]]
    return query["code"][0], params["state"], verifier


async def test_discovery_splits_browser_and_internal_urls(client: httpx.AsyncClient) -> None:
    resp = await client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()

    assert body["issuer"] == ISSUER
    assert body["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert body["token_endpoint"] == f"{INTERNAL_URL}/token"
    assert body["jwks_uri"] == f"{INTERNAL_URL}/jwks"
    assert body["userinfo_endpoint"] == f"{INTERNAL_URL}/userinfo"

    assert body["response_types_supported"] == ["code"]
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["id_token_signing_alg_values_supported"] == ["RS256"]
    assert body["subject_types_supported"] == ["public"]
    assert set(body["scopes_supported"]) == {"openid", "email", "profile"}
    assert set(body["token_endpoint_auth_methods_supported"]) == {
        "client_secret_basic",
        "client_secret_post",
    }


async def test_full_code_flow_with_pkce(client: httpx.AsyncClient) -> None:
    code, _state, verifier = await _full_login(client, sub="usr_alice")

    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    token_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        headers={"Authorization": f"Basic {basic}"},
    )
    assert token_resp.status_code == 200
    body = token_resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] > 0
    assert "access_token" in body
    assert "id_token" in body

    userinfo_resp = await client.get(
        "/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert userinfo_resp.status_code == 200
    info = userinfo_resp.json()
    assert info["email"] == "alice@example.com"
    assert info["email_verified"] is True
    assert info["sub"] == "usr_alice"


async def test_plain_pkce_rejected(client: httpx.AsyncClient) -> None:
    params = _authorize_params(code_challenge_method="plain")
    resp = await client.get("/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "error=invalid_request" in location
    assert "code=" not in location


async def test_missing_pkce_rejected(client: httpx.AsyncClient) -> None:
    params = _authorize_params()
    del params["code_challenge"]
    del params["code_challenge_method"]
    resp = await client.get("/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 302
    assert "error=invalid_request" in resp.headers["location"]


async def test_wrong_redirect_uri_rejected(client: httpx.AsyncClient) -> None:
    params = _authorize_params(redirect_uri="http://evil.example/callback")
    resp = await client.get("/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 400


async def test_code_replay_rejected(client: httpx.AsyncClient) -> None:
    code, _state, verifier = await _full_login(client, sub="usr_bob")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    first = await client.post("/token", data=data)
    assert first.status_code == 200

    second = await client.post("/token", data=data)
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


async def test_wrong_code_verifier_rejected(client: httpx.AsyncClient) -> None:
    code, _state, _verifier = await _full_login(client, sub="usr_dana")
    resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": "not-the-right-verifier",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"

    # The code is single-use even though the first attempt failed.
    replay = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": "still-wrong",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    assert replay.status_code == 400


async def test_id_token_verifies_against_jwks(client: httpx.AsyncClient) -> None:
    verifier, challenge = _make_pkce_pair()
    params = _authorize_params(code_challenge=challenge, nonce="the-nonce-value")
    resp = await client.get("/authorize", params=params)
    request_id = REQUEST_ID_RE.search(resp.text).group(1)  # type: ignore[union-attr]
    login_resp = await client.post(
        "/authorize/login",
        data={"request_id": request_id, "sub": "usr_carol"},
        follow_redirects=False,
    )
    code = parse_qs(urlparse(login_resp.headers["location"]).query)["code"][0]

    token_resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    id_token = token_resp.json()["id_token"]

    jwks_resp = await client.get("/jwks")
    jwk = jwks_resp.json()["keys"][0]
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

    header = jwt.get_unverified_header(id_token)
    assert header["kid"] == jwk["kid"]
    assert header["alg"] == "RS256"

    claims = jwt.decode(
        id_token,
        key=public_key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=ISSUER,
    )
    assert claims["sub"] == "usr_carol"
    assert claims["email"] == "carol@example.com"
    assert claims["nonce"] == "the-nonce-value"
    assert claims["iss"] == ISSUER
    assert claims["aud"] == CLIENT_ID
    assert "auth_time" in claims
    assert claims["exp"] - claims["iat"] == 300


def test_dev_only_guard_blocks_startup_without_env() -> None:
    env = {k: v for k, v in os.environ.items() if k != "MOCK_IDP_DEV_ONLY"}
    result = subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=str(APP_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "MOCK_IDP_DEV_ONLY" in result.stderr


def test_dev_only_guard_allows_startup_with_env() -> None:
    env = dict(os.environ)
    env["MOCK_IDP_DEV_ONLY"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=str(APP_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
