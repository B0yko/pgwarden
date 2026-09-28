"""Unit tests for the authorization server's pure pieces: PKCE, redirect-URI
rules, resource matching, client-auth parsing and the CIMD fetcher's SSRF guards.
"""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest

from pgwarden.oauth import pkce
from pgwarden.oauth.cimd import (
    CimdError,
    fetch_client_metadata,
    is_public_address,
    looks_like_cimd_client_id,
)
from pgwarden.oauth.redirects import (
    RedirectUriError,
    redirect_uri_matches,
    validate_redirect_uri,
)
from pgwarden.oauth.server import _parse_client_auth, resource_matches

# -- PKCE ----------------------------------------------------------------------

VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # RFC 7636 appendix B
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_s256_matches_rfc_7636_example() -> None:
    assert pkce.s256_challenge(VERIFIER) == CHALLENGE
    assert pkce.verify(VERIFIER, CHALLENGE)


def test_plain_and_malformed_challenges_are_invalid() -> None:
    assert pkce.is_valid_challenge(CHALLENGE, "S256")
    assert not pkce.is_valid_challenge(CHALLENGE, "plain")
    assert not pkce.is_valid_challenge(CHALLENGE, None)
    assert not pkce.is_valid_challenge("short", "S256")


def test_wrong_or_short_verifier_fails() -> None:
    assert not pkce.verify("x" * 43, CHALLENGE)
    assert not pkce.verify("too-short", CHALLENGE)
    assert not pkce.verify(None, CHALLENGE)


# -- redirect URIs ---------------------------------------------------------------


@pytest.mark.parametrize(
    "uri",
    [
        "https://client.example.com/cb",
        "http://127.0.0.1:6274/oauth/callback",
        "http://localhost:8787/callback",
        "http://[::1]:9000/cb",
        "cursor://anysphere.cursor-mcp/oauth/callback",
        "com.example.app:/oauth2redirect",
    ],
)
def test_allowed_redirect_uris(uri: str) -> None:
    validate_redirect_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "javascript:alert(1)",
        "data:text/html,hi",
        "file:///etc/passwd",
        "http://evil.example.com/cb",
        "https://client.example.com/cb#frag",
        "",
        "https:///nohost",
    ],
)
def test_rejected_redirect_uris(uri: str) -> None:
    with pytest.raises(RedirectUriError):
        validate_redirect_uri(uri)


def test_loopback_port_is_ignored_but_path_is_not() -> None:
    registered = ["http://127.0.0.1:6274/oauth/callback", "https://app.example.com/cb"]
    assert redirect_uri_matches("http://127.0.0.1:51234/oauth/callback", registered)
    assert not redirect_uri_matches("http://127.0.0.1:51234/other", registered)
    assert redirect_uri_matches("https://app.example.com/cb", registered)
    assert not redirect_uri_matches("https://app.example.com:444/cb", registered)
    assert not redirect_uri_matches("https://app.example.com/cb2", registered)


# -- resource indicator ------------------------------------------------------------


def test_resource_matching_is_canonical() -> None:
    canonical = "http://localhost:8080/mcp"
    assert resource_matches("http://localhost:8080/mcp", canonical)
    assert resource_matches("http://LOCALHOST:8080/mcp/", canonical)
    assert not resource_matches(None, canonical)
    assert not resource_matches("", canonical)
    assert not resource_matches("http://localhost:8080/other", canonical)
    assert not resource_matches("https://localhost:8080/mcp", canonical)
    assert not resource_matches("http://localhost:8080/mcp#x", canonical)


# -- client authentication -----------------------------------------------------------


def test_parse_basic_and_post_client_auth() -> None:
    basic = base64.b64encode(b"my%20client:s3cret").decode()
    auth = _parse_client_auth({"authorization": f"Basic {basic}"}, {})
    assert auth is not None and auth.client_id == "my client" and auth.secret == "s3cret"
    assert auth.method == "basic"
    post = _parse_client_auth({}, {"client_id": "c1", "client_secret": "x"})
    assert post is not None and post.method == "post"
    public = _parse_client_auth({}, {"client_id": "c1"})
    assert public is not None and public.method == "none" and public.secret is None
    assert _parse_client_auth({}, {}) is None
    assert _parse_client_auth({"authorization": "Basic !!!"}, {}) is None


# -- CIMD --------------------------------------------------------------------------

CLIENT_ID = "https://client.example.com/oauth/metadata.json"
DOC = {
    "client_id": CLIENT_ID,
    "client_name": "Example Client",
    "redirect_uris": ["http://127.0.0.1:3000/callback"],
    "token_endpoint_auth_method": "none",
}


def _resolver(*ips: str):  # type: ignore[no-untyped-def]
    async def resolve(host: str, port: int) -> list[str]:
        return list(ips)

    return resolve


def _transport(handler):  # type: ignore[no-untyped-def]
    return httpx.MockTransport(handler)


def test_cimd_client_id_shape() -> None:
    assert looks_like_cimd_client_id(CLIENT_ID)
    assert not looks_like_cimd_client_id("https://client.example.com")
    assert not looks_like_cimd_client_id("http://client.example.com/meta.json")
    assert not looks_like_cimd_client_id("plain-client-id")


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.5",
        "127.0.0.1",
        "169.254.169.254",
        "192.168.1.1",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
    ],
)
def test_non_public_addresses_are_refused(ip: str) -> None:
    assert not is_public_address(ip)


def test_public_address_allowed() -> None:
    assert is_public_address("8.8.8.8")
    assert is_public_address("2606:4700:4700::1111")


def test_fetch_pins_ip_and_keeps_host_for_sni() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["host"] = request.headers.get("host")
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, json=DOC)

    doc = asyncio.run(
        fetch_client_metadata(
            CLIENT_ID, resolver=_resolver("8.8.8.8"), transport=_transport(handler)
        )
    )
    assert doc["client_name"] == "Example Client"
    assert str(seen["url"]) == "https://8.8.8.8/oauth/metadata.json"
    assert seen["host"] == "client.example.com"
    assert seen["sni"] == "client.example.com"


def test_fetch_refuses_private_resolution() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never called
        raise AssertionError("must not connect")

    with pytest.raises(CimdError, match="non-public"):
        asyncio.run(
            fetch_client_metadata(
                CLIENT_ID, resolver=_resolver("8.8.8.8", "10.1.2.3"), transport=_transport(handler)
            )
        )


def test_fetch_refuses_redirects() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    with pytest.raises(CimdError, match="302"):
        asyncio.run(
            fetch_client_metadata(
                CLIENT_ID, resolver=_resolver("8.8.8.8"), transport=_transport(handler)
            )
        )


def test_fetch_enforces_size_cap() -> None:
    big = json.dumps({**DOC, "padding": "x" * 70_000}).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=big)

    with pytest.raises(CimdError, match="exceeds"):
        asyncio.run(
            fetch_client_metadata(
                CLIENT_ID, resolver=_resolver("8.8.8.8"), transport=_transport(handler)
            )
        )


def test_fetch_times_out() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(2)
        return httpx.Response(200, json=DOC)

    with pytest.raises(CimdError, match="timed out|failed"):
        asyncio.run(
            fetch_client_metadata(
                CLIENT_ID,
                resolver=_resolver("8.8.8.8"),
                transport=_transport(handler),
                timeout_s=0.2,
            )
        )


def test_fetch_rejects_client_id_mismatch_and_bad_redirects() -> None:
    def mismatch(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={**DOC, "client_id": "https://other.example.com/x"})

    with pytest.raises(CimdError, match="does not equal"):
        asyncio.run(
            fetch_client_metadata(
                CLIENT_ID, resolver=_resolver("8.8.8.8"), transport=_transport(mismatch)
            )
        )

    def bad_redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={**DOC, "redirect_uris": ["javascript:alert(1)"]})

    with pytest.raises(CimdError):
        asyncio.run(
            fetch_client_metadata(
                CLIENT_ID, resolver=_resolver("8.8.8.8"), transport=_transport(bad_redirect)
            )
        )
