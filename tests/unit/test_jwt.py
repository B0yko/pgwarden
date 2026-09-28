"""Unit tests for the gateway's EdDSA access tokens and its signing key."""

from __future__ import annotations

import datetime as dt

import pytest

from pgwarden.oauth.jwt import (
    ACCESS_TOKEN_TYP,
    TokenError,
    mint_access_token,
    verify_access_token,
)
from pgwarden.oauth.keys import (
    generate_signing_key_pem,
    jwk_thumbprint,
    load_signing_key,
    public_jwk,
)

_NOW = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.UTC)
_ISS = "https://gw.example.com"
_AUD = "https://gw.example.com/mcp"


def _key():
    return load_signing_key(generate_signing_key_pem())


def _mint(key, **overrides):
    kwargs = {
        "issuer": _ISS,
        "audience": _AUD,
        "subject": "person:alice",
        "client_id": "client-1",
        "now": _NOW,
    }
    kwargs.update(overrides)
    return mint_access_token(key.private_key, key.kid, **kwargs)


def test_round_trip() -> None:
    key = _key()
    token = _mint(key)
    claims = verify_access_token(
        token, {key.kid: key.public_key}, issuer=_ISS, audience=_AUD, now=_NOW
    )
    assert claims.subject == "person:alice"
    assert claims.client_id == "client-1"


def test_header_is_at_jwt_with_kid() -> None:
    import jwt as pyjwt

    key = _key()
    header = pyjwt.get_unverified_header(_mint(key))
    assert header["typ"] == ACCESS_TOKEN_TYP
    assert header["alg"] == "EdDSA"
    assert header["kid"] == key.kid


def test_wrong_audience_rejected() -> None:
    key = _key()
    token = _mint(key)
    with pytest.raises(TokenError):
        verify_access_token(
            token, {key.kid: key.public_key}, issuer=_ISS, audience="other", now=_NOW
        )


def test_wrong_issuer_rejected() -> None:
    key = _key()
    token = _mint(key)
    with pytest.raises(TokenError):
        verify_access_token(
            token, {key.kid: key.public_key}, issuer="other", audience=_AUD, now=_NOW
        )


def test_expired_rejected() -> None:
    key = _key()
    token = _mint(key, ttl_seconds=600)
    later = _NOW + dt.timedelta(seconds=601)
    with pytest.raises(TokenError):
        verify_access_token(token, {key.kid: key.public_key}, issuer=_ISS, audience=_AUD, now=later)


def test_foreign_key_rejected() -> None:
    key = _key()
    other = _key()
    token = _mint(key)
    with pytest.raises(TokenError):
        verify_access_token(
            token, {key.kid: other.public_key}, issuer=_ISS, audience=_AUD, now=_NOW
        )


def test_unknown_kid_rejected() -> None:
    key = _key()
    token = _mint(key)
    with pytest.raises(TokenError):
        verify_access_token(token, {}, issuer=_ISS, audience=_AUD, now=_NOW)


def test_wrong_typ_rejected() -> None:
    import jwt as pyjwt

    key = _key()
    # a plain JWT (not at+jwt) signed by the same key must be rejected
    forged = pyjwt.encode(
        {
            "iss": _ISS,
            "aud": _AUD,
            "sub": "person:alice",
            "client_id": "c",
            "iat": 0,
            "exp": 9_999_999_999,
        },
        key.private_key,
        algorithm="EdDSA",
        headers={"typ": "JWT", "kid": key.kid},
    )
    with pytest.raises(TokenError, match="typ"):
        verify_access_token(forged, {key.kid: key.public_key}, issuer=_ISS, audience=_AUD, now=_NOW)


def test_thumbprint_is_stable() -> None:
    key = _key()
    jwk = public_jwk(key.public_key)
    assert jwk["kid"] == jwk_thumbprint(jwk) == key.kid


def test_load_rejects_non_ed25519() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(ValueError, match="Ed25519"):
        load_signing_key(rsa_pem)
