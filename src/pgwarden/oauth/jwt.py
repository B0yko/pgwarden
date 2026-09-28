"""The gateway's own access tokens: EdDSA (Ed25519) JWTs it issues and verifies.

Per RFC 9068 the header is ``typ: at+jwt`` with a ``kid``; claims are ``iss``,
``aud`` (the canonical MCP URL), ``sub``, ``client_id``, ``jti``, ``iat`` and
``exp``. The verifier rejects any other ``typ`` or ``alg`` and any wrong
audience or issuer, and never accepts an upstream IdP token (token passthrough
is forbidden: those are not signed by this key and fail signature/typ checks).
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import secrets
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ACCESS_TOKEN_TYP = "at+jwt"
ALGORITHM = "EdDSA"
DEFAULT_TTL_SECONDS = 600  # 10 minutes


class TokenError(Exception):
    """Raised when an access token cannot be issued or fails verification."""


@dataclasses.dataclass(frozen=True)
class AccessTokenClaims:
    subject: str
    client_id: str
    issuer: str
    audience: str
    jti: str
    issued_at: dt.datetime
    expires_at: dt.datetime


def mint_access_token(
    private_key: Ed25519PrivateKey,
    kid: str,
    *,
    issuer: str,
    audience: str,
    subject: str,
    client_id: str,
    now: dt.datetime,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """Issue a signed EdDSA access token. ``now`` is injected for testability."""
    issued_at = now
    expires_at = now + dt.timedelta(seconds=ttl_seconds)
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "client_id": client_id,
        "jti": secrets.token_urlsafe(16),
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm=ALGORITHM,
        headers={"typ": ACCESS_TOKEN_TYP, "kid": kid},
    )


def verify_access_token(
    token: str,
    public_keys: dict[str, Ed25519PublicKey],
    *,
    issuer: str,
    audience: str,
    now: dt.datetime | None = None,
) -> AccessTokenClaims:
    """Verify signature, ``typ``, ``alg``, ``iss``, ``aud`` and ``exp``.

    ``public_keys`` maps ``kid`` to the key; a token with an unknown or missing
    ``kid``, a non-``at+jwt`` ``typ``, a non-EdDSA ``alg``, the wrong audience or
    issuer, or an expired ``exp`` is rejected with :class:`TokenError`.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenError(f"malformed token: {exc}") from exc

    if header.get("typ") != ACCESS_TOKEN_TYP:
        raise TokenError(f"unexpected token typ {header.get('typ')!r}; expected {ACCESS_TOKEN_TYP}")
    if header.get("alg") != ALGORITHM:
        raise TokenError(f"unexpected alg {header.get('alg')!r}; expected {ALGORITHM}")
    kid = header.get("kid")
    if not kid or kid not in public_keys:
        raise TokenError("token kid is unknown")

    # PyJWT validates exp against the wall clock; when a caller injects `now`
    # (tests, and the injectable-clock refresh test), skip PyJWT's exp check and
    # enforce exp ourselves against `now` below.
    options: dict[str, Any] = {
        "require": ["exp", "iat", "iss", "aud", "sub"],
        "verify_exp": now is None,
    }
    try:
        payload = jwt.decode(
            token,
            public_keys[kid],
            algorithms=[ALGORITHM],
            audience=audience,
            issuer=issuer,
            leeway=0,
            options=options,  # type: ignore[arg-type]
        )
    except jwt.PyJWTError as exc:
        raise TokenError(f"token verification failed: {exc}") from exc

    issued_at = dt.datetime.fromtimestamp(int(payload["iat"]), tz=dt.UTC)
    expires_at = dt.datetime.fromtimestamp(int(payload["exp"]), tz=dt.UTC)
    if now is not None and now >= expires_at:
        raise TokenError("token has expired")
    if "client_id" not in payload:
        raise TokenError("token is missing client_id")

    return AccessTokenClaims(
        subject=str(payload["sub"]),
        client_id=str(payload["client_id"]),
        issuer=str(payload["iss"]),
        audience=audience,
        jti=str(payload.get("jti", "")),
        issued_at=issued_at,
        expires_at=expires_at,
    )


__all__ = [
    "ACCESS_TOKEN_TYP",
    "ALGORITHM",
    "DEFAULT_TTL_SECONDS",
    "AccessTokenClaims",
    "TokenError",
    "mint_access_token",
    "verify_access_token",
]
