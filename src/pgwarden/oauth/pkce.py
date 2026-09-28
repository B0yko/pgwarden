"""PKCE (RFC 7636), S256 only. ``plain`` is never accepted."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

# RFC 7636 section 4.1: 43-128 characters from the unreserved set.
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
# An S256 challenge is base64url(sha256) without padding: exactly 43 characters.
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9\-_]{43}$")


def s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def is_valid_challenge(challenge: str | None, method: str | None) -> bool:
    """A well-formed S256 challenge. Any other method (including ``plain``) is invalid."""
    return method == "S256" and challenge is not None and bool(_CHALLENGE_RE.match(challenge))


def verify(verifier: str | None, challenge: str) -> bool:
    """Constant-time check that ``verifier`` hashes to the stored S256 ``challenge``."""
    if verifier is None or not _VERIFIER_RE.match(verifier):
        return False
    return hmac.compare_digest(s256_challenge(verifier), challenge)


__all__ = ["is_valid_challenge", "s256_challenge", "verify"]
