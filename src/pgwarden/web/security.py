"""Cookies, CSRF tokens and response security headers for the gateway's pages.

Cookies are ``HttpOnly``, ``SameSite=Lax`` and ``Path=/``. On an https
``public_url`` they are also ``Secure`` and carry the ``__Host-`` prefix (which
requires both); on loopback http, where ``Secure`` cannot be set, the same name
is used without the prefix. Pages get a strict CSP with no scripts at all and
``frame-ancestors 'none'``; a page whose form submission ends in a redirect to
another origin (the upstream IdP, the MCP client's redirect URI) names that
origin in ``form-action``, since browsers apply ``form-action`` to redirects too.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import Response


@dataclasses.dataclass(frozen=True)
class CookiePolicy:
    secure: bool

    def name(self, base: str) -> str:
        return f"__Host-{base}" if self.secure else base

    def set(self, response: Response, base: str, value: str, *, max_age: int) -> None:
        response.set_cookie(
            self.name(base),
            value,
            max_age=max_age,
            path="/",
            secure=self.secure,
            httponly=True,
            samesite="lax",
        )

    def clear(self, response: Response, base: str) -> None:
        response.delete_cookie(
            self.name(base), path="/", secure=self.secure, httponly=True, samesite="lax"
        )

    def get(self, request: Request, base: str) -> str | None:
        return request.cookies.get(self.name(base))


def cookie_policy(public_url: str) -> CookiePolicy:
    return CookiePolicy(secure=urlsplit(public_url).scheme == "https")


def csrf_token(session_secret: str, *parts: str) -> str:
    key = hmac.new(session_secret.encode(), b"pgwarden-csrf-v1", hashlib.sha256).digest()
    return hmac.new(key, "\x1f".join(parts).encode(), hashlib.sha256).hexdigest()


def csrf_ok(session_secret: str, token: str | None, *parts: str) -> bool:
    return bool(token) and hmac.compare_digest(csrf_token(session_secret, *parts), token or "")


def origin_source(url: str) -> str | None:
    """A CSP source expression for ``url``'s origin (or its scheme, for app schemes)."""
    parts = urlsplit(url)
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    if parts.scheme:
        return f"{parts.scheme}:"
    return None


def apply_security_headers(response: Response, *, form_targets: tuple[str, ...] = ()) -> Response:
    sources = ["'self'", *[s for s in (origin_source(t) for t in form_targets) if s]]
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; img-src 'self' data:; "
        f"form-action {' '.join(dict.fromkeys(sources))}; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def safe_next_path(value: str | None) -> str:
    """Only same-site relative paths: no scheme, no host, no protocol-relative //."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    return value


__all__ = [
    "CookiePolicy",
    "apply_security_headers",
    "cookie_policy",
    "csrf_ok",
    "csrf_token",
    "origin_source",
    "safe_next_path",
]
