"""Redirect-URI rules for client registration and the authorization request.

Allowed at registration: ``https`` URLs, loopback ``http`` (``127.0.0.1``,
``[::1]``, ``localhost``), and private-use URI schemes for native apps (RFC 8252
section 7.1, for example ``cursor://...``). Rejected: ``javascript:``, ``data:``,
``file:`` and other dangerous schemes, non-loopback ``http``, and any URI with a
fragment. At authorization time the redirect URI must match a registered one
exactly, except that the port of a loopback redirect URI is ignored (RFC 8252
section 7.3).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# Schemes that must never be a redirect target, whatever else is true.
_FORBIDDEN_SCHEMES = frozenset(
    {"javascript", "data", "file", "vbscript", "about", "blob", "filesystem", "ftp", "ws", "wss"}
)
# RFC 3986 scheme syntax.
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*$")


class RedirectUriError(ValueError):
    """A redirect URI that may not be registered or used."""


def validate_redirect_uri(uri: str) -> None:
    """Raise :class:`RedirectUriError` if ``uri`` may not be registered."""
    if not uri or any(c.isspace() for c in uri):
        raise RedirectUriError("redirect URI must be a non-empty string without whitespace")
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    if not scheme or not _SCHEME_RE.match(scheme):
        raise RedirectUriError(f"redirect URI {uri!r} has no valid scheme")
    if parts.fragment:
        raise RedirectUriError("redirect URI must not contain a fragment")
    if scheme in _FORBIDDEN_SCHEMES:
        raise RedirectUriError(f"redirect URI scheme {scheme!r} is not allowed")
    if scheme == "https":
        if not parts.hostname:
            raise RedirectUriError("https redirect URI must have a host")
        return
    if scheme == "http":
        host = (parts.hostname or "").lower()
        if host not in LOOPBACK_HOSTS:
            raise RedirectUriError(
                "http redirect URIs are only allowed for loopback hosts "
                "(127.0.0.1, [::1], localhost)"
            )
        return
    # Private-use scheme for a native app (RFC 8252 section 7.1).
    return


def is_loopback_http(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme.lower() == "http" and (parts.hostname or "").lower() in LOOPBACK_HOSTS


def _without_port(uri: str) -> tuple[str, str, str, str]:
    parts = urlsplit(uri)
    return (parts.scheme.lower(), (parts.hostname or "").lower(), parts.path, parts.query)


def redirect_uri_matches(requested: str, registered: list[str]) -> bool:
    """Exact match against a registered URI; the port of a loopback URI is ignored."""
    if requested in registered:
        return True
    if not is_loopback_http(requested):
        return False
    wanted = _without_port(requested)
    return any(is_loopback_http(r) and _without_port(r) == wanted for r in registered)


__all__ = [
    "LOOPBACK_HOSTS",
    "RedirectUriError",
    "is_loopback_http",
    "redirect_uri_matches",
    "validate_redirect_uri",
]
