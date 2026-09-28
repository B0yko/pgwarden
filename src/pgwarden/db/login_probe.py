"""Detect password staleness by trying to log in, instead of reading ``pg_authid``.

Provisioning (``pgwarden roles sync``, ``pgwarden db init``) runs with an
admin that only needs ``CREATEROLE``; ``pg_authid`` is unreadable to such an
admin (verified by experiment: ``permission denied for table pg_authid``).
A short-lived connection attempt with the role's own derived or configured
password is the only way to tell whether its stored verifier still matches.
"""

from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

import asyncpg

DEFAULT_PROBE_TIMEOUT_S = 5.0


def probe_dsn(admin_dsn: str, role: str, password: str) -> str:
    """A DSN with the same host/port/database as ``admin_dsn`` but ``role``'s credentials."""
    parts = urlsplit(admin_dsn)
    host = parts.hostname or "localhost"
    port = f":{parts.port}" if parts.port else ""
    netloc = f"{quote(role, safe='')}:{quote(password, safe='')}@{host}{port}"
    path = parts.path or "/postgres"
    return urlunsplit((parts.scheme or "postgresql", netloc, path, parts.query, ""))


async def password_is_current(
    admin_dsn: str, role: str, password: str, *, timeout: float = DEFAULT_PROBE_TIMEOUT_S
) -> bool:
    """True if ``role`` can already log in with ``password`` (nothing to fix).

    False for a wrong password or for a role that is currently ``NOLOGIN``
    (both raise ``InvalidAuthorizationSpecificationError``, the parent class
    of ``InvalidPasswordError`` -- verified by experiment). Any other error
    (network, unreachable host) propagates, since provisioning cannot
    reliably proceed without knowing the real state.
    """
    dsn = probe_dsn(admin_dsn, role, password)
    try:
        conn = await asyncpg.connect(dsn, timeout=timeout)
    except asyncpg.InvalidAuthorizationSpecificationError:
        return False
    await conn.close()
    return True
