"""Server-side login sessions for the gateway's own pages (/admin, /approve).

The cookie holds a random id; the database stores its sha256, the upstream
identity, a per-session CSRF token, and idle (30 min) and absolute (8 h)
expiry, both enforced on every read.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import secrets

from pgwarden.identity import UpstreamIdentity
from pgwarden.state.conn import AnyConn

SESSION_COOKIE = "pgw_session"
IDLE_TIMEOUT_S = 30 * 60
ABSOLUTE_TIMEOUT_S = 8 * 3600


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclasses.dataclass(frozen=True)
class WebSession:
    identity: UpstreamIdentity
    csrf_token: str
    created_at: dt.datetime
    expires_at: dt.datetime


async def create_session(
    conn: AnyConn, identity: UpstreamIdentity, now: dt.datetime
) -> tuple[str, WebSession]:
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    expires = now + dt.timedelta(seconds=ABSOLUTE_TIMEOUT_S)
    await conn.execute(
        "INSERT INTO pgwarden.web_sessions (id_hash, provider, subject, email, email_verified, "
        "csrf_token, created_at, last_seen_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8)",
        _hash(raw),
        identity.provider,
        identity.subject,
        identity.email,
        identity.email_verified,
        csrf,
        now,
        expires,
    )
    return raw, WebSession(identity=identity, csrf_token=csrf, created_at=now, expires_at=expires)


async def load_session(conn: AnyConn, raw: str | None, now: dt.datetime) -> WebSession | None:
    """The live session for this cookie value (touching its idle timer), or ``None``."""
    if not raw:
        return None
    row = await conn.fetchrow(
        "UPDATE pgwarden.web_sessions SET last_seen_at = $2 "
        "WHERE id_hash = $1 AND revoked_at IS NULL AND expires_at > $2 "
        "AND last_seen_at > $2 - make_interval(secs => $3) "
        "RETURNING provider, subject, email, email_verified, csrf_token, created_at, expires_at",
        _hash(raw),
        now,
        float(IDLE_TIMEOUT_S),
    )
    if row is None:
        return None
    return WebSession(
        identity=UpstreamIdentity(
            provider=row["provider"],
            subject=row["subject"],
            email=row["email"],
            email_verified=bool(row["email_verified"]),
        ),
        csrf_token=row["csrf_token"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
    )


async def revoke_session(conn: AnyConn, raw: str | None, now: dt.datetime) -> None:
    if raw:
        await conn.execute(
            "UPDATE pgwarden.web_sessions SET revoked_at = $2 WHERE id_hash = $1", _hash(raw), now
        )


__all__ = [
    "ABSOLUTE_TIMEOUT_S",
    "IDLE_TIMEOUT_S",
    "SESSION_COOKIE",
    "WebSession",
    "create_session",
    "load_session",
    "revoke_session",
]
