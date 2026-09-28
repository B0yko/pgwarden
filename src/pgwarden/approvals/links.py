"""HMAC-signed approval links.

A link is ``<public_url>/approve/<proposal id>?exp=<unix seconds>&sig=<hex>``,
signed with a key derived from ``PGWARDEN_SESSION_SECRET`` and valid for 24 h.
A valid link only opens the approval page, which still requires an OIDC login as
a configured approver; the link grants nothing by itself.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
from urllib.parse import urlencode

LINK_TTL_S = 24 * 3600
_LINK_KEY_LABEL = b"pgwarden-approval-link-v1"
_BINDING_KEY_LABEL = b"pgwarden-proposal-binding-v1"


def _derive(session_secret: str, label: bytes) -> bytes:
    return hmac.new(session_secret.encode("utf-8"), label, hashlib.sha256).digest()


def _signature(session_secret: str, proposal_id: str, exp: int) -> str:
    key = _derive(session_secret, _LINK_KEY_LABEL)
    return hmac.new(key, f"{proposal_id}.{exp}".encode(), hashlib.sha256).hexdigest()


def approval_link(
    public_url: str, session_secret: str, proposal_id: str, *, now: dt.datetime
) -> str:
    exp = int(now.timestamp()) + LINK_TTL_S
    query = urlencode({"exp": exp, "sig": _signature(session_secret, proposal_id, exp)})
    return f"{public_url.rstrip('/')}/approve/{proposal_id}?{query}"


def verify_link(
    session_secret: str, proposal_id: str, exp: str | None, sig: str | None, *, now: dt.datetime
) -> bool:
    """Constant-time signature check plus expiry."""
    if not exp or not sig or not exp.isdigit():
        return False
    expected = _signature(session_secret, proposal_id, int(exp))
    if not hmac.compare_digest(expected, sig):
        return False
    return int(now.timestamp()) < int(exp)


def binding_hmac(session_secret: str, sql: str, params_json: str, writer_role: str) -> str:
    """HMAC-SHA256 over (SQL, canonical parameters, writer role)."""
    key = _derive(session_secret, _BINDING_KEY_LABEL)
    message = b"\x1f".join(p.encode("utf-8") for p in (sql, params_json, writer_role))
    return hmac.new(key, message, hashlib.sha256).hexdigest()


__all__ = ["LINK_TTL_S", "approval_link", "binding_hmac", "verify_link"]
