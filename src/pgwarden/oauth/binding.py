"""Map an upstream identity to config entries, enforcing email binding.

Config names each identity as ``{subject}``, ``{email}`` or (Entra) ``{oid, tid}``.
Subjects and Entra ids are immutable and match directly. An email entry matches
only when the provider asserts the email is verified; the first time a verified
email matches, pgwarden records the provider's immutable subject for it
(``pgwarden.email_bindings``), and afterwards refuses the same email arriving
with a different subject. The same rule applies to ``people``, ``approvers`` and
``admins``.
"""

from __future__ import annotations

import datetime as dt

from pgwarden.config import Config, IdentityRef, PersonConfig
from pgwarden.identity import UpstreamIdentity, ref_matches
from pgwarden.state.conn import AnyConn


async def _email_binding_holds(
    conn: AnyConn, ident: UpstreamIdentity, email: str, now: dt.datetime
) -> bool:
    key = email.lower()
    await conn.execute(
        "INSERT INTO pgwarden.email_bindings (provider, email, subject, bound_at) "
        "VALUES ($1, $2, $3, $4) ON CONFLICT (provider, email) DO NOTHING",
        ident.provider,
        key,
        ident.subject,
        now,
    )
    bound = await conn.fetchval(
        "SELECT subject FROM pgwarden.email_bindings WHERE provider = $1 AND email = $2",
        ident.provider,
        key,
    )
    return bool(bound == ident.subject)


async def matches(
    conn: AnyConn, ref: IdentityRef, ident: UpstreamIdentity, now: dt.datetime
) -> bool:
    """``ref_matches`` plus the email-binding rule for email-shaped entries."""
    if not ref_matches(ref, ident):
        return False
    if ref.email is not None:
        return await _email_binding_holds(conn, ident, ref.email, now)
    return True


async def any_matches(
    conn: AnyConn, refs: list[IdentityRef], ident: UpstreamIdentity, now: dt.datetime
) -> bool:
    for ref in refs:
        if await matches(conn, ref, ident, now):
            return True
    return False


async def resolve_person(
    conn: AnyConn, config: Config, ident: UpstreamIdentity, now: dt.datetime
) -> PersonConfig | None:
    """The configured person this login is, or ``None`` (unmapped: 403, ask an admin)."""
    for person in config.people:
        if await matches(conn, person.identity, ident, now):
            await conn.execute(
                "INSERT INTO pgwarden.identity_bindings (provider, subject, person_role, email) "
                "VALUES ($1, $2, $3, $4) ON CONFLICT (provider, subject) DO NOTHING",
                ident.provider,
                ident.subject,
                person.role,
                ident.email,
            )
            return person
    return None


__all__ = ["any_matches", "matches", "resolve_person"]
