"""The principal: who a verified token belongs to, and what Postgres role,
bundles, writer role, masking status and rate limits apply to them.

The access-token ``sub`` is a stable principal key, never an email:
``person:<role-suffix>`` or ``machine:<name>`` (so a re-used email cannot
silently move to a different role). :func:`resolve_principal` maps that key back
to the configured person/machine and derives everything the MCP tools and the
auth middleware need.
"""

from __future__ import annotations

import dataclasses
from typing import Literal

from pgwarden.config import Config, IdentityRef, machine_role_name, person_role_name

PrincipalKind = Literal["person", "machine"]


@dataclasses.dataclass(frozen=True)
class UpstreamIdentity:
    """An identity asserted by the upstream IdP after a browser login.

    ``subject`` is the immutable identifier: the OIDC ``sub``, the GitHub
    numeric user id, or ``<tid>:<oid>`` for Entra. ``email_verified`` is what the
    provider asserts; an email-shaped config entry only matches a verified email.
    """

    provider: str
    subject: str
    email: str | None
    email_verified: bool


def entra_subject(tid: str, oid: str) -> str:
    return f"{tid}:{oid}"


def ref_matches(ref: IdentityRef, ident: UpstreamIdentity) -> bool:
    """Pure matching of a config identity entry against an upstream identity.

    No state: the email-to-immutable-id binding (refuse the same email with a
    different id after the first match) is enforced on top of this by the
    login layer (``pgwarden.oauth.binding``).
    """
    if ref.provider is not None and ref.provider != ident.provider:
        return False
    if ref.oid is not None and ref.tid is not None:
        return ident.subject == entra_subject(ref.tid, ref.oid)
    if ref.subject is not None:
        return ident.subject == ref.subject
    if ref.email is not None:
        return (
            ident.email_verified
            and ident.email is not None
            and ident.email.lower() == ref.email.lower()
        )
    return False


@dataclasses.dataclass(frozen=True)
class Principal:
    """A verified caller. ``role_name`` is the Postgres login role to connect as."""

    kind: PrincipalKind
    subject: str  # the token `sub`: person:<suffix> or machine:<name>
    role_name: str  # pw_u_<suffix> / pw_m_<suffix>
    email: str | None
    bundles: tuple[str, ...]
    writer: str | None
    masked: bool
    queries_per_minute: int
    proposals_per_hour: int


def person_subject(role_suffix: str) -> str:
    return f"person:{role_suffix}"


def machine_subject(name: str) -> str:
    return f"machine:{name}"


def _is_masked(bundles: tuple[str, ...], config: Config) -> bool:
    return not (set(bundles) & set(config.masking.raw_access_bundles))


def resolve_principal(config: Config, subject: str) -> Principal | None:
    """Map a token ``sub`` to a :class:`Principal`, or ``None`` if unmapped.

    An unmapped subject is a valid token whose identity is not (or no longer)
    listed in config; the caller turns that into a 403 telling the user to ask
    an admin.
    """
    kind, sep, ident = subject.partition(":")
    if not sep:
        return None
    if kind == "person":
        for person in config.people:
            if person.role == ident:
                bundles = tuple(person.bundles)
                return Principal(
                    kind="person",
                    subject=subject,
                    role_name=person_role_name(person.role),
                    email=person.identity.email,
                    bundles=bundles,
                    writer=person.writer,
                    masked=_is_masked(bundles, config),
                    queries_per_minute=config.limits.queries_per_minute,
                    proposals_per_hour=config.limits.proposals_per_hour,
                )
        return None
    if kind == "machine":
        for machine in config.machines:
            if machine.name == ident:
                bundles = tuple(machine.bundles)
                overrides = machine.rate_overrides
                qpm = config.limits.queries_per_minute
                pph = config.limits.proposals_per_hour
                if overrides is not None:
                    if overrides.queries_per_minute is not None:
                        qpm = overrides.queries_per_minute
                    if overrides.proposals_per_hour is not None:
                        pph = overrides.proposals_per_hour
                return Principal(
                    kind="machine",
                    subject=subject,
                    role_name=machine_role_name(machine.role),
                    email=None,
                    bundles=bundles,
                    writer=None,
                    masked=_is_masked(bundles, config),
                    queries_per_minute=qpm,
                    proposals_per_hour=pph,
                )
        return None
    return None


__all__ = [
    "Principal",
    "PrincipalKind",
    "UpstreamIdentity",
    "entra_subject",
    "ref_matches",
    "machine_subject",
    "person_subject",
    "resolve_principal",
]
