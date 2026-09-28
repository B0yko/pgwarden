"""State-database operations for the authorization server: clients, codes,
refresh-token families, revoked access tokens, machine secrets and suspension.

Every single-use or state-changing operation is one atomic statement
(``UPDATE ... WHERE <still valid> RETURNING``), so two concurrent requests can
never both redeem the same code or rotate the same refresh token.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
from typing import Any

from pgwarden.state.conn import AnyConn


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclasses.dataclass(frozen=True)
class ClientRecord:
    client_id: str
    kind: str
    client_name: str
    redirect_uris: list[str]
    token_endpoint_auth_method: str
    client_secret_hash: str | None
    registered_ip: str | None
    metadata: dict[str, Any]
    created_at: dt.datetime
    last_used_at: dt.datetime | None


def _client_from_row(row: Any) -> ClientRecord:
    uris = row["redirect_uris"]
    meta = row["metadata"]
    return ClientRecord(
        client_id=row["client_id"],
        kind=row["kind"],
        client_name=row["client_name"],
        redirect_uris=list(json.loads(uris) if isinstance(uris, str) else uris),
        token_endpoint_auth_method=row["token_endpoint_auth_method"],
        client_secret_hash=row["client_secret_hash"],
        registered_ip=row["registered_ip"],
        metadata=dict(json.loads(meta) if isinstance(meta, str) else meta),
        created_at=row["created_at"],
        last_used_at=row["last_used_at"],
    )


async def get_client(conn: AnyConn, client_id: str) -> ClientRecord | None:
    row = await conn.fetchrow(
        "SELECT * FROM pgwarden.oauth_clients WHERE client_id = $1", client_id
    )
    return _client_from_row(row) if row is not None else None


async def list_clients(conn: AnyConn) -> list[ClientRecord]:
    rows = await conn.fetch("SELECT * FROM pgwarden.oauth_clients ORDER BY created_at DESC")
    return [_client_from_row(r) for r in rows]


async def insert_client(
    conn: AnyConn,
    *,
    client_id: str,
    kind: str,
    client_name: str,
    redirect_uris: list[str],
    token_endpoint_auth_method: str,
    client_secret_hash: str | None,
    registered_ip: str | None,
    metadata: dict[str, Any],
    now: dt.datetime,
) -> None:
    await conn.execute(
        "INSERT INTO pgwarden.oauth_clients (client_id, kind, client_name, redirect_uris, "
        "token_endpoint_auth_method, client_secret_hash, registered_ip, metadata, created_at) "
        "VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8::jsonb, $9)",
        client_id,
        kind,
        client_name,
        json.dumps(redirect_uris),
        token_endpoint_auth_method,
        client_secret_hash,
        registered_ip,
        json.dumps(metadata),
        now,
    )


async def upsert_cimd_client(
    conn: AnyConn, *, client_id: str, doc: dict[str, Any], now: dt.datetime
) -> None:
    await conn.execute(
        "INSERT INTO pgwarden.oauth_clients (client_id, kind, client_name, redirect_uris, "
        "token_endpoint_auth_method, metadata, created_at) "
        "VALUES ($1, 'cimd', $2, $3::jsonb, 'none', $4::jsonb, $5) "
        "ON CONFLICT (client_id) DO UPDATE SET client_name = EXCLUDED.client_name, "
        "redirect_uris = EXCLUDED.redirect_uris, metadata = EXCLUDED.metadata, "
        "created_at = EXCLUDED.created_at",
        client_id,
        str(doc["client_name"]),
        json.dumps(list(doc["redirect_uris"])),
        json.dumps(doc),
        now,
    )


async def touch_client(conn: AnyConn, client_id: str, now: dt.datetime) -> None:
    await conn.execute(
        "UPDATE pgwarden.oauth_clients SET last_used_at = $2 WHERE client_id = $1", client_id, now
    )


# -- authorization codes -------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class AuthCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    resource: str | None
    principal_subject: str
    identity_email: str | None
    upstream_login_at: dt.datetime


async def insert_auth_code(
    conn: AnyConn,
    *,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    resource: str | None,
    principal_subject: str,
    identity_email: str | None,
    upstream_login_at: dt.datetime,
    expires_at: dt.datetime,
) -> None:
    """Store a freshly issued authorization code (only its hash is kept)."""
    await conn.execute(
        "INSERT INTO pgwarden.auth_codes (code_hash, client_id, redirect_uri, code_challenge, "
        "resource, principal_subject, identity_email, upstream_login_at, expires_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        sha256_hex(code),
        client_id,
        redirect_uri,
        code_challenge,
        resource,
        principal_subject,
        identity_email,
        upstream_login_at,
        expires_at,
    )


async def consume_auth_code(conn: AnyConn, code: str, now: dt.datetime) -> AuthCode | None:
    """Atomically mark a code used; ``None`` if unknown, already used or expired."""
    row = await conn.fetchrow(
        "UPDATE pgwarden.auth_codes SET used_at = $2 "
        "WHERE code_hash = $1 AND used_at IS NULL AND expires_at > $2 "
        "RETURNING client_id, redirect_uri, code_challenge, resource, principal_subject, "
        "identity_email, upstream_login_at",
        sha256_hex(code),
        now,
    )
    if row is None:
        return None
    return AuthCode(
        client_id=row["client_id"],
        redirect_uri=row["redirect_uri"],
        code_challenge=row["code_challenge"],
        resource=row["resource"],
        principal_subject=row["principal_subject"],
        identity_email=row["identity_email"],
        upstream_login_at=row["upstream_login_at"],
    )


# -- refresh-token families -----------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Family:
    family_id: str
    principal_subject: str
    client_id: str
    login_at: dt.datetime
    absolute_expires_at: dt.datetime
    revoked_at: dt.datetime | None


async def create_family(
    conn: AnyConn,
    *,
    family_id: str,
    principal_subject: str,
    client_id: str,
    login_at: dt.datetime,
    absolute_expires_at: dt.datetime,
) -> None:
    await conn.execute(
        "INSERT INTO pgwarden.token_families (family_id, principal_subject, client_id, login_at, "
        "absolute_expires_at) VALUES ($1, $2, $3, $4, $5)",
        family_id,
        principal_subject,
        client_id,
        login_at,
        absolute_expires_at,
    )


async def insert_refresh_token(
    conn: AnyConn, *, token: str, family_id: str, issued_at: dt.datetime
) -> None:
    await conn.execute(
        "INSERT INTO pgwarden.refresh_tokens (token_hash, family_id, issued_at) "
        "VALUES ($1, $2, $3)",
        sha256_hex(token),
        family_id,
        issued_at,
    )


async def get_family(conn: AnyConn, family_id: str) -> Family | None:
    row = await conn.fetchrow(
        "SELECT * FROM pgwarden.token_families WHERE family_id = $1", family_id
    )
    if row is None:
        return None
    return Family(
        family_id=row["family_id"],
        principal_subject=row["principal_subject"],
        client_id=row["client_id"],
        login_at=row["login_at"],
        absolute_expires_at=row["absolute_expires_at"],
        revoked_at=row["revoked_at"],
    )


@dataclasses.dataclass(frozen=True)
class RefreshUse:
    """Result of presenting a refresh token: the family, and whether it was a reuse."""

    family: Family | None
    reused: bool


async def use_refresh_token(conn: AnyConn, token: str, now: dt.datetime) -> RefreshUse:
    """Atomically consume a refresh token.

    A second presentation of an already-used token is a reuse: the caller then
    revokes the whole family. An unknown token returns ``family=None``.
    """
    token_hash = sha256_hex(token)
    row = await conn.fetchrow(
        "UPDATE pgwarden.refresh_tokens SET used_at = $2 "
        "WHERE token_hash = $1 AND used_at IS NULL RETURNING family_id",
        token_hash,
        now,
    )
    if row is not None:
        return RefreshUse(await get_family(conn, row["family_id"]), reused=False)
    existing = await conn.fetchrow(
        "SELECT family_id FROM pgwarden.refresh_tokens WHERE token_hash = $1", token_hash
    )
    if existing is None:
        return RefreshUse(None, reused=False)
    return RefreshUse(await get_family(conn, existing["family_id"]), reused=True)


async def family_for_refresh_token(conn: AnyConn, token: str) -> Family | None:
    row = await conn.fetchrow(
        "SELECT family_id FROM pgwarden.refresh_tokens WHERE token_hash = $1", sha256_hex(token)
    )
    return await get_family(conn, row["family_id"]) if row is not None else None


async def revoke_family(conn: AnyConn, family_id: str, reason: str, now: dt.datetime) -> None:
    await conn.execute(
        "UPDATE pgwarden.token_families SET revoked_at = $3, revoke_reason = $2 "
        "WHERE family_id = $1 AND revoked_at IS NULL",
        family_id,
        reason,
        now,
    )


async def revoke_families_for_subject(
    conn: AnyConn, principal_subject: str, reason: str, now: dt.datetime
) -> int:
    result = await conn.execute(
        "UPDATE pgwarden.token_families SET revoked_at = $3, revoke_reason = $2 "
        "WHERE principal_subject = $1 AND revoked_at IS NULL",
        principal_subject,
        reason,
        now,
    )
    return int(result.split()[-1]) if result.startswith("UPDATE") else 0


# -- access-token revocation and suspension ---------------------------------------


async def revoke_jti(conn: AnyConn, jti: str, expires_at: dt.datetime) -> None:
    await conn.execute(
        "INSERT INTO pgwarden.revoked_jtis (jti, expires_at) VALUES ($1, $2) "
        "ON CONFLICT (jti) DO NOTHING",
        jti,
        expires_at,
    )


async def access_denial_reason(conn: AnyConn, *, jti: str, role_name: str) -> str | None:
    """One round trip: is this access token revoked, or its principal suspended?"""
    row = await conn.fetchrow(
        "SELECT EXISTS (SELECT 1 FROM pgwarden.revoked_jtis WHERE jti = $1) AS revoked, "
        "EXISTS (SELECT 1 FROM pgwarden.people_status WHERE person_role = $2 AND suspended) "
        "AS suspended",
        jti,
        role_name,
    )
    if row is None:  # pragma: no cover - the query always returns a row
        return None
    if row["revoked"]:
        return "token has been revoked"
    if row["suspended"]:
        return "identity is suspended"
    return None


async def is_suspended(conn: AnyConn, role_name: str) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM pgwarden.people_status "
            "WHERE person_role = $1 AND suspended)",
            role_name,
        )
    )


# -- machine secrets -------------------------------------------------------------


async def set_machine_secret(conn: AnyConn, name: str, secret: str, now: dt.datetime) -> None:
    await conn.execute(
        "INSERT INTO pgwarden.machines (name, secret_hash, rotated_at) VALUES ($1, $2, $3) "
        "ON CONFLICT (name) DO UPDATE SET secret_hash = EXCLUDED.secret_hash, "
        "rotated_at = EXCLUDED.rotated_at",
        name,
        sha256_hex(secret),
        now,
    )


async def machine_secret_hash(conn: AnyConn, name: str) -> str | None:
    value = await conn.fetchval("SELECT secret_hash FROM pgwarden.machines WHERE name = $1", name)
    return str(value) if value is not None else None


__all__ = [
    "AuthCode",
    "ClientRecord",
    "Family",
    "RefreshUse",
    "access_denial_reason",
    "consume_auth_code",
    "create_family",
    "family_for_refresh_token",
    "get_client",
    "get_family",
    "insert_auth_code",
    "insert_client",
    "insert_refresh_token",
    "is_suspended",
    "list_clients",
    "machine_secret_hash",
    "revoke_families_for_subject",
    "revoke_family",
    "revoke_jti",
    "set_machine_secret",
    "sha256_hex",
    "touch_client",
    "upsert_cimd_client",
    "use_refresh_token",
]
