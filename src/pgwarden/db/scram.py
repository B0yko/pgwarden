"""Build pre-computed SCRAM-SHA-256 password verifiers (RFC 5802 / RFC 7677).

pgwarden never sends a plaintext password to Postgres in SQL text. Instead it
computes the verifier Postgres itself would have stored after
``PASSWORD 'plaintext'`` with ``password_encryption = scram-sha-256``, and
sets it with ``CREATE``/``ALTER ROLE ... PASSWORD '<verifier>'``. Postgres
recognizes an already-encrypted value by its ``SCRAM-SHA-256$`` prefix and
stores it verbatim instead of re-hashing it (verified by experiment: the
stored ``pg_authid.rolpassword`` for a role created this way is byte-for-byte
the string this module builds).

The salt is derived deterministically from the same role secret and role
name that produce the password, so re-running provisioning with an unchanged
secret reproduces an identical verifier and changes nothing (idempotency).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

DEFAULT_ITERATIONS = 4096
SALT_BYTES = 16


def derive_password(role_secret: str, role_name: str) -> str:
    """The role's login password: HMAC-SHA256(role_secret, role_name) as hex."""
    return hmac.new(
        role_secret.encode("utf-8"), role_name.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def derive_salt(role_secret: str, role_name: str) -> bytes:
    """A deterministic 16-byte salt, distinct from the password derivation above."""
    digest = hashlib.sha256(f"pgwarden-scram-salt:{role_secret}:{role_name}".encode()).digest()
    return digest[:SALT_BYTES]


def build_verifier(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> str:
    """The Postgres SCRAM-SHA-256 verifier text for ``password`` and ``salt``.

    Format (matches ``pg_authid.rolpassword`` exactly):
    ``SCRAM-SHA-256$<iterations>:<salt b64>$<StoredKey b64>:<ServerKey b64>``
    """
    salted_password = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=32
    )
    client_key = hmac.new(salted_password, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted_password, b"Server Key", hashlib.sha256).digest()
    salt_b64 = base64.b64encode(salt).decode("ascii")
    stored_b64 = base64.b64encode(stored_key).decode("ascii")
    server_b64 = base64.b64encode(server_key).decode("ascii")
    return f"SCRAM-SHA-256${iterations}:{salt_b64}${stored_b64}:{server_b64}"


def role_verifier(role_secret: str, role_name: str) -> tuple[str, str]:
    """Return ``(password, verifier)`` for ``role_name`` derived from ``role_secret``.

    ``password`` is what the gateway would use to connect as this role
    (never written to SQL text); ``verifier`` is what provisioning sets as
    the role's password. Both are deterministic in ``role_secret`` and
    ``role_name``, so re-deriving them is idempotent.
    """
    password = derive_password(role_secret, role_name)
    salt = derive_salt(role_secret, role_name)
    verifier = build_verifier(password, salt)
    return password, verifier


def verifier_for_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Build a verifier for an arbitrary, operator-chosen plaintext password.

    Unlike :func:`role_verifier`, the salt is random each call: this is for
    the state database's ``pgwarden_app`` role, whose password is whatever
    the operator put in ``PGWARDEN_STATE_DSN``, not something re-derived
    from a secret on every run. Callers only need this when they are about
    to change the password (typically after a login probe fails); a
    fresh salt each time it actually changes is fine.
    """
    salt = os.urandom(SALT_BYTES)
    return build_verifier(password, salt, iterations)
