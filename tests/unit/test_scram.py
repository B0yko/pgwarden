"""Unit tests for pgwarden.db.scram.

The verifier *format* and Postgres's acceptance of it were verified against
a real Postgres 16 by experiment (see docs/adr/0002-login-role-per-person.md); these
tests cover the pure-Python derivation logic without needing a database.
"""

from __future__ import annotations

import re

from pgwarden.db.scram import (
    build_verifier,
    derive_password,
    derive_salt,
    role_verifier,
    verifier_for_password,
)

VERIFIER_RE = re.compile(
    r"^SCRAM-SHA-256\$\d+:[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$"
)


def test_derive_password_is_deterministic() -> None:
    a = derive_password("secret", "pw_u_alice")
    b = derive_password("secret", "pw_u_alice")
    assert a == b
    assert re.fullmatch(r"[0-9a-f]{64}", a)


def test_derive_password_varies_by_role_and_secret() -> None:
    assert derive_password("secret", "pw_u_alice") != derive_password("secret", "pw_u_bob")
    assert derive_password("secret1", "pw_u_alice") != derive_password("secret2", "pw_u_alice")


def test_derive_salt_is_deterministic_and_distinct_from_password() -> None:
    salt_a = derive_salt("secret", "pw_u_alice")
    salt_b = derive_salt("secret", "pw_u_alice")
    assert salt_a == salt_b
    assert len(salt_a) == 16
    assert salt_a.hex() != derive_password("secret", "pw_u_alice")


def test_build_verifier_matches_postgres_format() -> None:
    verifier = build_verifier("deadbeef" * 8, b"0" * 16)
    assert VERIFIER_RE.match(verifier)


def test_role_verifier_is_idempotent() -> None:
    pw1, verifier1 = role_verifier("secret", "pw_u_alice")
    pw2, verifier2 = role_verifier("secret", "pw_u_alice")
    assert pw1 == pw2
    assert verifier1 == verifier2
    assert VERIFIER_RE.match(verifier1)


def test_role_verifier_never_contains_the_password() -> None:
    password, verifier = role_verifier("some-role-secret", "pw_u_alice")
    assert password not in verifier


def test_verifier_for_password_uses_a_random_salt() -> None:
    v1 = verifier_for_password("operator-chosen-password")
    v2 = verifier_for_password("operator-chosen-password")
    assert VERIFIER_RE.match(v1)
    assert VERIFIER_RE.match(v2)
    assert v1 != v2  # different random salts each call
