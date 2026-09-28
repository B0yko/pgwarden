"""Unit tests for principal resolution (no Postgres)."""

from __future__ import annotations

from pathlib import Path

from pgwarden.config import load_config
from pgwarden.identity import machine_subject, person_subject, resolve_principal

REPO_ROOT = Path(__file__).parent.parent.parent


def _demo():
    return load_config(REPO_ROOT / "demo" / "pgwarden.yaml")


def test_resolve_person_alice_is_masked() -> None:
    p = resolve_principal(_demo(), person_subject("alice"))
    assert p is not None
    assert p.kind == "person"
    assert p.role_name == "pw_u_alice"
    assert p.masked is True  # analyst is not a raw_access bundle
    assert "analyst" in p.bundles


def test_resolve_person_bob_is_raw_with_writer() -> None:
    p = resolve_principal(_demo(), person_subject("bob"))
    assert p is not None
    assert p.masked is False  # support is a raw_access bundle
    assert p.writer == "support_writer"


def test_resolve_machine() -> None:
    p = resolve_principal(_demo(), machine_subject("nightly-report"))
    assert p is not None
    assert p.kind == "machine"
    assert p.role_name == "pw_m_nightly_report"


def test_unmapped_subject_is_none() -> None:
    assert resolve_principal(_demo(), person_subject("nobody")) is None
    assert resolve_principal(_demo(), "garbage") is None
    assert resolve_principal(_demo(), machine_subject("no-machine")) is None
