"""Unit tests for masking's config-only planning helpers (no Postgres)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pgwarden.config import load_config
from pgwarden.db.masking import (
    MaskingError,
    _reject_public,
    _tagged_tables,
    _writer_bundle_pairs,
    masking_checks,
)

REPO_ROOT = Path(__file__).parent.parent.parent


def _demo_config() -> object:
    return load_config(REPO_ROOT / "demo" / "pgwarden.yaml")


def test_reject_public_is_case_insensitive() -> None:
    _reject_public({"analyst", "reporting"})  # no raise
    for name in ("public", "PUBLIC", "Public"):
        with pytest.raises(MaskingError, match="PUBLIC"):
            _reject_public({name})


def test_tagged_tables_covers_columns_and_view_grants() -> None:
    tables = _tagged_tables(_demo_config())
    assert ("public", "customers") in tables
    # sorted and de-duplicated
    assert tables == sorted(set(tables))


def test_writer_bundle_pairs_maps_writer_to_union_of_bundles() -> None:
    pairs = _writer_bundle_pairs(_demo_config())
    assert pairs["support_writer"] == {"support"}


def test_masking_checks_returns_the_three_checks() -> None:
    checks = masking_checks(_demo_config())
    assert len(checks) == 3
    names = {c.__name__ for c in checks}
    assert names == {
        "check_masking_invariant",
        "check_masked_view_grants",
        "check_writer_subset",
    }
