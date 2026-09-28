"""Unit tests for pgwarden.secrets."""

from __future__ import annotations

from pathlib import Path

import pytest

from pgwarden.secrets import SecretError, read_secret


def test_reads_from_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PGWARDEN_TEST_SECRET", "value-from-env")
    assert read_secret("PGWARDEN_TEST_SECRET") == "value-from-env"


def test_reads_from_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("PGWARDEN_TEST_SECRET", raising=False)
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("value-from-file\n", encoding="utf-8")
    monkeypatch.setenv("PGWARDEN_TEST_SECRET_FILE", str(secret_file))
    assert read_secret("PGWARDEN_TEST_SECRET") == "value-from-file"


def test_strips_only_one_trailing_newline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("value\n\n", encoding="utf-8")
    monkeypatch.delenv("PGWARDEN_TEST_SECRET", raising=False)
    monkeypatch.setenv("PGWARDEN_TEST_SECRET_FILE", str(secret_file))
    assert read_secret("PGWARDEN_TEST_SECRET") == "value\n"


def test_no_trailing_newline_untouched(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("value", encoding="utf-8")
    monkeypatch.delenv("PGWARDEN_TEST_SECRET", raising=False)
    monkeypatch.setenv("PGWARDEN_TEST_SECRET_FILE", str(secret_file))
    assert read_secret("PGWARDEN_TEST_SECRET") == "value"


def test_both_set_is_an_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("value", encoding="utf-8")
    monkeypatch.setenv("PGWARDEN_TEST_SECRET", "value-from-env")
    monkeypatch.setenv("PGWARDEN_TEST_SECRET_FILE", str(secret_file))
    with pytest.raises(SecretError):
        read_secret("PGWARDEN_TEST_SECRET")


def test_missing_required_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PGWARDEN_TEST_SECRET", raising=False)
    monkeypatch.delenv("PGWARDEN_TEST_SECRET_FILE", raising=False)
    with pytest.raises(SecretError):
        read_secret("PGWARDEN_TEST_SECRET")


def test_missing_optional_returns_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PGWARDEN_TEST_SECRET", raising=False)
    monkeypatch.delenv("PGWARDEN_TEST_SECRET_FILE", raising=False)
    assert read_secret("PGWARDEN_TEST_SECRET", required=False) is None
    assert read_secret("PGWARDEN_TEST_SECRET", required=False, default="fallback") == "fallback"


def test_missing_file_is_an_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("PGWARDEN_TEST_SECRET", raising=False)
    monkeypatch.setenv("PGWARDEN_TEST_SECRET_FILE", str(tmp_path / "does-not-exist.txt"))
    with pytest.raises(SecretError):
        read_secret("PGWARDEN_TEST_SECRET")
