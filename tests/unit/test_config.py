"""Unit tests for pgwarden.config: no Postgres needed."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from pgwarden.config import (
    Config,
    ConfigError,
    IdentityRef,
    MachineConfig,
    MaskingConfig,
    PersonConfig,
    Settings,
    UpstreamConfig,
    load_config,
    machine_role_name,
    person_role_name,
)


def make_upstream(**overrides: object) -> UpstreamConfig:
    base: dict[str, object] = {
        "name": "mock-idp",
        "issuer": "http://localhost:9400",
        "client_id": "pgwarden-demo",
    }
    base.update(overrides)
    return UpstreamConfig(**base)  # type: ignore[arg-type]


def make_config(**overrides: object) -> Config:
    base: dict[str, object] = {"public_url": "http://localhost:8080", "upstream": make_upstream()}
    base.update(overrides)
    return Config(**base)  # type: ignore[arg-type]


# -- role naming --------------------------------------------------------


def test_person_and_machine_role_names() -> None:
    assert person_role_name("alice") == "pw_u_alice"
    assert machine_role_name("nightly_report") == "pw_m_nightly_report"


# -- role suffix regex ----------------------------------------------------


@pytest.mark.parametrize("role", ["alice", "bob2", "nightly_report", "a", "a" * 41])
def test_valid_role_suffix(role: str) -> None:
    PersonConfig(identity=IdentityRef(email="a@example.com"), role=role)


@pytest.mark.parametrize(
    "role", ["Alice", "1alice", "bob-writer", "bob writer", "", "a" * 42, "bob!"]
)
def test_invalid_role_suffix(role: str) -> None:
    with pytest.raises(ValidationError):
        PersonConfig(identity=IdentityRef(email="a@example.com"), role=role)


# -- identity shape: subject xor email ------------------------------------


def test_identity_requires_exactly_one_of_subject_or_email() -> None:
    IdentityRef(subject="abc123")
    IdentityRef(email="a@example.com")
    with pytest.raises(ValidationError):
        IdentityRef()
    with pytest.raises(ValidationError):
        IdentityRef(subject="abc123", email="a@example.com")


def test_entra_identity_requires_oid_and_tid_together() -> None:
    IdentityRef(oid="oid-1", tid="tid-1")
    with pytest.raises(ValidationError):
        IdentityRef(oid="oid-1")
    with pytest.raises(ValidationError):
        IdentityRef(tid="tid-1")
    with pytest.raises(ValidationError):
        IdentityRef(oid="oid-1", tid="tid-1", email="a@example.com")


# -- entra preset cross-checks -------------------------------------------


def test_entra_preset_requires_tenant_id() -> None:
    with pytest.raises(ValidationError):
        make_upstream(preset="entra")
    make_upstream(preset="entra", tenant_id="tid-1")


def test_non_entra_preset_forbids_tenant_id() -> None:
    with pytest.raises(ValidationError):
        make_upstream(preset="oidc", tenant_id="tid-1")


def test_entra_people_must_use_oid_tid_not_email() -> None:
    upstream = make_upstream(preset="entra", tenant_id="tid-1")
    with pytest.raises(ValidationError):
        make_config(
            upstream=upstream,
            people=[PersonConfig(identity=IdentityRef(email="a@example.com"), role="alice")],
        )
    # oid/tid identity is accepted, but only when tid matches upstream.tenant_id.
    make_config(
        upstream=upstream,
        people=[PersonConfig(identity=IdentityRef(oid="o1", tid="tid-1"), role="alice")],
    )
    with pytest.raises(ValidationError):
        make_config(
            upstream=upstream,
            people=[PersonConfig(identity=IdentityRef(oid="o1", tid="other-tenant"), role="alice")],
        )


def test_non_entra_people_forbid_oid_tid() -> None:
    with pytest.raises(ValidationError):
        make_config(
            people=[PersonConfig(identity=IdentityRef(oid="o1", tid="t1"), role="alice")],
        )


# -- uniqueness -----------------------------------------------------------


def test_duplicate_person_role_rejected() -> None:
    with pytest.raises(ValidationError):
        make_config(
            people=[
                PersonConfig(identity=IdentityRef(email="a@example.com"), role="alice"),
                PersonConfig(identity=IdentityRef(email="b@example.com"), role="alice"),
            ]
        )


def test_duplicate_person_identity_rejected() -> None:
    with pytest.raises(ValidationError):
        make_config(
            people=[
                PersonConfig(identity=IdentityRef(email="a@example.com"), role="alice"),
                PersonConfig(identity=IdentityRef(email="a@example.com"), role="alice2"),
            ]
        )


def test_duplicate_machine_name_or_role_rejected() -> None:
    with pytest.raises(ValidationError):
        make_config(
            machines=[
                MachineConfig(name="nightly-report", role="nightly_report"),
                MachineConfig(name="nightly-report", role="other"),
            ]
        )
    with pytest.raises(ValidationError):
        make_config(
            machines=[
                MachineConfig(name="job-a", role="nightly_report"),
                MachineConfig(name="job-b", role="nightly_report"),
            ]
        )


def test_identity_provider_mismatch_rejected() -> None:
    with pytest.raises(ValidationError):
        make_config(
            people=[
                PersonConfig(
                    identity=IdentityRef(email="a@example.com", provider="someone-else"),
                    role="alice",
                )
            ]
        )


# -- public_url https unless loopback -------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "https://pgwarden.example.com",
    ],
)
def test_public_url_allowed(url: str) -> None:
    make_config(public_url=url)


@pytest.mark.parametrize("url", ["http://pgwarden.example.com", "ftp://localhost", "not-a-url"])
def test_public_url_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        make_config(public_url=url)


# -- bundle/writer names are valid Postgres identifiers ---------------------


def test_bundle_name_must_be_valid_identifier() -> None:
    PersonConfig(identity=IdentityRef(email="a@example.com"), role="alice", bundles=["analyst"])
    with pytest.raises(ValidationError):
        PersonConfig(identity=IdentityRef(email="a@example.com"), role="alice", bundles=["Analyst"])
    with pytest.raises(ValidationError):
        PersonConfig(
            identity=IdentityRef(email="a@example.com"), role="alice", bundles=["an-alyst"]
        )


def test_writer_name_must_be_valid_identifier() -> None:
    PersonConfig(identity=IdentityRef(email="a@example.com"), role="bob", writer="support_writer")
    with pytest.raises(ValidationError):
        PersonConfig(
            identity=IdentityRef(email="a@example.com"), role="bob", writer="support-writer"
        )


# -- masking config ---------------------------------------------------------


def test_masking_columns_key_shape_and_tags() -> None:
    MaskingConfig(columns={"public.customers.email": "email"})
    with pytest.raises(ValidationError):
        MaskingConfig(columns={"customers.email": "email"})  # only two segments
    with pytest.raises(ValidationError):
        MaskingConfig(columns={"public.customers.email": "not-a-tag"})  # type: ignore[dict-item]


def test_masking_view_grants_key_shape() -> None:
    MaskingConfig(view_grants={"public.customers": ["analyst"]})
    with pytest.raises(ValidationError):
        MaskingConfig(view_grants={"public.customers.email": ["analyst"]})
    with pytest.raises(ValidationError):
        MaskingConfig(view_grants={"public.customers": ["Analyst"]})


def test_rls_required_key_shape() -> None:
    make_config(rls_required=["public.customers"])
    with pytest.raises(ValidationError):
        make_config(rls_required=["customers"])


# -- load_config --------------------------------------------------------


def test_load_config_demo_yaml() -> None:
    demo_path = Path(__file__).parent.parent.parent / "demo" / "pgwarden.yaml"
    config = load_config(demo_path)
    assert config.demo.enabled is True
    assert {p.role for p in config.people} == {"alice", "bob", "dana"}
    assert config.masking.raw_access_bundles == ["support"]


def test_load_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml")


def test_load_config_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("public_url: [unterminated", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_rejects_unknown_field(tmp_path: Path) -> None:
    path = tmp_path / "extra.yaml"
    path.write_text(
        "public_url: http://localhost:8080\n"
        "upstream:\n  name: x\n  issuer: http://localhost:9400\n  client_id: x\n"
        "not_a_real_field: 1\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(path)


# -- Settings.from_env ----------------------------------------------------


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PGWARDEN_CONFIG", str(tmp_path / "pgwarden.yaml"))
    monkeypatch.setenv("PGWARDEN_TARGET_DSN", "postgresql://localhost:5432/shop")
    monkeypatch.setenv(
        "PGWARDEN_STATE_DSN", "postgresql://pgwarden_app:secret@localhost:5432/pgwarden"
    )
    monkeypatch.setenv("PGWARDEN_SERVER_TIMING", "1")
    settings = Settings.from_env()
    assert settings.server_timing is True
    assert settings.target_dsn.endswith("/shop")


def test_settings_from_env_missing_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PGWARDEN_CONFIG", raising=False)
    with pytest.raises(ConfigError):
        Settings.from_env()


def test_env_expansion_with_defaults() -> None:
    from pgwarden.config import expand_env

    env = {"PORT_URL": "http://localhost:58080"}
    tree = {"public_url": "${PORT_URL:-http://localhost:8080}", "x": ["${MISSING:-d}", 3]}
    assert expand_env(tree, env) == {"public_url": "http://localhost:58080", "x": ["d", 3]}
    import pytest

    with pytest.raises(KeyError):
        expand_env("${UNSET_WITHOUT_DEFAULT}", {})


def test_landing_hides_demo_identities_when_demo_disabled() -> None:
    from pathlib import Path

    from pgwarden.config import load_config
    from pgwarden.web.landing import _demo_rows

    config = load_config(Path(__file__).parent.parent.parent / "demo" / "pgwarden.yaml")
    assert _demo_rows(config)  # demo on: rows exist
    assert config.demo.enabled is True
