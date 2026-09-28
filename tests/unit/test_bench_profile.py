"""The benchmark compose profile, its two gateway configs and the host wrapper stay in step."""

from __future__ import annotations

import inspect
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from pgwarden.bench.load import PEAK_CONNECTIONS_SQL
from pgwarden.cli import bench_latency_command, bench_load_command
from pgwarden.config import load_config

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    loaded = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _default_services(compose: dict[str, Any]) -> set[str]:
    """What `docker compose up` starts: every service that is not tied to a profile."""
    return {name for name, svc in compose["services"].items() if not svc.get("profiles")}


def test_bench_service_is_only_in_the_bench_profile(compose: dict[str, Any]) -> None:
    services = compose["services"]
    assert services["bench"]["profiles"] == ["bench"]
    assert "bench" not in _default_services(compose)
    # nothing else is tied to the profile, and the demo stack itself is unchanged
    assert {n for n, s in services.items() if "bench" in (s.get("profiles") or [])} == {"bench"}
    assert {"secrets", "postgres", "mock-idp", "mailpit", "init", "gateway"} <= _default_services(
        compose
    )


def test_no_default_service_depends_on_bench(compose: dict[str, Any]) -> None:
    for name in _default_services(compose):
        assert "bench" not in (compose["services"][name].get("depends_on") or {}), name


def test_bench_service_has_no_docker_socket_and_no_admin_credentials(
    compose: dict[str, Any],
) -> None:
    bench = compose["services"]["bench"]
    volumes = [str(v) for v in bench["volumes"]]
    assert not any("docker.sock" in v for v in volumes)
    assert not any("admin" in v or "postgres_password" in v for v in volumes)
    # of the gateway's secrets only the role secret is mounted, as a single read-only file
    gateway_mounts = [v for v in volumes if ".pgwarden-dev/gateway" in v]
    assert gateway_mounts == ["./.pgwarden-dev/gateway/role_secret:/run/pgwarden/role_secret:ro"]
    assert all(v.endswith(":ro") for v in volumes)
    env = bench["environment"]
    assert not any("ADMIN" in key or "STATE_DSN" in key or "SIGNING" in key for key in env)
    assert bench.get("privileged") is not True
    assert bench["entrypoint"] == []  # `pgwarden bench ...` is the command


def test_bench_service_uses_the_gateway_image_on_the_compose_network(
    compose: dict[str, Any],
) -> None:
    services = compose["services"]
    assert services["bench"]["image"] == services["gateway"]["image"]
    assert "network_mode" not in services["bench"]
    assert services["bench"]["environment"]["PGWARDEN_BENCH_CONNECT_URL"] == "http://gateway:8080"


def _without_pool(path: Path) -> dict[str, Any]:
    dumped = load_config(path).model_dump(mode="json")
    dumped.pop("pool")
    return dumped  # type: ignore[no-any-return]


def test_cold_config_is_the_bench_config_plus_one_pool_field() -> None:
    bench = ROOT / "demo" / "pgwarden.bench.yaml"
    cold = ROOT / "demo" / "pgwarden.bench-cold.yaml"
    os.environ.setdefault("PGWARDEN_PUBLIC_URL", "http://localhost:8080")
    os.environ.setdefault("PGWARDEN_OIDC_ISSUER", "http://localhost:9400")
    assert _without_pool(bench) == _without_pool(cold)
    assert load_config(cold).pool.idle_timeout_s == 1
    assert load_config(bench).pool.idle_timeout_s > 1
    # the only field the cold file sets on top is pool.idle_timeout_s
    cold_raw = yaml.safe_load(cold.read_text(encoding="utf-8"))
    bench_raw = yaml.safe_load(bench.read_text(encoding="utf-8"))
    assert cold_raw.pop("pool") == {"idle_timeout_s": 1}
    assert cold_raw == bench_raw


def test_bench_config_has_twenty_machines_with_raised_limits() -> None:
    os.environ.setdefault("PGWARDEN_PUBLIC_URL", "http://localhost:8080")
    os.environ.setdefault("PGWARDEN_OIDC_ISSUER", "http://localhost:9400")
    config = load_config(ROOT / "demo" / "pgwarden.bench.yaml")
    names = {m.name for m in config.machines}
    assert {f"bench-{i:02d}" for i in range(1, 21)} <= names
    assert config.limits.queries_per_minute >= 100_000


def test_wrapper_script_is_executable_and_shares_the_connection_sql() -> None:
    script = ROOT / "devtools" / "bench" / "run.sh"
    text = script.read_text(encoding="utf-8")
    assert os.access(script, os.X_OK)
    assert text.startswith("#!/usr/bin/env bash")
    assert PEAK_CONNECTIONS_SQL in text
    for phase in ("latency)", "cold)", "load)", "all)", "restore)"):
        assert phase in text


def test_wrapper_runs_the_spec_parameters() -> None:
    text = (ROOT / "devtools" / "bench" / "run.sh").read_text(encoding="utf-8")
    assert "--iterations 1000 --warmup 100 --repetitions 3" in text
    assert "--identities 20 --concurrency 20 --duration 60 --mix pk:60,filter:30,agg:10" in text
    assert "audit verify" in text and "docker stats" in text


def _option_default(command: Any, name: str) -> Any:
    return inspect.signature(command).parameters[name].default.default


def test_commands_default_to_the_spec_parameters() -> None:
    assert _option_default(bench_latency_command, "iterations") == 1000
    assert _option_default(bench_latency_command, "warmup") == 100
    assert _option_default(bench_latency_command, "repetitions") == 3
    assert _option_default(bench_latency_command, "role") == "pw_m_bench_01"
    assert _option_default(bench_load_command, "identities") == 20
    assert _option_default(bench_load_command, "concurrency") == 20
    assert _option_default(bench_load_command, "duration") == 60
    assert _option_default(bench_load_command, "mix") == "pk:60,filter:30,agg:10"
