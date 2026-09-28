"""Unit tests for the benchmark aggregation, cold-start bookkeeping and host-side parsing."""

from __future__ import annotations

import collections
import json
from pathlib import Path

import pytest

from pgwarden.bench import cold, hostmetrics
from pgwarden.bench.latency import BenchCallError, LatencyResult, aggregate_repetitions, check_call
from pgwarden.bench.load import classify, summarize_load
from pgwarden.bench.metadata import collect_metadata
from pgwarden.redteam import mcp_client
from pgwarden.redteam.stack import StackClient


def _result(
    query: str,
    *,
    direct: tuple[float, float],
    wrapper: tuple[float, float],
    gateway: tuple[float, float],
    spans: dict[str, float],
) -> LatencyResult:
    return LatencyResult(
        query=query,
        direct_p50=direct[0],
        direct_p95=direct[1],
        wrapper_p50=wrapper[0],
        wrapper_p95=wrapper[1],
        gateway_p50=gateway[0],
        gateway_p95=gateway[1],
        overhead_p50=gateway[0] - direct[0],
        overhead_p95=gateway[1] - direct[1],
        server_timing_median=spans,
    )


def _three_repetitions() -> list[list[LatencyResult]]:
    reps = []
    for d50, g50, g95, db in [
        (1.0, 10.0, 20.0, 2.0),
        (1.2, 12.0, 30.0, 3.0),
        (0.8, 11.0, 25.0, 4.0),
    ]:
        reps.append(
            [
                _result(
                    "pk",
                    direct=(d50, d50 * 3),
                    wrapper=(5.0, 9.0),
                    gateway=(g50, g95),
                    spans={"db": db, "auth": 1.0},
                ),
                _result(
                    "agg",
                    direct=(40.0, 50.0),
                    wrapper=(50.0, 60.0),
                    gateway=(55.0, 70.0),
                    spans={"db": 39.0},
                ),
            ]
        )
    return reps


def test_aggregate_takes_the_median_across_repetitions() -> None:
    rows = aggregate_repetitions(_three_repetitions())
    pk = next(r for r in rows if r["query"] == "pk")
    assert [r["query"] for r in rows] == ["pk", "agg"]
    assert pk["direct_p50"] == 1.0
    assert pk["gateway_p50"] == 11.0
    assert pk["gateway_p95"] == 25.0
    # the overhead is the difference of the reported medians, so the table adds up
    assert pk["overhead_p50"] == pytest.approx(10.0)
    assert pk["overhead_p95"] == pytest.approx(25.0 - 3.0)
    assert pk["server_timing_median"] == {"auth": 1.0, "db": 3.0}


def test_aggregate_reports_min_and_max_of_the_repetitions() -> None:
    pk = aggregate_repetitions(_three_repetitions())[0]
    spread = pk["spread"]
    assert spread["gateway_p50"] == [10.0, 12.0]
    assert spread["gateway_p95"] == [20.0, 30.0]
    assert spread["direct_p50"] == [0.8, 1.2]
    # per-repetition overheads are 9.0, 10.8 and 10.2
    assert spread["overhead_p50"] == [9.0, 10.8]
    assert len(pk["repetition_results"]) == 3
    assert pk["repetition_results"][0]["gateway_p50"] == 10.0


def test_aggregate_with_one_repetition_has_a_zero_spread() -> None:
    row = aggregate_repetitions(_three_repetitions()[:1])[1]
    assert row["gateway_p50"] == 55.0
    assert row["spread"]["gateway_p50"] == [55.0, 55.0]


def _tool_response(*, status: int = 200, error: dict[str, object] | None = None) -> object:
    body = {"result": {"structuredContent": {"error": error} if error else {"rows": []}}}
    return mcp_client.ToolResponse(status=status, text=json.dumps(body), body=body)


def test_a_refused_timed_call_aborts_the_run() -> None:
    check_call(_tool_response())  # type: ignore[arg-type]
    with pytest.raises(BenchCallError, match="bench config"):
        check_call(
            _tool_response(error={"sqlstate": "53400", "message": "rate limit exceeded"})  # type: ignore[arg-type]
        )
    with pytest.raises(BenchCallError, match="HTTP 401"):
        check_call(_tool_response(status=401))  # type: ignore[arg-type]


# -- cold start ---------------------------------------------------------------------------


def _sample(cold_ms: float, *, fresh: bool = True, warm: float = 10.0) -> cold.ColdSample:
    return cold.ColdSample(
        cold_ms=cold_ms,
        cold_spans={"db": cold_ms - 8.0, "auth": 1.0},
        warm_ms=[warm, warm + 1.0],
        warm_spans=[{"db": 2.0, "auth": 1.0}, {"db": 2.0, "auth": 1.0}],
        fresh_backend=fresh,
    )


def test_cold_cost_is_cold_median_minus_warm_median() -> None:
    samples = [_sample(30.0), _sample(34.0), _sample(32.0)]
    out = cold.summarize_cold(samples, idle_wait_s=2.5, idle_timeout_s=1)
    assert out["measured"] is True
    assert out["cold_first_query_ms"] == {"median": 32.0, "min": 30.0, "max": 34.0}
    assert out["warm_query_ms"]["median"] == 10.5
    assert out["cold_cost_ms"] == 21.5
    assert out["db_span_cost_ms"] == pytest.approx(24.0 - 2.0)
    assert out["confirmed_cold_samples"] == 3
    assert out["pool_idle_timeout_s"] == 1
    assert out["server_timing_median"]["warm"] == {"auth": 1.0, "db": 2.0}


def test_samples_without_a_new_backend_are_excluded() -> None:
    samples = [_sample(30.0)] * 9 + [_sample(500.0, fresh=False)]
    out = cold.summarize_cold(samples, idle_wait_s=2.5, idle_timeout_s=1)
    assert out["measured"] is True
    assert out["samples"] == 10
    assert out["confirmed_cold_samples"] == 9
    assert out["cold_first_query_ms"]["max"] == 30.0  # the unconfirmed 500 ms is not in it


def test_cold_is_not_measured_when_eviction_cannot_be_confirmed() -> None:
    samples = [_sample(30.0, fresh=False)] * 8 + [_sample(31.0)] * 2
    out = cold.summarize_cold(samples, idle_wait_s=2.5, idle_timeout_s=1)
    assert out["measured"] is False
    assert "2 of 10" in out["reason"]
    assert "cold_cost_ms" not in out
    assert cold.summarize_cold([], idle_wait_s=2.5, idle_timeout_s=1)["measured"] is False


async def test_cold_wait_must_stay_below_the_http_keepalive() -> None:
    client = StackClient("http://localhost:8080")
    token = None
    with pytest.raises(ValueError, match="keep-alive"):
        await cold.run_cold(
            client=client,
            token=token,  # type: ignore[arg-type]
            role_dsn="postgresql://x@127.0.0.1:1/x",
            samples=1,
            idle_wait_s=6.0,
        )


# -- load -----------------------------------------------------------------------------------


def test_classify_separates_rate_limits_from_errors() -> None:
    assert classify(_tool_response()) is None  # type: ignore[arg-type]
    assert (
        classify(_tool_response(error={"sqlstate": "53400", "retryable": True}))  # type: ignore[arg-type]
        == "rate_limited"
    )
    # pool exhaustion is retryable too, but it is not a rate limit: it counts as an error
    assert (
        classify(_tool_response(error={"sqlstate": "53300", "retryable": True}))  # type: ignore[arg-type]
        == "sqlstate_53300"
    )
    assert classify(_tool_response(status=502)) == "http_502"  # type: ignore[arg-type]


def test_error_rate_excludes_rate_limited_calls() -> None:
    outcomes = collections.Counter({"rate_limited": 10, "sqlstate_53300": 2})
    res = summarize_load(
        identities=20,
        concurrency=20,
        elapsed_s=10.0,
        latencies_ok=[float(i) for i in range(1, 89)],
        outcomes=outcomes,
        peak_connections=None,
    )
    assert res.total_requests == 100
    assert res.rate_limited == 10
    assert res.errors == 2
    assert res.error_rate == pytest.approx(2 / 90, abs=1e-4)
    assert res.error_kinds == {"sqlstate_53300": 2}
    assert res.requests_per_s == 10.0
    assert res.peak_pg_connections is None


# -- metadata -------------------------------------------------------------------------------


def test_metadata_carries_the_host_values(tmp_path: Path) -> None:
    config = tmp_path / "pgwarden.bench.yaml"
    config.write_text("public_url: http://localhost:8080\n", encoding="utf-8")
    env = {
        "PGWARDEN_RUN_DATE": "2026-09-28",
        "PGWARDEN_BENCH_HARDWARE": "MacBook Air M5, 24 GB, Docker via colima with 4 CPUs / 6 GB",
        "PGWARDEN_BENCH_COLIMA_CPUS": "4",
        "PGWARDEN_BENCH_COLIMA_MEMORY_GIB": "6",
        "PGWARDEN_BENCH_OTHER_CONTAINERS": "2",
        "PGWARDEN_BENCH_POSTGRES_VERSION": "16.4",
        "PGWARDEN_GIT_COMMIT": "abc1234",
    }
    meta = collect_metadata(config_path=str(config), env=env)
    assert meta["date"] == "2026-09-28"
    assert meta["hardware"].startswith("MacBook Air M5, 24 GB")
    assert (meta["colima_cpus"], meta["colima_memory_gib"]) == (4, 6)
    assert meta["other_containers"] == 2 and meta["shared_machine"] is True
    assert meta["postgres_version"] == "16.4"
    assert meta["config_file"] == "pgwarden.bench.yaml"
    assert len(meta["config_hash"]) == 16


def test_metadata_leaves_unknowns_null() -> None:
    meta = collect_metadata(config_path=None, env={})
    assert meta["hardware"] == "unspecified"
    assert meta["other_containers"] is None and meta["shared_machine"] is None
    assert meta["colima_cpus"] is None and meta["config_hash"] is None


# -- StackClient with a separate connect URL --------------------------------------------------


def test_stack_client_keeps_the_public_resource_but_connects_elsewhere() -> None:
    client = StackClient("http://localhost:58080", connect_url="http://gateway:8080/")
    assert client.resource == "http://localhost:58080/mcp"
    assert client.mcp_endpoint == "http://gateway:8080/mcp"
    http = client.http_client(timeout=5.0)
    assert http.headers["host"] == "localhost:58080"
    plain = StackClient("http://localhost:58080")
    assert plain.mcp_endpoint == plain.resource
    assert "host" not in plain.http_client().headers


# -- host-side parsing ------------------------------------------------------------------------

DOCKER_STATS = (
    "\x1b[2J\x1b[H0.00%|41.2MiB / 5.78GiB\n"
    "\x1b[2J\x1b[H87.31%|63.5MiB / 5.78GiB\n"
    "\x1b[2J\x1b[H142.05%|1.5GiB / 5.78GiB\n"
    "Error response from daemon: something\n"
    "\x1b[2J\x1b[H--|--\n"
)


def test_parse_docker_stats_strips_screen_codes_and_units() -> None:
    samples = hostmetrics.parse_docker_stats(DOCKER_STATS)
    assert samples == [(0.0, 41.2), (87.31, 63.5), (142.05, 1536.0)]
    assert hostmetrics.parse_docker_stats("") == []


def test_parse_vmrss_and_integer_lines() -> None:
    assert hostmetrics.parse_vmrss("VmRSS:\t  102400 kB\nVmRSS:   204800 kB\n") == [100.0, 200.0]
    assert hostmetrics.parse_int_lines("3\n7\n\nerror\n5\n") == [3, 7, 5]


def test_parse_audit_verify_ok_and_broken() -> None:
    ok = hostmetrics.parse_audit_verify(
        "OK: 1842 events, chain intact\nhead seq: 1842\nhead hash: 9f2ab0\n", 0
    )
    assert ok == {
        "ok": True,
        "exit_code": 0,
        "detail": "1842 events, chain intact",
        "head_seq": 1842,
        "head_hash": "9f2ab0",
    }
    broken = hostmetrics.parse_audit_verify("BROKEN at seq 12: hash mismatch\n", 1)
    assert broken["ok"] is False
    assert broken["detail"] == "BROKEN at seq 12: hash mismatch"
    # an exit code that disagrees with the text is not "ok"
    assert hostmetrics.parse_audit_verify("OK: fine\n", 1)["ok"] is False
    assert hostmetrics.parse_audit_verify("", 1)["detail"] == "no output"


def _write_samples(directory: Path, *, raw: dict[str, object]) -> None:
    (directory / "raw.json").write_text(json.dumps(raw), encoding="utf-8")
    (directory / "docker-stats.txt").write_text(DOCKER_STATS, encoding="utf-8")
    (directory / "gateway-rss.txt").write_text(
        "VmRSS:\t 90000 kB\nVmRSS:\t 130000 kB\n", encoding="utf-8"
    )
    (directory / "pg-connections.txt").write_text("4\n9\n12\n8\n", encoding="utf-8")
    (directory / "audit-verify.txt").write_text(
        "OK: 900 events\nhead seq: 900\nhead hash: abcdef\n", encoding="utf-8"
    )
    (directory / "audit-verify.exit").write_text("0\n", encoding="utf-8")


def test_merge_load_adds_host_peaks_and_the_audit_result(tmp_path: Path) -> None:
    raw = {
        "command": "pgwarden bench load --identities 20",
        "result": {"total_requests": 100, "peak_pg_connections": None},
    }
    _write_samples(tmp_path, raw=raw)
    doc = hostmetrics.merge_load(tmp_path)
    assert doc["command"].startswith("docker compose --profile bench run --rm bench pgwarden")
    host = doc["host_samples"]
    assert host["gateway_cpu_percent_of_one_core_peak"] == pytest.approx(142.05, abs=0.06)
    assert host["gateway_rss_mib_peak"] == pytest.approx(126.9, abs=0.1)
    assert host["gateway_container_memory_mib_peak"] == 1536.0
    assert host["pg_connections_peak"] == 12
    assert doc["result"]["peak_pg_connections"] == 12
    assert "pg_stat_activity" in doc["result"]["peak_pg_connections_source"]
    assert doc["audit_verify"]["ok"] is True and doc["audit_verify"]["head_seq"] == 900


def test_merge_load_keeps_a_peak_the_run_sampled_itself(tmp_path: Path) -> None:
    raw = {"command": "pgwarden bench load", "result": {"peak_pg_connections": 15}}
    _write_samples(tmp_path, raw=raw)
    assert hostmetrics.merge_load(tmp_path)["result"]["peak_pg_connections"] == 15


def test_merge_needs_the_container_output(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="raw.json"):
        hostmetrics.merge_load(tmp_path)


def test_merge_cold_adds_a_block_to_the_latency_document(tmp_path: Path) -> None:
    raw = {
        "command": "pgwarden bench cold --samples 30 --idle-wait 2.5",
        "config_file": "pgwarden.bench-cold.yaml",
        "config_hash": "0123456789abcdef",
        "date": "2026-09-28",
        "git_commit": "abc1234",
        "cold_start": {"measured": True, "cold_cost_ms": 21.5},
    }
    (tmp_path / "raw.json").write_text(json.dumps(raw), encoding="utf-8")
    latency = {"command": "x", "queries": []}
    out = hostmetrics.merge_cold(tmp_path, latency)
    cold_block = out["cold_start"]
    assert cold_block["cold_cost_ms"] == 21.5
    assert cold_block["config_file"] == "pgwarden.bench-cold.yaml"
    assert cold_block["command"].endswith("pgwarden bench cold --samples 30 --idle-wait 2.5")
    assert out["queries"] == []


def test_merge_latency_records_the_audit_result_after_the_run(tmp_path: Path) -> None:
    _write_samples(tmp_path, raw={"command": "pgwarden bench latency", "queries": []})
    doc = hostmetrics.merge_latency(tmp_path)
    assert doc["audit_verify"]["ok"] is True
    assert doc["command"].startswith("docker compose --profile bench run --rm bench")
