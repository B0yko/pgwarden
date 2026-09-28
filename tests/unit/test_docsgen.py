"""Unit tests for the configuration-doc generator and the README table renderers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pgwarden.docsgen import (
    generate_configuration_md,
    inject,
    render_baselines_table,
    render_latency_table,
    render_load_table,
    render_readme,
    render_redteam_table,
)


def test_configuration_md_covers_every_field() -> None:
    text = generate_configuration_md()
    assert "# Configuration reference" in text
    assert "`PGWARDEN_SIGNING_KEY`" in text
    for field in ("public_url", "trusted_proxy_hops", "max_replicas", "queries_per_minute"):
        assert f"`{field}`" in text


def test_redteam_table_excludes_non_attack_categories() -> None:
    data = {
        "summary": {
            "by_category": {
                "A": {"attacks": 10, "blocked": 10, "layers": ["protocol"]},
                "benign": {"attacks": 0, "blocked": 0, "layers": []},
            },
            "benign_passed": 32,
            "benign_total": 32,
            "residual_risks": [{"id": "D05"}],
        }
    }
    table = render_redteam_table(data)
    assert "A. Stacked statements | 10 | 10" in table
    assert "| benign |" not in table  # the pseudo-category is not a table row
    assert "Benign controls passed: 32 / 32" in table


def test_baselines_table_shows_pgwarden_zero() -> None:
    data = {
        "sql_attacks_total": 66,
        "benign_total": 29,
        "baselines": [
            {
                "baseline": "keyword/regex blocklist",
                "attacks_let_through": 39,
                "benign_wrongly_blocked": 3,
            },
        ],
    }
    table = render_baselines_table(data)
    assert "39 / 66" in table
    assert "**0 / 66**" in table


def test_inject_replaces_between_markers() -> None:
    readme = "before\n<!-- pgwarden:redteam:start -->\nOLD\n<!-- pgwarden:redteam:end -->\nafter\n"
    out = inject(readme, "redteam", "NEW TABLE")
    assert "NEW TABLE" in out and "OLD" not in out
    assert out.startswith("before") and out.rstrip().endswith("after")


def _latency_doc(*, pk_overhead: float = 4.1, cold: dict[str, Any] | None = None) -> dict[str, Any]:
    spread = {
        "direct_p50": [0.4, 0.5],
        "direct_p95": [0.9, 1.2],
        "wrapper_p50": [2.0, 2.2],
        "wrapper_p95": [3.0, 3.5],
        "gateway_p50": [4.4, 5.1],
        "gateway_p95": [7.9, 9.0],
        "overhead_p50": [3.9, 4.6],
        "overhead_p95": [6.9, 7.8],
    }
    return {
        "date": "2026-09-28",
        "git_commit": "abc1234",
        "postgres_version": "16.15 (Debian 16.15-1.pgdg13+2)",
        "hardware": "MacBook Air M5, 24 GB, Docker via colima with 4 CPUs / 6 GB",
        "config_file": "pgwarden.bench.yaml",
        "config_hash": "0123456789abcdef",
        "other_containers": 2,
        "iterations": 1000,
        "warmup": 100,
        "repetitions": 3,
        "queries": [
            {
                "query": "primary-key lookup",
                "rows": 1,
                "direct_p50": 0.44,
                "direct_p95": 1.05,
                "wrapper_p50": 2.1,
                "wrapper_p95": 3.2,
                "gateway_p50": 0.44 + pk_overhead,
                "gateway_p95": 8.4,
                "overhead_p50": pk_overhead,
                "overhead_p95": 7.35,
                "spread": spread,
                "server_timing_median": {"audit": 0.7, "auth": 0.4, "db": 1.3, "ratelimit": 0.3},
            },
            {
                "query": "monthly aggregate over orders",
                "rows": 24,
                "direct_p50": 41.2,
                "direct_p95": 50.0,
                "wrapper_p50": 44.0,
                "wrapper_p95": 53.0,
                "gateway_p50": 46.0,
                "gateway_p95": 58.0,
                "overhead_p50": 4.8,
                "overhead_p95": 8.0,
                "spread": spread,
                "server_timing_median": {"audit": 0.7, "auth": 0.4, "db": 41.0, "ratelimit": 0.3},
            },
        ],
        "cold_start": cold,
        "audit_verify": {"ok": True, "detail": "chain intact through seq 900", "head_seq": 900},
    }


def test_latency_table_has_the_spec_columns_and_spreads() -> None:
    table = render_latency_table(_latency_doc())
    assert table.startswith(
        "| Query | Direct p50 / p95 | Direct + wrapper p50 / p95 | Via pgwarden p50 / p95 "
        "| Overhead p50 / p95 (ms) |"
    )
    pk = next(
        line for line in table.splitlines() if line.startswith("| primary-key lookup (1 row) |")
    )
    assert "0.44 / 1.05<br><sub>0.40-0.50 / 0.90-1.20</sub>" in pk
    assert "4.10 / 7.35<br><sub>3.90-4.60 / 6.90-7.80</sub>" in pk
    agg = next(
        line
        for line in table.splitlines()
        if line.startswith("| monthly aggregate over orders (24 rows)")
    )
    assert "41.2 / 50.0" in agg  # one decimal from 10 ms up
    assert "median of 3 repetitions of 1000 timed calls after 100 warm-up calls" in table


def test_latency_table_lists_server_timing_spans_in_pipeline_order() -> None:
    table = render_latency_table(_latency_doc())
    assert "| Query | auth | ratelimit | db | audit |" in table
    assert "| primary-key lookup | 0.40 | 0.30 | 1.30 | 0.70 |" in table


def test_latency_target_met_and_missed_names_the_dominant_span() -> None:
    met = render_latency_table(_latency_doc(pk_overhead=4.1))
    assert "Design target (overhead p50 <= 10 ms on the primary-key lookup): met, 4.10 ms." in met
    missed = render_latency_table(_latency_doc(pk_overhead=12.3))
    assert "missed, 12.3 ms. The largest `Server-Timing` span is `db` (1.30 ms)." in missed


def test_latency_run_line_and_audit_line() -> None:
    table = render_latency_table(_latency_doc())
    assert "Run: 2026-09-28; commit `abc1234`; Postgres 16.15;" in table
    assert "MacBook Air M5, 24 GB, Docker via colima with 4 CPUs / 6 GB" in table
    assert "2 other containers running on the machine during the run" in table
    assert "config `pgwarden.bench.yaml` (sha256 0123456789abcdef)" in table
    assert "Audit chain verified after the latency run: OK, chain intact through seq 900." in table


def test_latency_cold_line_measured_not_measured_and_absent() -> None:
    measured = {
        "measured": True,
        "pool_idle_timeout_s": 1,
        "idle_wait_s": 2.5,
        "samples": 30,
        "confirmed_cold_samples": 29,
        "cold_first_query_ms": {"median": 38.8, "min": 34.0, "max": 46.8},
        "warm_query_ms": {"median": 3.79, "min": 2.6, "max": 27.0},
        "cold_cost_ms": 35.0,
        "db_span_cost_ms": 27.3,
    }
    line = render_latency_table(_latency_doc(cold=measured))
    assert "median 38.8 ms (min 34.0, max 46.8) against 3.79 ms warm" in line
    assert "cold cost of 35.0 ms, of which 27.3 ms in the `db` span" in line
    assert "`pool.idle_timeout_s: 1`" in line
    assert "29 of 30 samples were confirmed cold" in line
    unmeasured = {"measured": False, "reason": "only 3 of 30 samples opened a new connection"}
    assert "Cold first-query cost: not measured. only 3 of 30" in render_latency_table(
        _latency_doc(cold=unmeasured)
    )
    assert "Cold first-query cost: not measured in this run." in render_latency_table(
        _latency_doc(cold=None)
    )


def _load_doc(*, p95: float = 88.0, errors: int = 0) -> dict[str, Any]:
    return {
        "date": "2026-09-28",
        "git_commit": "abc1234",
        "postgres_version": "16.15 (Debian)",
        "hardware": "MacBook Air M5, 24 GB, Docker via colima with 4 CPUs / 6 GB",
        "config_file": "pgwarden.bench.yaml",
        "config_hash": "0123456789abcdef",
        "other_containers": 1,
        "mix": "pk:60,filter:30,agg:10",
        "result": {
            "identities": 20,
            "concurrency": 20,
            "duration_s": 60.1,
            "total_requests": 38000,
            "requests_per_s": 632.5,
            "p50_ms": 24.2,
            "p95_ms": p95,
            "p99_ms": 130.4,
            "errors": errors,
            "error_rate": errors / 38000,
            "rate_limited": 0,
            "peak_pg_connections": 20,
        },
        "host_samples": {
            "gateway_cpu_percent_of_one_core_peak": 96.4,
            "gateway_cpu_percent_of_one_core_mean": 81.2,
            "gateway_cpu_samples": 121,
            "gateway_rss_mib_peak": 131.5,
            "gateway_rss_samples": 171,
        },
        "audit_verify": {
            "ok": True,
            "detail": "chain intact through seq 61000",
            "head_seq": 61000,
        },
    }


def test_load_table_has_every_required_measure() -> None:
    table = render_load_table(_load_doc())
    for expected in (
        "| Identities | 20 machine identities (bench-01 to bench-20) |",
        "| Concurrency | 20 |",
        "| Duration | 60.1 s, mix `pk:60,filter:30,agg:10` |",
        "| Total requests | 38000 (0 rate-limited) |",
        "| Requests/s | 632.5 |",
        "| Latency p50 / p95 / p99 | 24.2 / 88.0 / 130.4 ms |",
        "| Error rate (rate-limited calls excluded) | 0.00% (0 errors) |",
        "| 20 |",
        "96.4% (mean 81.2%, 121 samples)",
        "| Gateway peak RSS | 131.5 MiB (171 samples) |",
        "OK: chain intact through seq 61000, head seq 61000",
    ):
        assert expected in table, expected
    assert "Peak Postgres connections" in table
    assert "met (p95 88.0 ms, 0 errors)" in table


def test_load_target_missed_on_slow_p95_or_any_error() -> None:
    assert "missed (p95 210.0 ms, 0 errors)" in render_load_table(_load_doc(p95=210.0))
    assert "missed (p95 88.0 ms, 3 errors)" in render_load_table(_load_doc(errors=3))


def test_render_readme_fills_the_latency_and_load_markers(tmp_path: Path) -> None:
    (tmp_path / "latency-2026-09-28.json").write_text(json.dumps(_latency_doc()), encoding="utf-8")
    (tmp_path / "load-2026-09-28.json").write_text(json.dumps(_load_doc()), encoding="utf-8")
    readme = (
        "a\n<!-- pgwarden:latency:start -->\nOLD\n<!-- pgwarden:latency:end -->\n"
        "b\n<!-- pgwarden:load:start -->\nOLD\n<!-- pgwarden:load:end -->\nc\n"
    )
    out = render_readme(readme, tmp_path)
    assert "OLD" not in out
    assert "| Query | Direct p50 / p95 |" in out and "| Measure | Result |" in out
    assert render_readme(out, tmp_path) == out  # rendering is idempotent
