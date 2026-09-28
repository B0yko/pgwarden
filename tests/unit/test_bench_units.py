"""Unit tests for the benchmark helpers (no stack)."""

from __future__ import annotations

from pgwarden.bench.latency import _parse_server_timing, _percentile, load_queries
from pgwarden.bench.load import parse_mix


def test_percentile() -> None:
    values = [float(i) for i in range(1, 101)]
    assert _percentile(values, 50) in (50.0, 51.0)
    assert _percentile(values, 95) in (95.0, 96.0)
    assert _percentile([], 50) == 0.0


def test_parse_server_timing() -> None:
    spans = _parse_server_timing("auth;dur=1.1, db;dur=2.3, ratelimit;dur=0.5")
    assert spans == {"auth": 1.1, "db": 2.3, "ratelimit": 0.5}
    assert _parse_server_timing("") == {}


def test_parse_mix_aliases() -> None:
    assert parse_mix("pk:60,filter:30,agg:10") == {
        "pk_lookup": 60.0,
        "filtered_select": 30.0,
        "monthly_aggregate": 10.0,
    }


def test_query_shapes_are_committed() -> None:
    names = {q["name"] for q in load_queries()}
    assert {"pk_lookup", "filtered_select", "monthly_aggregate"} <= names
