"""Unit tests for pgwarden.timing (Server-Timing spans; no Postgres needed)."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from pgwarden.timing import Timing, render_server_timing


def _fake_clock() -> Callable[[], float]:
    """A deterministic clock: each call advances by 10ms, starting at 0."""
    state = {"t": 0.0}

    def clock() -> float:
        state["t"] += 0.010
        return state["t"]

    return clock


def test_span_records_one_entry_with_a_positive_duration() -> None:
    timing = Timing()
    with timing.span("db"):
        pass
    assert len(timing.spans) == 1
    assert timing.spans[0].name == "db"
    assert timing.spans[0].duration_ms >= 0.0


def test_span_records_even_when_the_block_raises() -> None:
    timing = Timing()
    with pytest.raises(ValueError), timing.span("db"):
        raise ValueError("boom")
    assert len(timing.spans) == 1
    assert timing.spans[0].name == "db"


def test_as_dict_sums_repeated_span_names() -> None:
    timing = Timing(_clock=_fake_clock())
    with timing.span("db"):
        pass
    with timing.span("db"):
        pass
    with timing.span("auth"):
        pass
    totals = timing.as_dict()
    assert set(totals) == {"db", "auth"}
    assert totals["db"] == pytest.approx(20.0, abs=0.5)
    assert totals["auth"] == pytest.approx(10.0, abs=0.5)


def test_total_ms_is_the_sum_of_every_span() -> None:
    timing = Timing(_clock=_fake_clock())
    with timing.span("auth"):
        pass
    with timing.span("db"):
        pass
    assert timing.total_ms() == pytest.approx(20.0, abs=0.5)


def test_record_adds_a_span_without_timing_a_block() -> None:
    timing = Timing()
    timing.record("pool", 12.5)
    assert len(timing.spans) == 1
    assert timing.spans[0].name == "pool"
    assert timing.spans[0].duration_ms == 12.5


def test_render_server_timing_formats_name_and_duration() -> None:
    timing = Timing()
    timing.record("auth", 1.234)
    timing.record("db", 5.0)
    header = render_server_timing(timing)
    assert header == "auth;dur=1.2, db;dur=5.0"


def test_render_server_timing_empty_is_empty_string() -> None:
    assert render_server_timing(Timing()) == ""
