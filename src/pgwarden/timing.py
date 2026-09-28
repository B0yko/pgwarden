"""Per-request span timing and the ``Server-Timing`` header it renders as.

Used by the MCP layer (a later step) to time ``auth``, ``ratelimit``,
``pool``, ``db`` and ``audit`` around a single ``/mcp`` call and expose the
breakdown both as a response header (``PGWARDEN_SERVER_TIMING=1``) and, for
clients that cannot see headers, in the tool result's ``_meta``. Kept
dependency-free and synchronous so it can wrap arbitrary sync or async work
without importing anything from the web or db layers.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

# The only span names the MCP layer is expected to record, per the spec's
# "Timing" section. Not enforced (a caller may record an unknown name; the
# renderer does not care), just documented here as the canonical set.
SPAN_NAMES = ("auth", "ratelimit", "pool", "db", "audit")


@dataclass(frozen=True)
class Span:
    """One completed timing span."""

    name: str
    duration_ms: float


@dataclass
class Timing:
    """Records spans for one request, in the order they finish.

    Not thread-safe or task-safe across concurrent callers -- one instance
    belongs to exactly one request/task, created fresh per call.
    """

    _spans: list[Span] = field(default_factory=list)
    _clock: Callable[[], float] = field(default=time.perf_counter, repr=False)

    @contextmanager
    def span(self, name: str) -> Iterator[None]:
        """Time the wrapped block and record it as a span named ``name``.

        Recorded even if the block raises, so a failed step still shows up
        in the breakdown (for example a ``db`` span around a query that
        errored out).
        """
        clock = self._clock
        start = clock()
        try:
            yield
        finally:
            elapsed_ms = (clock() - start) * 1000.0
            self._spans.append(Span(name=name, duration_ms=elapsed_ms))

    def record(self, name: str, duration_ms: float) -> None:
        """Record a span whose duration was measured elsewhere."""
        self._spans.append(Span(name=name, duration_ms=duration_ms))

    @property
    def spans(self) -> tuple[Span, ...]:
        return tuple(self._spans)

    def total_ms(self) -> float:
        return sum(s.duration_ms for s in self._spans)

    def as_dict(self) -> dict[str, float]:
        """Duration in ms per span name, later spans of the same name winning.

        A name recorded more than once (for example two ``db`` spans around
        two statements in one call) collapses to its sum, which is what a
        ``Server-Timing`` breakdown and the latency benchmark both want.
        """
        totals: dict[str, float] = {}
        for s in self._spans:
            totals[s.name] = totals.get(s.name, 0.0) + s.duration_ms
        return totals


def render_server_timing(timing: Timing) -> str:
    """Render ``timing`` as a ``Server-Timing`` header value (RFC-ish, W3C draft).

    Each span becomes ``name;dur=<ms>``, entries separated by ``, ``, durations
    rounded to one decimal place. An empty ``Timing`` renders to ``""``; the
    caller should omit the header entirely in that case rather than send it
    empty.
    """
    parts = [f"{name};dur={duration:.1f}" for name, duration in timing.as_dict().items()]
    return ", ".join(parts)


__all__ = ["SPAN_NAMES", "Span", "Timing", "render_server_timing"]
