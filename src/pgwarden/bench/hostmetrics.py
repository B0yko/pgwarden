"""Host-side numbers for the benchmark results, and the merge that writes the final files.

The benchmark container has no Docker socket, so ``devtools/bench/run.sh`` samples the
gateway from the host while the run is in progress and leaves plain text files in a
scratch directory:

Each sampler runs at least once a second (docker stats streams about two frames a second and
the polls run about every half second); the number of samples of each is recorded.

* ``docker-stats.txt``: the stream of ``docker stats --format '{{.CPUPerc}}|{{.MemUsage}}'``
  for the gateway container (CPU as a percentage of one core, as Docker reports it),
* ``gateway-rss.txt``: the ``VmRSS`` line of the gateway process,
* ``pg-connections.txt``: connections held by pgwarden's roles,
* ``audit-verify.txt`` and ``audit-verify.exit``: the output and exit code of
  ``pgwarden audit verify`` after the run,
* ``raw.json``: the JSON document the benchmark command printed in the container.

This module parses those files and folds them into ``docs/results/{latency,load}-<date>.json``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_UNITS_MIB = {
    "b": 1 / (1024 * 1024),
    "kib": 1 / 1024,
    "kb": 1 / 1024,
    "mib": 1.0,
    "mb": 1.0,
    "gib": 1024.0,
    "gb": 1024.0,
}
COMPOSE_PREFIX = "docker compose --profile bench run --rm bench"


def _size_mib(text: str) -> float | None:
    match = re.fullmatch(r"\s*([0-9.]+)\s*([A-Za-z]+)\s*", text)
    if not match or match.group(2).lower() not in _UNITS_MIB:
        return None
    return float(match.group(1)) * _UNITS_MIB[match.group(2).lower()]


def parse_docker_stats(text: str) -> list[tuple[float, float]]:
    """``(cpu_percent, memory_mib)`` per frame of a ``docker stats`` stream.

    Anything that is not a ``<cpu>%|<used> / <limit>`` line (screen-clearing escapes,
    blank lines, an error message) is skipped.
    """
    samples: list[tuple[float, float]] = []
    for raw in _ANSI.sub("\n", text).splitlines():
        line = raw.strip()
        cpu_text, sep, mem_text = line.partition("|")
        if not sep or not cpu_text.endswith("%"):
            continue
        try:
            cpu = float(cpu_text[:-1])
        except ValueError:
            continue
        mem = _size_mib(mem_text.split("/")[0])
        if mem is not None:
            samples.append((cpu, mem))
    return samples


def parse_vmrss(text: str) -> list[float]:
    """MiB per ``VmRSS:  123456 kB`` line of ``/proc/<pid>/status``."""
    return [int(m.group(1)) / 1024.0 for m in re.finditer(r"VmRSS:\s*(\d+)\s*kB", text)]


def parse_int_lines(text: str) -> list[int]:
    """The integer lines of a file, ignoring anything else."""
    return [int(line) for line in (raw.strip() for raw in text.splitlines()) if line.isdigit()]


def parse_audit_verify(output: str, exit_code: int) -> dict[str, Any]:
    """The result of ``pgwarden audit verify`` from its output and exit code."""
    text = _ANSI.sub("", output)
    ok = exit_code == 0 and re.search(r"^OK:", text, re.MULTILINE) is not None
    result: dict[str, Any] = {"ok": ok, "exit_code": exit_code}
    ok_line = re.search(r"^OK:\s*(.*)$", text, re.MULTILINE)
    broken = re.search(r"^BROKEN.*$", text, re.MULTILINE)
    if ok_line:
        result["detail"] = ok_line.group(1).strip()
    elif broken:
        result["detail"] = broken.group(0).strip()
    else:
        result["detail"] = text.strip().splitlines()[-1] if text.strip() else "no output"
    seq = re.search(r"^head seq:\s*(\d+)", text, re.MULTILINE)
    head = re.search(r"^head hash:\s*([0-9a-f]+)", text, re.MULTILINE)
    if seq:
        result["head_seq"] = int(seq.group(1))
    if head:
        result["head_hash"] = head.group(1)
    return result


def _read(directory: Path, name: str) -> str:
    path = directory / name
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def _audit_from(directory: Path) -> dict[str, Any] | None:
    output = _read(directory, "audit-verify.txt")
    exit_text = _read(directory, "audit-verify.exit").strip()
    if not output and not exit_text:
        return None
    return parse_audit_verify(output, int(exit_text) if exit_text.lstrip("-").isdigit() else 1)


def host_summary(directory: Path) -> dict[str, Any]:
    """Peaks over the sampler files in ``directory``."""
    stats = parse_docker_stats(_read(directory, "docker-stats.txt"))
    rss = parse_vmrss(_read(directory, "gateway-rss.txt"))
    conns = parse_int_lines(_read(directory, "pg-connections.txt"))
    summary: dict[str, Any] = {
        "gateway_cpu_percent_of_one_core_peak": round(max((c for c, _ in stats), default=0.0), 1),
        "gateway_cpu_percent_of_one_core_mean": (
            round(sum(c for c, _ in stats) / len(stats), 1) if stats else 0.0
        ),
        "gateway_cpu_samples": len(stats),
        "gateway_rss_mib_peak": round(max(rss, default=0.0), 1),
        "gateway_rss_samples": len(rss),
        "gateway_container_memory_mib_peak": round(max((m for _, m in stats), default=0.0), 1),
        "pg_connections_peak": max(conns, default=0),
        "pg_connections_samples": len(conns),
    }
    return summary


def _load_raw(directory: Path) -> dict[str, Any]:
    raw = json.loads(_read(directory, "raw.json") or "{}")
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{directory / 'raw.json'} is missing or empty")
    return raw


def merge_load(directory: Path) -> dict[str, Any]:
    """The final ``load-<date>.json`` document from the container output and the samplers."""
    document = _load_raw(directory)
    document["command"] = f"{COMPOSE_PREFIX} {document['command']}"
    host = host_summary(directory)
    document["host_samples"] = host
    result = document.get("result", {})
    if result.get("peak_pg_connections") is None and host["pg_connections_samples"]:
        result["peak_pg_connections"] = host["pg_connections_peak"]
        result["peak_pg_connections_source"] = (
            "pg_stat_activity, sampled once a second from the host"
        )
    audit = _audit_from(directory)
    if audit is not None:
        document["audit_verify"] = audit
    return document


def merge_latency(directory: Path) -> dict[str, Any]:
    """The final ``latency-<date>.json`` document (audit verify recorded after the run)."""
    document = _load_raw(directory)
    document["command"] = f"{COMPOSE_PREFIX} {document['command']}"
    audit = _audit_from(directory)
    if audit is not None:
        document["audit_verify"] = audit
    return document


def merge_cold(directory: Path, into: dict[str, Any]) -> dict[str, Any]:
    """Add the cold-start block from a cold run to an existing latency document."""
    raw = _load_raw(directory)
    cold = dict(raw["cold_start"])
    cold["command"] = f"{COMPOSE_PREFIX} {raw['command']}"
    cold["config_file"] = raw.get("config_file")
    cold["config_hash"] = raw.get("config_hash")
    cold["date"] = raw.get("date")
    cold["git_commit"] = raw.get("git_commit")
    into["cold_start"] = cold
    return into


__all__ = [
    "COMPOSE_PREFIX",
    "host_summary",
    "merge_cold",
    "merge_latency",
    "merge_load",
    "parse_audit_verify",
    "parse_docker_stats",
    "parse_int_lines",
    "parse_vmrss",
]
