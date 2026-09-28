"""Reproducibility metadata every benchmark results file carries.

The benchmark container cannot see Docker or git, so the host wrapper
(``devtools/bench/run.sh``) passes what only the host knows through
``PGWARDEN_*`` variables: the commit, colima's CPUs and memory, the number of
other running containers and the hardware string. The config hash comes from the
config file mounted into the container.
"""

from __future__ import annotations

import datetime as _dt
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pgwarden.redteam.report import _config_hash, _git_commit

HARDWARE_FALLBACK = "unspecified"


def _int_env(env: Mapping[str, str], name: str) -> int | None:
    raw = (env.get(name) or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def collect_metadata(
    *,
    config_path: str | None,
    postgres_version: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The metadata block merged into a benchmark results document."""
    env = os.environ if env is None else env
    other = _int_env(env, "PGWARDEN_BENCH_OTHER_CONTAINERS")
    return {
        "date": env.get("PGWARDEN_RUN_DATE") or _dt.date.today().isoformat(),
        "git_commit": _git_commit(),
        "postgres_version": postgres_version or env.get("PGWARDEN_BENCH_POSTGRES_VERSION") or None,
        "config_file": Path(config_path).name if config_path else None,
        "config_hash": _config_hash(config_path),
        "hardware": env.get("PGWARDEN_BENCH_HARDWARE") or HARDWARE_FALLBACK,
        "colima_cpus": _int_env(env, "PGWARDEN_BENCH_COLIMA_CPUS"),
        "colima_memory_gib": _int_env(env, "PGWARDEN_BENCH_COLIMA_MEMORY_GIB"),
        "other_containers": other,
        "shared_machine": None if other is None else other > 0,
    }


__all__ = ["HARDWARE_FALLBACK", "collect_metadata"]
