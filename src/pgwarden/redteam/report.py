"""Assemble a red-team results document: the summary plus reproducibility metadata."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

import asyncpg

from pgwarden.redteam.runner import CaseResult, summarize


def _git_commit() -> str | None:
    override = os.environ.get("PGWARDEN_GIT_COMMIT")
    if override:
        return override
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).resolve().parent,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip() or None


def _config_hash(config_path: str | None) -> str | None:
    if not config_path or not Path(config_path).is_file():
        return None
    return hashlib.sha256(Path(config_path).read_bytes()).hexdigest()[:16]


async def build_report(
    results: list[CaseResult],
    *,
    admin_dsn: str | None,
    config_path: str | None,
    date: str,
    hardware: str,
    command: str,
    other_containers: int | None = None,
) -> dict[str, Any]:
    postgres_version: str | None = None
    if admin_dsn:
        conn = await asyncpg.connect(admin_dsn, timeout=10)
        try:
            postgres_version = str(await conn.fetchval("SHOW server_version"))
        finally:
            await conn.close()
    return {
        "command": command,
        "date": date,
        "hardware": hardware,
        "git_commit": _git_commit(),
        "postgres_version": postgres_version,
        "config_hash": _config_hash(config_path),
        "other_containers": other_containers,
        "summary": summarize(results),
        "cases": [
            {
                "id": r.id,
                "category": r.category,
                "kind": r.kind,
                "title": r.title,
                "expected_layer": r.expected_layer,
                "observed_layer": r.observed_layer,
                "passed": r.passed,
                "detail": r.detail,
            }
            for r in results
        ],
    }


__all__ = ["build_report"]
