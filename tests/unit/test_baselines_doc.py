"""docs/baselines.md publishes the blocklist and the sqlglot version the results used."""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOC = (REPO / "docs" / "baselines.md").read_text(encoding="utf-8")


def _latest_results() -> dict[str, object]:
    files = sorted((REPO / "docs" / "results").glob("baselines-*.json"))
    parsed: dict[str, object] = json.loads(files[-1].read_text(encoding="utf-8"))
    return parsed


def test_every_blocklist_pattern_is_published() -> None:
    patterns = _latest_results()["blocklist_patterns"]
    assert isinstance(patterns, list)
    for pattern in patterns:
        assert pattern.replace("\\s+", "\\s+") in DOC, pattern


def test_the_recorded_sqlglot_version_is_stated() -> None:
    assert str(_latest_results()["sqlglot_version"]) in DOC


def test_the_result_table_matches_the_recorded_run() -> None:
    data = _latest_results()
    total = data["sql_attacks_total"]
    benign = data["benign_total"]
    baselines = data["baselines"]
    assert isinstance(baselines, list)
    for row in baselines:
        cells = f"| {row['baseline']} | {row['attacks_let_through']} / {total} "
        cells += f"| {row['benign_wrongly_blocked']} / {benign} |"
        assert cells in DOC, cells
