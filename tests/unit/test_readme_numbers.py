"""The counts the README states in prose agree with the recorded red-team run."""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _latest(prefix: str) -> dict[str, object]:
    files = sorted((REPO / "docs" / "results").glob(f"{prefix}-*.json"))
    parsed: dict[str, object] = json.loads(files[-1].read_text(encoding="utf-8"))
    return parsed


def test_readme_states_the_recorded_attack_and_benign_counts() -> None:
    summary = _latest("redteam")["summary"]
    assert isinstance(summary, dict)
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    match = re.search(
        r"(\d+) must-block attacks in nine categories .*? and (\d+) benign", readme, re.S
    )
    assert match, "the README no longer states the corpus size"
    assert int(match.group(1)) == summary["must_block_total"]
    assert int(match.group(2)) == summary["benign_total"]
