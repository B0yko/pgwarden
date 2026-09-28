"""CI check for docs/threat-model.md.

Asserts that every OWASP ID from all three pinned lists appears in the table, that
the IDs used match docs/threat-model-ids.yaml, and that every cited test ID exists —
a red-team corpus case id or a collectible pytest test.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
THREAT_MODEL = REPO_ROOT / "docs" / "threat-model.md"
IDS_YAML = REPO_ROOT / "docs" / "threat-model-ids.yaml"
ATTACKS_DIR = REPO_ROOT / "src" / "pgwarden" / "redteam" / "attacks"


def _pinned_ids() -> set[str]:
    data = yaml.safe_load(IDS_YAML.read_text(encoding="utf-8"))
    ids: set[str] = set()
    for group in data.values():
        ids.update(group["ids"].keys())
    return ids


def _table_text() -> str:
    return THREAT_MODEL.read_text(encoding="utf-8")


def test_every_owasp_id_appears_and_matches_the_pinned_list() -> None:
    text = _table_text()
    used = set(re.findall(r"\b(?:LLM|ASI|MCP)\d{2}\b", text))
    pinned = _pinned_ids()
    unknown = used - pinned
    assert not unknown, f"threat model cites unknown OWASP ids: {sorted(unknown)}"
    missing = pinned - used
    assert not missing, f"threat model is missing OWASP ids: {sorted(missing)}"


def _corpus_case_ids() -> set[str]:
    ids: set[str] = set()
    for path in ATTACKS_DIR.glob("*.yaml"):
        for case in yaml.safe_load(path.read_text(encoding="utf-8")):
            ids.add(case["id"])
    return ids


def _collected_test_names() -> set[str]:
    # Every test function name across the suite; cited as <file>::<test>.
    names: set[str] = set()
    for path in (REPO_ROOT / "tests").rglob("test_*.py"):
        for match in re.finditer(r"^(?:async )?def (test_\w+)\(", path.read_text("utf-8"), re.M):
            names.add(f"{path.name}::{match.group(1)}")
    return names


def test_every_cited_test_id_exists() -> None:
    text = _table_text()
    corpus = _corpus_case_ids()
    tests = _collected_test_names()
    problems: list[str] = []
    for cell in re.findall(r"redteam:([A-Z]\d{2})", text):
        if cell not in corpus:
            problems.append(f"redteam:{cell}")
    for cell in re.findall(r"(test_\w+\.py::test_\w+)", text):
        if cell not in tests:
            problems.append(cell)
    assert not problems, f"threat model cites test ids that do not exist: {problems}"


def test_mitigated_rows_cite_at_least_one_test() -> None:
    # Each table row that is not "not applicable" must cite a test id.
    rows = [
        line
        for line in _table_text().splitlines()
        if line.startswith("|")
        and "|" in line[1:]
        and "Mitigating layer" not in line
        and not line.startswith("| ---")
        and "Threat |" not in line
    ]
    for row in rows:
        if "not applicable" in row.lower():
            continue
        assert "redteam:" in row or ".py::test_" in row, f"no test cited: {row[:80]}"
