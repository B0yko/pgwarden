"""Structure of the red-team corpus: the counts and distinctness the release gate needs.

The gate requires at least 120 must-block attacks across nine categories, at least 8
per category, each a distinct technique (no copies that differ only in a literal),
and at least 30 benign controls. These checks need no database.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from pgwarden.redteam.runner import load_corpus
from pgwarden.redteam.scenarios import SCENARIOS

LAYERS = {
    "protocol",
    "read_only_transaction",
    "privileges",
    "rls",
    "masking_view",
    "timeout_or_cap",
    "rate_limit",
    "oauth",
    "approval",
}


def _must_block(case: dict[str, Any]) -> bool:
    return bool(case.get("must_block", "expected_layer" in case))


def _shape(sql: str) -> str:
    """The statement with literals and numbers erased, to spot copies that differ in a literal."""
    text = re.sub(r"'(?:[^']|'')*'", "'?'", sql)
    text = re.sub(r"\$\$.*?\$\$", "'?'", text, flags=re.S)
    text = re.sub(r"\b\d+(?:\.\d+)?\b", "0", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def test_ids_are_unique() -> None:
    ids = [c["id"] for c in load_corpus()]
    assert [i for i, n in Counter(ids).items() if n > 1] == []


def test_at_least_120_must_block_and_8_per_category() -> None:
    attacks = [c for c in load_corpus() if _must_block(c)]
    per_category = Counter(c["category"] for c in attacks)
    assert set(per_category) == set("ABCDEFGHI")
    # the flood case only runs with --allow-load, so it does not count towards the minimums
    counted = [c for c in attacks if "flood" not in c["title"].lower()]
    per_counted = Counter(c["category"] for c in counted)
    assert all(per_counted[cat] >= 8 for cat in "ABCDEFGHI"), per_counted
    assert len(counted) >= 120, len(counted)


def test_at_least_30_benign_controls() -> None:
    assert sum(1 for c in load_corpus() if c["category"] == "benign") >= 30


def test_every_must_block_case_names_a_known_layer_and_an_oracle_or_scenario() -> None:
    for case in load_corpus():
        if not _must_block(case):
            continue
        assert case["expected_layer"] in LAYERS, case["id"]
        assert case.get("oracles") or case.get("scenario"), case["id"]


def test_every_scenario_name_is_registered() -> None:
    for case in load_corpus():
        if "scenario" in case:
            assert case["scenario"] in SCENARIOS, case["id"]


def test_no_two_attacks_in_a_category_differ_only_in_a_literal() -> None:
    # The same statement run by a different principal is a different attack when the
    # principals hold different grants (G01 to G03: support, analyst, machine).
    seen: dict[tuple[str, str, str, str], str] = {}
    for case in load_corpus():
        if not _must_block(case):
            continue
        args = case.get("args", {})
        sql = args.get("sql") or args.get("name") or args.get("schema") or ""
        if case.get("scenario"):
            # procedures share code but differ in the technique they stage
            sql = f"{case['scenario']}|{args.get('mode', '')}|{args.get('sql', '')}"
        key = (
            case["category"],
            case.get("tool", "scenario"),
            case.get("identity", ""),
            _shape(str(sql)),
        )
        assert key not in seen, f"{case['id']} repeats {seen[key]} up to literals"
        seen[key] = case["id"]


def test_titles_are_distinct_within_a_category() -> None:
    titles: dict[str, set[str]] = defaultdict(set)
    for case in load_corpus():
        assert case["title"] not in titles[case["category"]], case["id"]
        titles[case["category"]].add(case["title"])
