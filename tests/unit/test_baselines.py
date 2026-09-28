"""Unit tests for the statement-filter baselines (ADR-0001 evidence)."""

from __future__ import annotations

import pytest

pytest.importorskip("sqlglot")

from pgwarden.bench.baselines import blocklist_allows, evaluate, run, sqlglot_allows


def test_blocklist_misses_function_and_rls_attacks() -> None:
    # A blocklist keyed on "dangerous words" lets these through.
    assert blocklist_allows("SELECT * FROM billing.payment_methods")
    assert blocklist_allows(
        "SELECT query_to_xml('SELECT token FROM billing.payment_methods', false, false, '')"
    )
    # ... but wrongly blocks a legitimate statement that merely contains a semicolon.
    assert not blocklist_allows("SELECT ';'")


def test_sqlglot_allowlist_misses_function_attacks_and_overblocks() -> None:
    assert sqlglot_allows("SELECT 1")
    assert not sqlglot_allows("DELETE FROM refunds")
    assert not sqlglot_allows("SELECT 1; SELECT 2")
    # a read that calls a function is still a SELECT to the parser
    assert sqlglot_allows("SELECT pg_read_file('/etc/passwd')")


def test_evaluation_shows_both_baselines_leak_and_pgwarden_does_not() -> None:
    result = run()
    assert result["sql_attacks_total"] > 40
    for b in result["baselines"]:
        assert b["attacks_let_through"] > 0, b["baseline"]
    assert result["pgwarden"] == {"attacks_let_through": 0, "benign_wrongly_blocked": 0}


def test_evaluate_counts_only_sql_cases() -> None:
    cases = [
        {
            "id": "X1",
            "category": "A",
            "tool": "query",
            "args": {"sql": "DROP TABLE t"},
            "expected_layer": "protocol",
        },
        {
            "id": "X2",
            "category": "G",
            "tool": "describe_table",
            "args": {"name": "x"},
            "expected_layer": "privileges",
        },
        {"id": "B1", "category": "benign", "tool": "query", "args": {"sql": "SELECT 1"}},
    ]
    result = evaluate(cases)
    assert result["sql_attacks_total"] == 1  # the describe_table case is not SQL-bearing
    assert result["benign_total"] == 1
