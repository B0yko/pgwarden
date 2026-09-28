"""Unit tests for the LLM harness's pure logic (no model calls)."""

from __future__ import annotations

from pathlib import Path

from pgwarden.redteam.ledger import BudgetExceeded, Ledger, ModelPrice
from pgwarden.redteam.llm import load_injections, load_tasks

REPO_ROOT = Path(__file__).parent.parent.parent


def test_tasks_have_identity_and_answer_sql() -> None:
    tasks = load_tasks()
    assert len(tasks) == 10
    assert {t["identity"] for t in tasks} == {"alice", "bob"}
    assert all(t["answer_sql"].lower().startswith("select") for t in tasks)


def test_injections_load_with_targets() -> None:
    injections = load_injections(REPO_ROOT / "demo" / "injections.yaml")
    assert len(injections) == 12
    assert any(i.table and "payment_methods" in i.table for i in injections)


def test_ledger_stops_before_budget() -> None:
    ledger = Ledger(budget_usd=1.0, prices={"m": ModelPrice(1e-6, 1e-6)})
    ledger.record("m", 400_000, 400_000, None)  # ~$0.80
    ledger.check_before(headroom_usd=0.05)  # still under
    ledger.record("m", 200_000, 0, None)  # -> ~$1.00
    try:
        ledger.check_before(headroom_usd=0.05)
        raise AssertionError("expected BudgetExceeded")
    except BudgetExceeded:
        pass


def test_ledger_prefers_actual_cost() -> None:
    ledger = Ledger(budget_usd=5.0, prices={"m": ModelPrice(1.0, 1.0)})
    cost = ledger.record("m", 10, 10, actual_usd=0.0031)
    assert cost == 0.0031 and ledger.spent_usd == 0.0031
