"""The red-team release gate, run against the live compose stack (marker `stack`).

Runs the whole deterministic corpus (categories A to I plus the benign controls)
through ``redteam.runner.Runner`` and asserts the gate from the spec: every
must-block attack blocked with the expected observed layer, every benign control
passed, and no failures. The documented residual risks are recorded, not counted.
"""

from __future__ import annotations

import asyncio

import pytest

from helpers.stack import Stack
from pgwarden.redteam.runner import Runner, load_corpus, summarize
from pgwarden.redteam.stack import StackClient

pytestmark = pytest.mark.stack


def _admin_dsn(stack: Stack) -> str:
    # the admin DSN in the secrets directory names the maintenance database; the
    # oracles read the demo (target) database
    return stack.admin_dsn.replace("/postgres?", "/shop?")


def test_redteam_gate_holds_on_the_live_stack(stack: Stack) -> None:
    async def run() -> dict[str, object]:
        runner = Runner(
            StackClient(stack.base_url),
            admin_dsn=_admin_dsn(stack),
            machine_secrets={"nightly-report": stack.machine_secret("nightly-report")},
            state_dsn=stack.state_dsn,
            allow_load=True,
        )
        return summarize(await runner.run(load_corpus()))

    summary = asyncio.run(run())
    assert summary["failures"] == [], summary["failures"]
    assert summary["must_block_blocked"] == summary["must_block_total"]
    assert summary["benign_passed"] == summary["benign_total"]
    assert summary["must_block_total"] >= 120
    # a documented residual risk records the behaviour and is never counted as blocked
    residual = summary["residual_risks"]
    assert isinstance(residual, list) and residual, "the documented residual risks were not run"
    for risk in residual:
        assert "returns data, as documented" in risk["detail"], risk
    by_category = summary["by_category"]
    assert isinstance(by_category, dict)
    for category in "ABCDEFGHI":
        assert by_category[category]["attacks"] >= 8, category
