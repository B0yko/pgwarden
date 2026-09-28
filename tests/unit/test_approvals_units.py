"""Unit tests for the write path's pure pieces: the plan-tree rule, signed links,
the binding HMAC and notification payloads (which must never carry SQL or params).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json

import httpx

from pgwarden.approvals.links import LINK_TTL_S, approval_link, binding_hmac, verify_link
from pgwarden.approvals.notifiers import ApprovalNotice, SlackNotifier, SmtpNotifier
from pgwarden.approvals.validate import check_plan

NOW = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.UTC)
SECRET = "unit-test-session-secret"


def _plan(root: dict[str, object]) -> list[dict[str, object]]:
    return [{"Plan": root}]


def test_single_root_modifytable_is_accepted() -> None:
    result = check_plan(
        _plan(
            {
                "Node Type": "ModifyTable",
                "Operation": "Update",
                "Relation Name": "support_tickets",
                "Plans": [{"Node Type": "Index Scan", "Plan Rows": 1}],
            }
        )
    )
    assert result.ok and result.plan is not None
    assert result.plan.operation == "Update"
    assert result.plan.relation == "support_tickets"
    assert result.plan.estimated_rows == 1


def test_plain_select_is_rejected() -> None:
    assert not check_plan(_plan({"Node Type": "Seq Scan", "Plan Rows": 10})).ok


def test_cte_write_under_insert_is_rejected() -> None:
    # WITH d AS (DELETE ...) INSERT ... -> two ModifyTable nodes.
    plan = _plan(
        {
            "Node Type": "ModifyTable",
            "Operation": "Insert",
            "Plans": [
                {
                    "Node Type": "ModifyTable",
                    "Operation": "Delete",
                    "Parent Relationship": "InitPlan",
                    "Subplan Name": "CTE d",
                },
                {"Node Type": "CTE Scan"},
            ],
        }
    )
    result = check_plan(plan)
    assert not result.ok and "more than once" in (result.reason or "")


def test_select_with_data_modifying_cte_is_rejected() -> None:
    plan = _plan(
        {
            "Node Type": "CTE Scan",
            "Plans": [{"Node Type": "ModifyTable", "Operation": "Delete", "Subplan Name": "CTE d"}],
        }
    )
    result = check_plan(plan)
    assert not result.ok and "inside a CTE" in (result.reason or "")


def test_merge_is_rejected() -> None:
    assert not check_plan(_plan({"Node Type": "ModifyTable", "Operation": "Merge"})).ok


def test_plan_as_json_string_is_parsed() -> None:
    text = json.dumps(_plan({"Node Type": "ModifyTable", "Operation": "Insert", "Plan Rows": 1}))
    assert check_plan(text).ok


def test_link_round_trip_and_tamper_and_expiry() -> None:
    link = approval_link("http://localhost:8080", SECRET, "abc123", now=NOW)
    assert link.startswith("http://localhost:8080/approve/abc123?")
    query = dict(p.split("=", 1) for p in link.split("?", 1)[1].split("&"))
    assert verify_link(SECRET, "abc123", query["exp"], query["sig"], now=NOW)
    assert not verify_link(SECRET, "other", query["exp"], query["sig"], now=NOW)
    assert not verify_link(SECRET, "abc123", query["exp"], "0" * 64, now=NOW)
    assert not verify_link("other-secret", "abc123", query["exp"], query["sig"], now=NOW)
    later = NOW + dt.timedelta(seconds=LINK_TTL_S + 1)
    assert not verify_link(SECRET, "abc123", query["exp"], query["sig"], now=later)
    assert not verify_link(SECRET, "abc123", None, query["sig"], now=NOW)


def test_binding_changes_with_any_input() -> None:
    base = binding_hmac(SECRET, "UPDATE t SET a = $1", '["x"]', "writer")
    assert base == binding_hmac(SECRET, "UPDATE t SET a = $1", '["x"]', "writer")
    assert base != binding_hmac(SECRET, "UPDATE t SET a = $2", '["x"]', "writer")
    assert base != binding_hmac(SECRET, "UPDATE t SET a = $1", '["y"]', "writer")
    assert base != binding_hmac(SECRET, "UPDATE t SET a = $1", '["x"]', "other")


NOTICE = ApprovalNotice(
    proposal_id="p-1",
    proposer="bob@example.com",
    operation="Update",
    relation="support_tickets",
    estimated_rows=1,
    expires_at=NOW + dt.timedelta(hours=24),
    link="http://localhost:8080/approve/p-1?exp=1&sig=ab",
)
SECRET_SQL = "UPDATE support_tickets SET status = $1 WHERE id = $2"
SECRET_PARAM = "customer-ssn-123-45-6789"


def test_notifications_carry_summary_and_link_only() -> None:
    text = NOTICE.text()
    assert NOTICE.link in text and "support_tickets" in text
    assert "SET status" not in text and SECRET_PARAM not in text

    slack = SlackNotifier("https://hooks.slack.example.com/services/T/B/X").payload(NOTICE)
    assert set(slack) == {"text"}
    assert NOTICE.link in slack["text"] and "SET status" not in slack["text"]

    email = SmtpNotifier(
        "smtp://mailpit:1025", sender="pgwarden@example.com", recipients=["a@example.com"]
    )
    body = email.message(NOTICE).get_content()
    assert NOTICE.link in body and "SET status" not in body


def test_slack_send_posts_json() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["type"] = request.headers["content-type"]
        return httpx.Response(200, text="ok")

    notifier = SlackNotifier(
        "https://hooks.slack.example.com/services/T/B/X", transport=httpx.MockTransport(handler)
    )
    asyncio.run(notifier.send(NOTICE))
    assert seen["type"] == "application/json"
    assert "text" in seen["body"]  # type: ignore[operator]
