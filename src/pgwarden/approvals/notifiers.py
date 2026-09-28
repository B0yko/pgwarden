"""Approval notifications: a Slack incoming webhook, SMTP email, and a log sink.

A notification carries a short summary and the signed approval link only --
never the SQL text, the parameters or the proposer's free-text reason -- so no
PII from the proposed write lands in chat or in mailboxes. The approver sees
the full statement on the (login-gated) approval page. A failing channel is
logged and never blocks the proposal.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
from email.message import EmailMessage
from typing import Protocol
from urllib.parse import urlsplit

import httpx

log = logging.getLogger("pgwarden.approvals")


@dataclasses.dataclass(frozen=True)
class ApprovalNotice:
    proposal_id: str
    proposer: str
    operation: str
    relation: str | None
    estimated_rows: int | None
    expires_at: dt.datetime
    link: str

    def summary(self) -> str:
        target = self.relation or "a table"
        rows = "unknown" if self.estimated_rows is None else str(self.estimated_rows)
        return (
            f"pgwarden: {self.proposer} proposes an {self.operation.upper()} on {target} "
            f"(estimated rows: {rows}). Proposal {self.proposal_id}, "
            f"approvable until {self.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
        )

    def text(self) -> str:
        return f"{self.summary()}\nReview it here: {self.link}"


class Notifier(Protocol):
    name: str

    async def send(self, notice: ApprovalNotice) -> None: ...


class LogNotifier:
    name = "log"

    async def send(self, notice: ApprovalNotice) -> None:
        log.info("%s", notice.text())


class SlackNotifier:
    """Slack incoming webhook: POST {"text": ...} as JSON."""

    name = "slack"

    def __init__(
        self, webhook_url: str, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.webhook_url = webhook_url
        self.transport = transport

    def payload(self, notice: ApprovalNotice) -> dict[str, str]:
        return {"text": f"{notice.summary()} <{notice.link}|Review the proposal>"}

    async def send(self, notice: ApprovalNotice) -> None:
        async with httpx.AsyncClient(transport=self.transport, timeout=5.0) as client:
            response = await client.post(self.webhook_url, json=self.payload(notice))
            response.raise_for_status()


class SmtpNotifier:
    """Email via SMTP (PGWARDEN_SMTP_URL such as smtp://mailpit:1025 or smtps://user:pw@host)."""

    name = "smtp"

    def __init__(self, smtp_url: str, *, sender: str, recipients: list[str]) -> None:
        self.smtp_url = smtp_url
        self.sender = sender
        self.recipients = recipients

    def message(self, notice: ApprovalNotice) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = f"pgwarden approval requested: {notice.operation} on {notice.relation}"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(notice.text())
        return msg

    async def send(self, notice: ApprovalNotice) -> None:
        import aiosmtplib

        if not self.recipients:
            log.warning("smtp notifier has no recipients; skipping")
            return
        parts = urlsplit(self.smtp_url)
        use_tls = parts.scheme == "smtps"
        await aiosmtplib.send(
            self.message(notice),
            hostname=parts.hostname or "localhost",
            port=parts.port or (465 if use_tls else 25),
            username=parts.username,
            password=parts.password,
            use_tls=use_tls,
            start_tls=parts.scheme == "smtp+starttls",
            timeout=10,
        )


async def notify_all(notifiers: list[Notifier], notice: ApprovalNotice) -> list[str]:
    """Send on every channel; return the names of channels that failed (logged, not raised)."""
    failed: list[str] = []
    for notifier in notifiers:
        try:
            await notifier.send(notice)
        except Exception:  # noqa: BLE001 - a notification failure must not block the proposal
            log.exception("approval notification via %s failed", notifier.name)
            failed.append(notifier.name)
    return failed


__all__ = [
    "ApprovalNotice",
    "LogNotifier",
    "Notifier",
    "SlackNotifier",
    "SmtpNotifier",
    "notify_all",
]
