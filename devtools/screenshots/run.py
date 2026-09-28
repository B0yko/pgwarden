"""Drive a real session against the running demo stack and write the README screenshots.

    docker compose up -d --wait
    uv run playwright install chromium        # once
    uv run python devtools/screenshots/run.py

What it does, all in headless Chromium at a fixed 1440x900 viewport, light colour scheme,
UTC and en-US (page content only, no browser chrome):

1. Starts the pinned MCP Inspector (`npx @modelcontextprotocol/inspector@2.8.0`) and
   connects it to the gateway's /mcp over streamable HTTP through its own OAuth client
   (dynamic client registration, PKCE S256, RFC 8707 resource):
   pgwarden's consent screen -> the mock IdP's user picker -> pgwarden's confirmation ->
   back in the Inspector, connected, tool list visible. Every step is asserted.
   - as alice: consent screen (screenshot 1), then a masked `query` (screenshot 2), then
     two attempts the database refuses (a raw-table read and a write), which land in the audit log.
   - as bob: the same flow, then `propose_write` through the Inspector's tool form.
2. Opens the approval notice that arrived in Mailpit (screenshot 3; summary and link,
   no SQL).
3. Signs in as carol, opens the admin audit page filtered to alice (screenshot 4), then
   rejects the proposal from bob so the demo stack is left without a pending write.
4. Re-encodes every PNG from its pixels (no text, EXIF, time or ICC chunks), verifies the
   chunk list, and writes the files to docs/media/.

Re-runnable: the same four files are replaced on every run. The stack is only driven
through the browser; nothing is restarted or reconfigured. Each run registers two OAuth
clients (the gateway limits registrations to 20 per hour per address) and makes one
proposal for bob (10 per hour).

`--check-only` runs just bob's Inspector OAuth connect and asserts the tool list.
Exit codes: 0 success, 1 a check failed, 2 npx, Chromium or the stack is unavailable.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote

import httpx
from playwright.async_api import Browser, BrowserContext, Page, async_playwright, expect
from playwright.async_api import Error as PlaywrightError

import flows
import pngmeta
from flows import InspectorProcess, InspectorUnavailable, StackUrls

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "docs" / "media"

FILES = {
    "consent": "01-consent-screen.png",
    "masked_query": "02-masked-query-alice.png",
    "approval_email": "03-approval-email-mailpit.png",
    "audit": "04-admin-audit.png",
}

MASKED_SQL = "SELECT full_name, email FROM customers ORDER BY id LIMIT 5"
RAW_TABLE_SQL = "SELECT full_name, email FROM public.customers LIMIT 1"
WRITE_SQL = "DELETE FROM orders"
PROPOSAL = {
    "sql": "UPDATE support_tickets SET status = $1 WHERE id = $2",
    "params": ["pending_customer", 1],
    "reason": "Customer asked to wait for their reply before closing the ticket.",
    "max_rows": 1,
}


async def new_context(browser: Browser) -> BrowserContext:
    return await browser.new_context(
        viewport=flows.VIEWPORT,
        color_scheme="light",
        timezone_id="UTC",
        locale="en-US",
        device_scale_factor=1,
    )


async def ensure_stack(urls: StackUrls) -> None:
    async with httpx.AsyncClient(timeout=5) as client:
        for name, url in (
            ("gateway", f"{urls.gateway}/readyz"),
            ("mock IdP", f"{urls.idp}/healthz"),
        ):
            try:
                ok = (await client.get(url)).status_code == 200
            except httpx.HTTPError:
                ok = False
            if not ok:
                raise InspectorUnavailable(
                    f"the {name} is not reachable at {url}; run docker compose up -d --wait"
                )
        try:
            (await client.get(f"{urls.mailpit}/api/v1/info")).raise_for_status()
        except httpx.HTTPError as exc:
            raise InspectorUnavailable(f"Mailpit is not reachable at {urls.mailpit}") from exc


async def alice_session(browser: Browser, urls: StackUrls, shots: dict[str, bytes]) -> None:
    context = await new_context(browser)
    page = await context.new_page()
    async with InspectorProcess(f"{urls.gateway}/mcp") as inspector:

        async def capture_consent(p: Page) -> None:
            shots["consent"] = await p.screenshot()

        connected = await flows.connect_via_oauth(
            page, inspector, urls, "alice", on_consent=capture_consent
        )
        assert connected.pg_role == "pw_u_alice"
        await flows.close_monitor_sidebar(page)

        masked = await flows.run_tool(page, "query", {"sql": MASKED_SQL})
        rows = masked["rows_untrusted"]
        assert isinstance(rows, list) and len(rows) == 5, masked
        assert all("***" in str(row["email"]) for row in rows), f"email not masked: {rows}"
        # The Inspector's "Authorization complete" toast covers a corner until it fades.
        await expect(page.get_by_text("Authentication succeeded.")).to_be_hidden(timeout=20_000)
        shots["masked_query"] = await page.screenshot()

        # Two refusals for the audit page: reading the raw table and writing.
        raw = await flows.run_tool(page, "query", {"sql": RAW_TABLE_SQL})
        assert "error" in raw and "rows_untrusted" not in raw, raw
        write = await flows.run_tool(page, "query", {"sql": WRITE_SQL})
        assert "error" in write and "rows_untrusted" not in write, write
    await context.close()


async def bob_session(browser: Browser, urls: StackUrls, *, propose: bool) -> str | None:
    """Connect as bob through the Inspector; optionally propose a write. Returns its id."""
    context = await new_context(browser)
    page = await context.new_page()
    proposal_id: str | None = None
    async with InspectorProcess(f"{urls.gateway}/mcp") as inspector:
        connected = await flows.connect_via_oauth(page, inspector, urls, "bob")
        assert connected.pg_role == "pw_u_bob"
        assert set(flows.EXPECTED_TOOLS) <= set(connected.tools), connected.tools
        if propose:
            await flows.close_monitor_sidebar(page)
            who = await flows.run_tool(page, "whoami", {})
            assert who["pg_role"] == "pw_u_bob", who
            result = await flows.run_tool(page, "propose_write", PROPOSAL)
            assert result.get("state") == "pending", result
            proposal_id = str(result["proposal_id"])
    await context.close()
    return proposal_id


async def _find_mail(urls: StackUrls, proposal_id: str, timeout_s: float = 20.0) -> str:
    deadline = time.monotonic() + timeout_s
    async with httpx.AsyncClient(timeout=5, base_url=urls.mailpit) as client:
        while time.monotonic() < deadline:
            found = (await client.get("/api/v1/search", params={"query": proposal_id})).json()
            if found["messages"]:
                message = (await client.get(f"/api/v1/message/{found['messages'][0]['ID']}")).json()
                return str(message["Text"])
            await asyncio.sleep(0.5)
    raise AssertionError(f"no approval email for proposal {proposal_id} in Mailpit")


async def mailpit_shot(browser: Browser, urls: StackUrls, proposal_id: str) -> tuple[bytes, str]:
    text = await _find_mail(urls, proposal_id)
    # Summary and link only: neither the statement nor its parameters travel by email.
    assert "SET status" not in text and "pending_customer" not in text, text
    link = re.search(r"http\S+/approve/\S+", text)
    assert link, text
    context = await new_context(browser)
    page = await context.new_page()
    await page.goto(f"{urls.mailpit}/search?q={quote(proposal_id)}")
    await page.locator(".message").first.click()
    await expect(page.get_by_text("Review it here")).to_be_visible()
    png = await page.screenshot()
    await context.close()
    return png, link.group(0)


async def _sign_in_as_carol(page: Page, urls: StackUrls, target_path: str) -> None:
    await page.goto(f"{urls.gateway}{target_path}")
    await page.wait_for_url(f"{urls.idp}/authorize?**", timeout=20_000)
    await page.get_by_role("button", name=re.compile(r"\(carol@example\.com\)")).click()
    await page.wait_for_url(f"{urls.gateway}{target_path.split('?')[0]}**", timeout=20_000)


async def carol_session(
    browser: Browser, urls: StackUrls, approve_link: str, proposal_id: str
) -> bytes:
    context = await new_context(browser)
    page = await context.new_page()
    await _sign_in_as_carol(page, urls, "/admin/audit?identity=alice%40example.com")
    await expect(page.get_by_role("heading", name="Audit log")).to_be_visible()
    first_rows = (await page.locator("tbody tr").first.inner_text()).lower()
    assert "pw_u_alice" in first_rows and "query" in first_rows, first_rows
    body = await page.inner_text("body")
    for sql in (MASKED_SQL, RAW_TABLE_SQL, WRITE_SQL):
        assert sql in body, f"audit page does not show: {sql}"
    png = await page.screenshot()

    # Leave the demo stack without a pending write: carol reviews and rejects it.
    await page.goto(approve_link)
    await expect(page.get_by_role("heading", name="Review a proposed write")).to_be_visible()
    await expect(page.get_by_text(proposal_id)).to_be_visible()
    await page.get_by_role("button", name="Reject").click()
    await expect(page.get_by_text("Rejected.")).to_be_visible()
    await context.close()
    return png


def write_pngs(out_dir: Path, shots: dict[str, bytes]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, name in FILES.items():
        clean = pngmeta.strip_metadata(shots[key])
        pngmeta.check_clean(clean, label=name)
        path = out_dir / name
        path.write_bytes(clean)
        chunks = ",".join(pngmeta.check_file(path))
        size = len(clean) / 1024
        shown = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
        print(
            f"wrote {shown} ({flows.VIEWPORT['width']}x{flows.VIEWPORT['height']}, "
            f"{size:.0f} KiB, chunks {chunks})"
        )


async def amain(args: argparse.Namespace) -> None:
    urls = StackUrls.from_env(REPO_ROOT)
    await ensure_stack(urls)
    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(headless=True)
        except PlaywrightError as exc:
            raise InspectorUnavailable(
                f"Chromium is not installed (uv run playwright install chromium): {exc}"
            ) from exc
        try:
            if args.check_only:
                await bob_session(browser, urls, propose=False)
                print(f"OK: Inspector {flows.INSPECTOR_VERSION} OAuth flow reached the tool list")
                return
            shots: dict[str, bytes] = {}
            await alice_session(browser, urls, shots)
            proposal_id = await bob_session(browser, urls, propose=True)
            assert proposal_id is not None
            shots["approval_email"], link = await mailpit_shot(browser, urls, proposal_id)
            shots["audit"] = await carol_session(browser, urls, link, proposal_id)
        finally:
            await browser.close()
    write_pngs(args.out, shots)
    print(
        f"OK: Inspector {flows.INSPECTOR_VERSION} OAuth flow connected as alice and bob; "
        "screenshots written"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--out", type=Path, default=DEFAULT_OUT, help="output directory (docs/media)"
    )
    parser.add_argument(
        "--check-only", action="store_true", help="only run bob's Inspector OAuth check"
    )
    args = parser.parse_args()
    try:
        asyncio.run(amain(args))
    except InspectorUnavailable as exc:
        print(f"unavailable: {exc}", file=sys.stderr)
        return 2
    except (AssertionError, PlaywrightError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
