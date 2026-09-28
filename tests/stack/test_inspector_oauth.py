"""The MCP Inspector's own OAuth client, driven in headless Chromium, against the live stack.

Runs the pinned Inspector (`@modelcontextprotocol/inspector@2.8.0`, see
devtools/screenshots/flows.py) and clicks Connect: the Inspector registers itself
(dynamic client registration), sends PKCE S256 and the RFC 8707 `resource`, and the
browser walks pgwarden's consent screen, the mock IdP's user picker and pgwarden's
confirmation. The test asserts the session ends up authenticated (the Inspector shows
"Connected" with the tool list, and `whoami` answers as the Postgres role for bob).
The same helpers produce the README screenshots (devtools/screenshots/run.py).

Skips cleanly when npx, Playwright's Chromium or the stack is missing, unless
PGWARDEN_REQUIRE_STACK=1 (CI), which turns every skip into a failure.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

from helpers.stack import Stack

pytestmark = pytest.mark.stack

SCREENSHOTS_DIR = Path(__file__).parent.parent.parent / "devtools" / "screenshots"


def _unavailable(reason: str) -> None:
    if os.environ.get("PGWARDEN_REQUIRE_STACK") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope="module")
def flows() -> ModuleType:
    pytest.importorskip("playwright.async_api")
    if not (os.environ.get("PGWARDEN_NPX") or shutil.which("npx")):
        _unavailable("npx is not on PATH (set PGWARDEN_NPX)")
    sys.path.insert(0, str(SCREENSHOTS_DIR))
    try:
        import flows as module  # devtools/screenshots/flows.py, not part of the wheel
    finally:
        sys.path.remove(str(SCREENSHOTS_DIR))
    return module


def test_inspector_oauth_connects_and_lists_tools_as_bob(stack: Stack, flows: ModuleType) -> None:
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import async_playwright

    urls = flows.StackUrls(gateway=stack.base_url, idp=stack.idp_url, mailpit=stack.mailpit_url)

    async def run() -> None:
        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch(headless=True)
            except PlaywrightError as exc:
                raise flows.InspectorUnavailable(
                    f"Chromium is not installed (uv run playwright install chromium): {exc}"
                ) from exc
            try:
                context = await browser.new_context(viewport=flows.VIEWPORT, color_scheme="light")
                page = await context.new_page()
                async with flows.InspectorProcess(f"{urls.gateway}/mcp") as inspector:
                    connected = await flows.connect_via_oauth(page, inspector, urls, "bob")
                    assert connected.pg_role == "pw_u_bob"
                    assert set(flows.EXPECTED_TOOLS) <= set(connected.tools), connected.tools
                    # Authenticated for real: a tool call as the person, not just a tool list.
                    await flows.close_monitor_sidebar(page)
                    who = await flows.run_tool(page, "whoami", {})
                    assert who["pg_role"] == "pw_u_bob", who
                    assert who["email"] == "bob@example.com", who
            finally:
                await browser.close()

    try:
        asyncio.run(run())
    except flows.InspectorUnavailable as exc:
        _unavailable(str(exc))
