"""Drive the pinned MCP Inspector through pgwarden's OAuth flow in headless Chromium.

Development tooling only: this directory is not part of the wheel or the production
image. `run.py` uses it to produce the README screenshots, and
`tests/stack/test_inspector_oauth.py` uses it to assert that the Inspector's own
OAuth client (dynamic client registration, PKCE S256, RFC 8707 resource) gets through
pgwarden's consent screen, the upstream sign-in and the confirmation, ends up
authenticated, and can list and call the gateway's tools.

The Inspector is started fresh for every session, with an in-memory secret store and a
throwaway storage directory, so no token survives between sessions and nothing is
written to the OS keychain or to the user's home directory.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

import httpx
from playwright.async_api import Page, expect
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

# The Inspector release the README and the CI check are pinned to.
INSPECTOR_VERSION = "2.8.0"
INSPECTOR_PACKAGE = f"@modelcontextprotocol/inspector@{INSPECTOR_VERSION}"

# Inspector default ports (web UI, MCP Apps sandbox, MCP Apps app origin), then a
# fixed fallback set for machines where one of them is taken.
_PORT_SETS = ((6274, 6275, 6278), (6374, 6375, 6378), (6474, 6475, 6478))

VIEWPORT = {"width": 1440, "height": 900}
EXPECTED_TOOLS = ("whoami", "list_tables", "describe_table", "query")


class InspectorUnavailable(RuntimeError):
    """npx or Playwright's Chromium is missing; callers may skip instead of failing."""


@dataclasses.dataclass(frozen=True)
class StackUrls:
    gateway: str
    idp: str
    mailpit: str

    @classmethod
    def from_env(cls, repo_root: Path) -> StackUrls:
        """Ports from .env (or PGWARDEN_STACK_ENV_FILE), overridden by *_PORT variables."""
        env_file = Path(os.environ.get("PGWARDEN_STACK_ENV_FILE", repo_root / ".env"))
        values: dict[str, str] = {}
        if env_file.is_file():
            for raw in env_file.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    values[key.strip()] = value.strip()
        values.update({k: v for k, v in os.environ.items() if k.endswith("_PORT")})
        return cls(
            gateway=f"http://localhost:{values.get('GATEWAY_PORT', '8080')}",
            idp=f"http://localhost:{values.get('IDP_PORT', '9400')}",
            mailpit=f"http://localhost:{values.get('MAILPIT_WEB_PORT', '8025')}",
        )


def find_npx() -> str:
    npx = os.environ.get("PGWARDEN_NPX") or shutil.which("npx")
    if not npx:
        raise InspectorUnavailable("npx is not on PATH (set PGWARDEN_NPX to its location)")
    return npx


def _port_free(port: int) -> bool:
    for host in ("127.0.0.1", "::1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            # Like a listening server: a port in TIME_WAIT from the last session is usable.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError as exc:
                # No IPv6 on this host is fine; an address in use is not.
                if exc.errno in (48, 98):
                    return False
    return True


def _pick_ports() -> tuple[int, int, int]:
    for ports in _PORT_SETS:
        if all(_port_free(p) for p in ports):
            return ports
    raise InspectorUnavailable("no free port set for the Inspector (6274/6374/6474 ranges)")


class InspectorProcess:
    """`npx @modelcontextprotocol/inspector@<pinned> --web` for one session."""

    def __init__(self, gateway_mcp_url: str) -> None:
        self.gateway_mcp_url = gateway_mcp_url
        self.ports = _pick_ports()
        self.token = secrets.token_urlsafe(16)
        self._proc: subprocess.Popen[bytes] | None = None
        self._tmp: Path | None = None
        self._log: Path | None = None

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.ports[0]}"

    @property
    def url(self) -> str:
        return f"{self.origin}/?MCP_INSPECTOR_API_TOKEN={self.token}"

    async def __aenter__(self) -> InspectorProcess:
        npx = find_npx()
        self._tmp = Path(tempfile.mkdtemp(prefix="pgwarden-inspector-"))
        self._log = self._tmp / "inspector.log"
        env = {
            **os.environ,
            "CLIENT_PORT": str(self.ports[0]),
            "MCP_SANDBOX_PORT": str(self.ports[1]),
            "MCP_APP_ORIGIN_PORT": str(self.ports[2]),
            "MCP_AUTO_OPEN_ENABLED": "false",
            "MCP_INSPECTOR_API_TOKEN": self.token,
            "MCP_INSPECTOR_SECRET_STORE": "memory",
            "MCP_STORAGE_DIR": str(self._tmp / "storage"),
        }
        with self._log.open("wb") as log:
            self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, pinned package
                [
                    npx,
                    "--yes",
                    INSPECTOR_PACKAGE,
                    "--web",
                    "--server-url",
                    self.gateway_mcp_url,
                    "--transport",
                    "http",
                ],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        try:
            await self._wait_ready()
        except BaseException:
            await self.__aexit__(None, None, None)
            raise
        return self

    async def _wait_ready(self, timeout_s: float = 120.0) -> None:
        assert self._proc is not None
        deadline = time.monotonic() + timeout_s
        async with httpx.AsyncClient(timeout=2) as client:
            while time.monotonic() < deadline:
                if self._proc.poll() is not None:
                    raise InspectorUnavailable(f"the Inspector exited early:\n{self._tail()}")
                with contextlib.suppress(httpx.HTTPError):
                    if (await client.get(self.url)).status_code == 200:
                        return
                await asyncio.sleep(0.5)
        raise InspectorUnavailable(
            f"the Inspector did not come up in {timeout_s:.0f}s:\n{self._tail()}"
        )

    def _tail(self) -> str:
        if self._log and self._log.is_file():
            return "\n".join(self._log.read_text(errors="replace").splitlines()[-15:])
        return ""

    async def __aexit__(self, *_exc: object) -> None:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            # npx starts the Inspector as a child; stop the whole process group.
            for sig in (signal.SIGTERM, signal.SIGKILL):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, sig)
                for _ in range(20):
                    if proc.poll() is not None:
                        break
                    await asyncio.sleep(0.25)
                if proc.poll() is not None:
                    break
        if self._tmp is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)


@dataclasses.dataclass
class Connected:
    user: str
    tools: list[str]
    pg_role: str


async def connect_via_oauth(
    page: Page,
    inspector: InspectorProcess,
    urls: StackUrls,
    user: str,
    *,
    on_consent: Callable[[Page], Awaitable[None]] | None = None,
) -> Connected:
    """Click Connect in the Inspector and walk pgwarden's browser flow as `user`.

    Consent (pgwarden) -> user picker (mock IdP) -> confirmation (pgwarden) -> back in
    the Inspector, connected, with the tool list visible. Every step is asserted.
    """
    await page.goto(inspector.url)
    await expect(page.get_by_text("Disconnected", exact=True)).to_be_visible()
    await page.locator(".mantine-Switch-track").first.click()

    # 1. pgwarden's consent screen: the Inspector's DCR client, resource = the /mcp URL.
    try:
        await page.wait_for_url(f"{urls.gateway}/oauth/authorize?**", timeout=20_000)
    except PlaywrightTimeoutError as exc:
        shown = (await page.inner_text("body"))[:600]
        raise AssertionError(
            "the Inspector did not reach pgwarden's consent screen (a 429 from the "
            f"20-per-hour registration limit looks like this). The page shows:\n{shown}"
        ) from exc
    await expect(
        page.get_by_role("heading", name="Connect an assistant to your database?")
    ).to_be_visible()
    body = await page.inner_text("body")
    assert "MCP Inspector" in body, body
    assert f"{urls.gateway}/mcp" in body, body
    assert inspector.origin.removeprefix("http://") in body, body
    if on_consent is not None:
        await on_consent(page)
    await page.get_by_role("button", name="Continue to sign in").click()

    # 2. the mock IdP's user picker
    await page.wait_for_url(f"{urls.idp}/authorize?**", timeout=20_000)
    await page.get_by_role(
        "button", name=re.compile(rf"\({re.escape(user)}@example\.com\)")
    ).click()

    # 3. pgwarden's confirmation: who you are, which Postgres role you will use
    await page.wait_for_url(f"{urls.gateway}/oauth/callback?**", timeout=20_000)
    await expect(page.get_by_role("heading", name="Confirm access")).to_be_visible()
    pg_role = f"pw_u_{user}"
    await expect(page.get_by_text(pg_role, exact=True)).to_be_visible()
    await page.get_by_role("button", name="Allow").click()

    # 4. back in the Inspector: authenticated and connected
    await page.wait_for_url(f"{inspector.origin}/**", timeout=30_000)
    await expect(page.get_by_text("Connected", exact=True)).to_be_visible(timeout=30_000)
    await page.get_by_text("Tools", exact=True).first.click()
    for tool in EXPECTED_TOOLS:
        await expect(
            page.locator("button.list-item", has_text=re.compile(rf"^{tool}$"))
        ).to_be_visible()
    names = await page.locator("button.list-item").all_inner_texts()
    return Connected(user=user, tools=[n.strip() for n in names], pg_role=pg_role)


async def close_monitor_sidebar(page: Page) -> None:
    """Give the tool form and result the full width (the Protocol pane is not needed)."""
    button = page.get_by_role("button", name="Close monitoring sidebar")
    if await button.count():
        await button.click()


async def _ace_set(page: Page, index: int, value: str) -> None:
    await (
        page.locator(".ace_editor")
        .nth(index)
        .evaluate("(el, v) => el.env.editor.setValue(v, -1)", value)
    )


async def run_tool(page: Page, tool: str, arguments: dict[str, object]) -> dict[str, object]:
    """Open `tool` in the Inspector's Tools tab, run it with `arguments` and return its result.

    Arguments are entered through the form's own "Edit as JSON" editor; the returned
    dict is the tool's JSON result as the Inspector displays it.
    """
    await page.locator("button.list-item", has_text=re.compile(rf"^{tool}$")).click()
    # Re-opening the tool that produced the visible result shows the result again;
    # close it to get the form back.
    await dismiss_results(page)
    toggle = page.get_by_label("Edit as JSON")
    await toggle.check(force=True)
    editor = page.locator(".ace_editor").first
    await expect(editor).to_be_visible()
    await _ace_set(page, 0, json.dumps(arguments, indent=2))
    execute = page.get_by_role("button", name="Execute Tool")
    await expect(execute).to_be_enabled()
    await execute.click()
    results = page.get_by_role("heading", name="Results")
    await expect(results).to_be_visible(timeout=30_000)
    return await _read_result(page)


async def _read_result(page: Page) -> dict[str, object]:
    # The Results pane's first read-only editor holds the tool's text content (JSON).
    text = await page.locator(".ace_editor").first.evaluate("el => el.env.editor.getValue()")
    parsed = json.loads(text)
    assert isinstance(parsed, dict), text
    return parsed


async def dismiss_results(page: Page) -> None:
    close = page.get_by_role("button", name="Close results")
    if await close.count():
        await close.click()
