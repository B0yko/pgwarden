"""A minimal raw MCP client: one ``tools/call`` or ``tools/list`` per HTTP request.

It speaks the stateless 2026-07-28 streamable-HTTP envelope directly (protocol
version and client capabilities in ``_meta``, ``Mcp-Method``/``Mcp-Name``
headers) and returns the HTTP status and the complete response text, so the
red-team oracles can scan everything the gateway sent back, including error
messages, DETAIL and HINT.
"""

from __future__ import annotations

import dataclasses
import json
import secrets
from typing import Any

import httpx

PROTOCOL_VERSION = "2026-07-28"


@dataclasses.dataclass(frozen=True)
class ToolResponse:
    status: int
    text: str
    body: dict[str, Any] | None
    headers: dict[str, str] = dataclasses.field(default_factory=dict)

    @property
    def result(self) -> dict[str, Any]:
        """The tool's structured result (the dict our tools return), or ``{}``."""
        if not self.body:
            return {}
        res = self.body.get("result") or {}
        structured = res.get("structuredContent")
        if isinstance(structured, dict):
            inner = structured.get("result")
            return inner if isinstance(inner, dict) and len(structured) == 1 else structured
        for item in res.get("content") or []:
            if item.get("type") == "text":
                try:
                    parsed = json.loads(item.get("text", ""))
                except ValueError:
                    continue
                if isinstance(parsed, dict):
                    return parsed
        return {}

    @property
    def tool_error(self) -> dict[str, Any] | None:
        err = self.result.get("error")
        return err if isinstance(err, dict) else None


def _headers(token: str | None, method: str, name: str | None) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
    }
    if name is not None:
        headers["Mcp-Name"] = name
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _meta() -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    }


async def call_tool(
    mcp_url: str,
    token: str | None,
    name: str,
    arguments: dict[str, Any],
    *,
    timeout_s: float = 60.0,
    http: httpx.AsyncClient | None = None,
) -> ToolResponse:
    payload = {
        "jsonrpc": "2.0",
        "id": secrets.randbelow(1 << 30),
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": _meta()},
    }
    return await _post(mcp_url, token, "tools/call", name, payload, timeout_s, http)


async def list_tools(mcp_url: str, token: str | None, *, timeout_s: float = 30.0) -> ToolResponse:
    payload = {
        "jsonrpc": "2.0",
        "id": secrets.randbelow(1 << 30),
        "method": "tools/list",
        "params": {"_meta": _meta()},
    }
    return await _post(mcp_url, token, "tools/list", None, payload, timeout_s, None)


async def _post(
    mcp_url: str,
    token: str | None,
    method: str,
    name: str | None,
    payload: dict[str, Any],
    timeout_s: float,
    http: httpx.AsyncClient | None,
) -> ToolResponse:
    own = http is None
    client = http or httpx.AsyncClient(timeout=timeout_s, follow_redirects=False)
    try:
        resp = await client.post(
            mcp_url, headers=_headers(token, method, name), json=payload, timeout=timeout_s
        )
    finally:
        if own:
            await client.aclose()
    try:
        body = resp.json()
    except ValueError:
        body = None
    return ToolResponse(
        status=resp.status_code,
        text=resp.text,
        body=body if isinstance(body, dict) else None,
        headers={k.lower(): v for k, v in resp.headers.items()},
    )


__all__ = ["PROTOCOL_VERSION", "ToolResponse", "call_tool", "list_tools"]
