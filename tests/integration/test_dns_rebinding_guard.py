"""The /mcp endpoint rejects requests aimed at a foreign Host or Origin (DNS rebinding).

A browser tricked into resolving an attacker's hostname to the gateway's address sends
that hostname in `Host` and the attacker's page in `Origin`. Both must be refused even
when the request carries a valid bearer token, and a request that names the gateway's
own host must still work.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio

from helpers.gateway import Harness, run_gateway
from pgwarden.config import Config
from pgwarden.identity import person_subject

pytestmark = pytest.mark.pg

_WHOAMI: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "whoami",
        "arguments": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    },
}
_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Mcp-Protocol-Version": "2026-07-28",
    "Mcp-Method": "tools/call",
    "Mcp-Name": "whoami",
}


@pytest_asyncio.fixture
async def harness(
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_demo_masking: None,
    pg_role_secret: str,
    pg_demo_config: object,
) -> AsyncIterator[Harness]:
    assert isinstance(pg_demo_config, Config)
    async for h in run_gateway(pg_demo_config, pg_target_dsn, pg_state_dsn, pg_role_secret):
        yield h


async def _post(harness: Harness, **extra_headers: str) -> int:
    token = harness.token(person_subject("alice"))
    async with harness.raw(token) as http:
        resp = await http.post("/mcp", headers={**_HEADERS, **extra_headers}, json=_WHOAMI)
    return resp.status_code


async def test_the_gateways_own_host_is_accepted(harness: Harness) -> None:
    assert await _post(harness) == 200


async def test_a_foreign_host_header_is_rejected(harness: Harness) -> None:
    assert await _post(harness, Host="attacker.example") in (403, 421)


async def test_a_foreign_origin_header_is_rejected(harness: Harness) -> None:
    assert await _post(harness, Origin="https://attacker.example") == 403
