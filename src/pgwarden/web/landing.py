"""The landing page: how to connect a client, and (demo only) who to sign in as.

``demo.enabled`` changes only what this page shows. It never changes
authentication.
"""

from __future__ import annotations

import json

from fastapi import APIRouter
from starlette.responses import Response

from pgwarden.config import Config, machine_role_name, person_role_name
from pgwarden.web.render import render

INSPECTOR_VERSION = "2.8.0"


def _demo_rows(config: Config) -> list[dict[str, str]]:
    raw = set(config.masking.raw_access_bundles)
    rows: list[dict[str, str]] = []
    for person in config.people:
        masked = not (raw & set(person.bundles))
        rows.append(
            {
                "identity": person.identity.email or person.identity.subject or "",
                "role": person_role_name(person.role),
                "bundles": ", ".join(person.bundles),
                "writer": person.writer or "",
                "access": "PII masked" if masked else "PII raw, rows limited by RLS",
            }
        )
    staff = {ref.email for ref in [*config.approvers, *config.admins] if ref.email}
    for email in sorted(staff):
        duties = []
        if any(ref.email == email for ref in config.approvers):
            duties.append("approver")
        if any(ref.email == email for ref in config.admins):
            duties.append("admin")
        rows.append(
            {
                "identity": email,
                "role": "none",
                "bundles": "",
                "writer": "",
                "access": f"{' and '.join(duties)}; no data access",
            }
        )
    for machine in config.machines:
        rows.append(
            {
                "identity": f"machine {machine.name}",
                "role": machine_role_name(machine.role),
                "bundles": ", ".join(machine.bundles),
                "writer": "",
                "access": "client_credentials",
            }
        )
    rows.append(
        {
            "identity": "anyone else (for example mallory@example.org)",
            "role": "none",
            "bundles": "",
            "writer": "",
            "access": "valid sign-in, not mapped: 403",
        }
    )
    return rows


def build_landing_router(config: Config) -> APIRouter:
    router = APIRouter()
    mcp_url = f"{config.public_url.rstrip('/')}/mcp"
    cursor_json = json.dumps({"mcpServers": {"pgwarden": {"url": mcp_url}}}, indent=2)

    @router.get("/")
    async def landing() -> Response:
        return render(
            "landing.html",
            {
                "mcp_url": mcp_url,
                "idp": config.upstream.name,
                "inspector_version": INSPECTOR_VERSION,
                "cursor_json": cursor_json,
                "demo": config.demo.enabled,
                "demo_rows": _demo_rows(config) if config.demo.enabled else [],
            },
        )

    return router


__all__ = ["INSPECTOR_VERSION", "build_landing_router"]
