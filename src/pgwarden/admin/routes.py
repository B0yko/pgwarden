"""The admin UI (item 10): server-rendered, no JavaScript, strict CSP.

Every route requires an OIDC login plus membership of ``admins`` in config;
anyone else gets a 403. Every page view is recorded as an ``admin_view`` audit
event, fail-closed (no audit row, no page). State-changing actions are
CSRF-protected POSTs. Access itself is config as code: there is no role or grant
editing here, only suspension.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Request
from starlette.responses import RedirectResponse, Response

from pgwarden.approvals.links import approval_link
from pgwarden.approvals.service import ApprovalService
from pgwarden.config import machine_role_name, person_role_name
from pgwarden.identity import machine_subject, person_subject
from pgwarden.oauth import binding, store
from pgwarden.oauth.authorize import WebAuth
from pgwarden.state import audit
from pgwarden.state.audit import AuditError, AuditFilter
from pgwarden.web.render import message, render
from pgwarden.web.sessions import WebSession

PAGE_SIZE = 50
_OUTCOMES = ("ok", "denied", "error", "blocked", "rate_limited", "started")


def _parse_date(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value).replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def build_admin_router(web: WebAuth, approvals: ApprovalService) -> APIRouter:
    router = APIRouter()
    config = web.gateway.config

    async def guard(request: Request, section: str) -> WebSession | Response:
        session = await web.current_session(request)
        if session is None:
            target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(f"/login?next={quote(target, safe='')}", status_code=303)
        async with web.gateway.require_state_pool().acquire() as conn:
            is_admin = await binding.any_matches(conn, config.admins, session.identity, web.now())
            try:
                await audit.record(
                    conn,
                    event="admin_view",
                    outcome="ok" if is_admin else "denied",
                    tool=f"admin.{section}",
                    identity_sub=session.identity.subject,
                    identity_email=session.identity.email,
                )
            except AuditError:
                return message("Unavailable", "The audit log is unavailable.", status_code=503)
        if not is_admin:
            return message(
                "Admins only",
                "You are signed in, but you are not a configured admin.",
                status_code=403,
            )
        return session

    def page(template: str, section: str, session: WebSession, ctx: dict[str, Any]) -> Response:
        base = {
            "section": section,
            "viewer": session.identity.email or session.identity.subject,
            "csrf": session.csrf_token,
        }
        return render(template, {**base, **ctx})

    @router.get("/admin")
    async def admin_root() -> Response:
        return RedirectResponse("/admin/audit", status_code=303)

    def _filters(request: Request) -> tuple[AuditFilter, dict[str, str]]:
        q = request.query_params
        raw = {k: q.get(k, "") for k in ("identity", "tool", "outcome", "from", "to")}
        outcome = raw["outcome"] if raw["outcome"] in _OUTCOMES else None
        until = _parse_date(raw["to"])
        flt = AuditFilter(
            identity=raw["identity"] or None,
            tool=raw["tool"] or None,
            outcome=outcome,
            since=_parse_date(raw["from"]),
            until=until + dt.timedelta(days=1) if until else None,
        )
        return flt, {k: v for k, v in raw.items() if v}

    @router.get("/admin/audit")
    async def audit_page(request: Request) -> Response:
        session = await guard(request, "audit")
        if isinstance(session, Response):
            return session
        flt, raw = _filters(request)
        try:
            page_no = max(1, int(request.query_params.get("page", "1")))
        except ValueError:
            page_no = 1
        async with web.gateway.require_state_pool().acquire() as conn:
            rows = await audit.query_events(
                conn, flt, limit=PAGE_SIZE + 1, offset=(page_no - 1) * PAGE_SIZE
            )
        return page(
            "admin_audit.html",
            "audit",
            session,
            {
                "rows": rows[:PAGE_SIZE],
                "has_more": len(rows) > PAGE_SIZE,
                "page": page_no,
                "f": flt,
                "outcomes": _OUTCOMES,
                "date_from": raw.get("from", ""),
                "date_to": raw.get("to", ""),
                "query": urlencode(raw),
            },
        )

    @router.get("/admin/audit/export")
    async def audit_export(request: Request) -> Response:
        session = await guard(request, "audit_export")
        if isinstance(session, Response):
            return session
        fmt = request.query_params.get("format", "jsonl")
        if fmt not in ("jsonl", "csv"):
            return message("Invalid format", "format must be jsonl or csv.")
        flt, _ = _filters(request)
        async with web.gateway.require_state_pool().acquire() as conn:
            rows = await audit.query_events(conn, flt, newest_first=False)
        body = audit.format_events(rows, "csv" if fmt == "csv" else "jsonl")
        media = "text/csv" if fmt == "csv" else "application/x-ndjson"
        return Response(
            body,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="pgwarden-audit.{fmt}"',
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.get("/admin/approvals")
    async def approvals_page(request: Request) -> Response:
        session = await guard(request, "approvals")
        if isinstance(session, Response):
            return session
        proposals = await approvals.list_for_review(limit=200)
        for p in proposals:
            p["link"] = approval_link(
                config.public_url, approvals.session_secret, p["proposal_id"], now=web.now()
            ).removeprefix(config.public_url.rstrip("/"))
        return page("admin_approvals.html", "approvals", session, {"proposals": proposals})

    @router.get("/admin/people")
    async def people_page(request: Request) -> Response:
        session = await guard(request, "people")
        if isinstance(session, Response):
            return session
        async with web.gateway.require_state_pool().acquire() as conn:
            status = {
                r["person_role"]: bool(r["suspended"])
                for r in await conn.fetch(
                    "SELECT person_role, suspended FROM pgwarden.people_status"
                )
            }
            last_seen = {
                r["identity_sub"]: r["last"]
                for r in await conn.fetch(
                    "SELECT identity_sub, max(ts) AS last FROM pgwarden.audit_log "
                    "WHERE event = 'tool_call' GROUP BY identity_sub"
                )
            }
        people: list[dict[str, Any]] = []
        raw_bundles = set(config.masking.raw_access_bundles)
        for person in config.people:
            role = person_role_name(person.role)
            people.append(
                {
                    "kind": "person",
                    "identity": person.identity.email
                    or person.identity.subject
                    or f"{person.identity.tid}:{person.identity.oid}",
                    "role": role,
                    "bundles": ", ".join(person.bundles),
                    "writer": person.writer,
                    "masked": not (raw_bundles & set(person.bundles)),
                    "last_seen": last_seen.get(person_subject(person.role)),
                    "suspended": status.get(role, False),
                }
            )
        for machine in config.machines:
            role = machine_role_name(machine.role)
            people.append(
                {
                    "kind": "machine",
                    "identity": machine.name,
                    "role": role,
                    "bundles": ", ".join(machine.bundles),
                    "writer": None,
                    "masked": not (raw_bundles & set(machine.bundles)),
                    "last_seen": last_seen.get(machine_subject(machine.name)),
                    "suspended": status.get(role, False),
                }
            )
        return page("admin_people.html", "people", session, {"people": people})

    async def _set_suspended(request: Request, role: str, suspended: bool) -> Response:
        session = await guard(request, "people_suspend" if suspended else "people_unsuspend")
        if isinstance(session, Response):
            return session
        form = await request.form()
        if str(form.get("csrf") or "") != session.csrf_token:
            return message("Invalid form", "The form token is invalid. Reload the page.")
        person = next((p for p in config.people if person_role_name(p.role) == role), None)
        if person is None:
            return message("Unknown person", "No configured person has that role.", status_code=404)
        now = web.now()
        async with web.gateway.require_state_pool().acquire() as conn:
            await conn.execute(
                "INSERT INTO pgwarden.people_status (person_role, suspended, suspended_at, "
                "suspended_by, updated_at) VALUES ($1, $2, $3, $4, $3) "
                "ON CONFLICT (person_role) DO UPDATE SET suspended = EXCLUDED.suspended, "
                "suspended_at = EXCLUDED.suspended_at, suspended_by = EXCLUDED.suspended_by, "
                "updated_at = EXCLUDED.updated_at",
                role,
                suspended,
                now,
                session.identity.email or session.identity.subject,
            )
            if suspended:
                await store.revoke_families_for_subject(
                    conn, person_subject(person.role), "suspended by admin", now
                )
        if suspended:
            await web.gateway.pool_manager.close_role(role)
        return RedirectResponse("/admin/people", status_code=303)

    @router.post("/admin/people/{role}/suspend")
    async def suspend(request: Request, role: str) -> Response:
        return await _set_suspended(request, role, True)

    @router.post("/admin/people/{role}/unsuspend")
    async def unsuspend(request: Request, role: str) -> Response:
        return await _set_suspended(request, role, False)

    @router.get("/admin/clients")
    async def clients_page(request: Request) -> Response:
        session = await guard(request, "clients")
        if isinstance(session, Response):
            return session
        async with web.gateway.require_state_pool().acquire() as conn:
            clients = await store.list_clients(conn)
        return page("admin_clients.html", "clients", session, {"clients": clients})

    @router.get("/admin/health")
    async def health_page(request: Request) -> Response:
        session = await guard(request, "health")
        if isinstance(session, Response):
            return session
        async with web.gateway.require_state_pool().acquire() as conn:
            row = await conn.fetchrow(
                "SELECT ran_at, ok, results FROM pgwarden.doctor_runs ORDER BY id DESC LIMIT 1"
            )
        doctor = None
        if row is not None:
            results = row["results"]
            doctor = {
                "ran_at": row["ran_at"],
                "ok": row["ok"],
                "results": json.loads(results) if isinstance(results, str) else results,
            }
        pools = sorted(
            (role, idle, in_use)
            for role, (idle, in_use) in web.gateway.pool_manager.stats().items()
        )
        return page(
            "admin_health.html",
            "health",
            session,
            {"pools": pools, "doctor": doctor, "global_cap": config.pool.global_cap},
        )

    return router


__all__ = ["build_admin_router"]
