"""The approval page: ``/approve/<proposal id>?exp=..&sig=..``.

The signed link from the notification only opens this page. The page requires
an OIDC login (redirecting to ``/login``) as a configured approver, shows the
full SQL, parameters and planner estimate, and offers Approve and Reject as
CSRF-protected POSTs. Self-approval is refused by the approval service.
"""

from __future__ import annotations

import json
from urllib.parse import quote

from fastapi import APIRouter, Request
from starlette.responses import RedirectResponse, Response

from pgwarden.approvals.links import verify_link
from pgwarden.approvals.service import ApprovalError, ApprovalService
from pgwarden.oauth import binding
from pgwarden.oauth.authorize import WebAuth
from pgwarden.web.render import message, render


def build_approval_router(web: WebAuth, approvals: ApprovalService) -> APIRouter:
    router = APIRouter()

    async def _page(
        request: Request,
        proposal_id: str,
        exp: str | None,
        sig: str | None,
        *,
        notice: str | None = None,
        notice_class: str = "",
    ) -> Response:
        if not verify_link(approvals.session_secret, proposal_id, exp, sig, now=web.now()):
            return message(
                "Link not valid",
                "This approval link is invalid or has expired (links are valid for 24 hours).",
                status_code=404,
            )
        session = await web.current_session(request)
        if session is None:
            target = f"/approve/{quote(proposal_id)}?exp={quote(exp or '')}&sig={quote(sig or '')}"
            return RedirectResponse(f"/login?next={quote(target, safe='')}", status_code=303)
        async with web.gateway.require_state_pool().acquire() as conn:
            is_approver = await binding.any_matches(
                conn, web.gateway.config.approvers, session.identity, web.now()
            )
        if not is_approver:
            return message(
                "Not an approver",
                "You are signed in, but you are not a configured approver for this gateway.",
                status_code=403,
            )
        proposal = await approvals.get_for_review(proposal_id)
        if proposal is None:
            return message("Not found", "No such proposal.", status_code=404)
        return render(
            "approve.html",
            {
                "p": proposal,
                "params_json": json.dumps(proposal["params"], indent=2, default=str),
                "viewer": session.identity.email or session.identity.subject,
                "csrf": session.csrf_token,
                "exp": exp,
                "sig": sig,
                "notice": notice,
                "notice_class": notice_class,
                "grant_minutes": web.gateway.config.write.grant_ttl_s // 60,
            },
        )

    @router.get("/approve/{proposal_id}")
    async def review(request: Request, proposal_id: str) -> Response:
        q = request.query_params
        return await _page(request, proposal_id, q.get("exp"), q.get("sig"))

    @router.post("/approve/{proposal_id}")
    async def decide(request: Request, proposal_id: str) -> Response:
        form = await request.form()
        exp = str(form.get("exp") or "")
        sig = str(form.get("sig") or "")
        if not verify_link(approvals.session_secret, proposal_id, exp, sig, now=web.now()):
            return message(
                "Link not valid", "This approval link is invalid or has expired.", status_code=404
            )
        session = await web.current_session(request)
        if session is None:
            return message(
                "Signed out", "Your session expired. Open the link again.", status_code=401
            )
        csrf = str(form.get("csrf") or "")
        if not csrf or csrf != session.csrf_token:
            return message(
                "Invalid form", "The form token is invalid. Reload the page.", status_code=400
            )
        async with web.gateway.require_state_pool().acquire() as conn:
            is_approver = await binding.any_matches(
                conn, web.gateway.config.approvers, session.identity, web.now()
            )
        if not is_approver:
            return message("Not an approver", "You are not a configured approver.", status_code=403)
        decision = str(form.get("decision") or "")
        try:
            if decision == "approve":
                await approvals.approve(proposal_id, session.identity)
                notice, css = (
                    "Approved: the proposer can execute it once, within the grant window.",
                    "ok",
                )
            elif decision == "reject":
                await approvals.reject(proposal_id, session.identity)
                notice, css = "Rejected.", "bad"
            else:
                return message("Invalid form", "Unknown decision.", status_code=400)
        except ApprovalError as exc:
            status = 403 if exc.code in ("self_approval", "not_an_approver") else 409
            return message("Not possible", exc.message, status_code=status)
        return await _page(request, proposal_id, exp, sig, notice=notice, notice_class=css)

    return router


__all__ = ["build_approval_router"]
