"""The browser half of the authorization server: /oauth/authorize, the two
consent steps, the upstream callback, and /login for the gateway's own pages.

Per the MCP security guidance for a proxy that uses one static client id at the
upstream IdP, the MCP client is identified and approved *before* the browser is
sent upstream (confused-deputy defence):

1. ``GET /oauth/authorize`` validates the client, the exact redirect URI (loopback
   port ignored), PKCE S256, ``state`` and the ``resource``, stores the pending
   request server-side, and shows a consent page naming the client and the host
   it will send the browser back to.
2. ``POST /oauth/authorize/consent`` (CSRF-protected) sends the browser to the
   IdP with a fresh single-use ``state``, nonce and PKCE verifier, all bound to
   this browser by a cookie.
3. ``GET /oauth/callback`` exchanges the upstream code, validates the identity,
   maps it to a configured person, and shows who is signed in and which Postgres
   role will be used.
4. ``POST /oauth/authorize/confirm`` (CSRF-protected) issues the authorization
   code and redirects to the client with ``code``, ``state`` and ``iss``.

If the sign-in is too old by the time of the confirmation POST, login restarts
upstream for the same pending request instead of failing.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import secrets
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import asyncpg
from fastapi import APIRouter, Request
from starlette.responses import RedirectResponse, Response

from pgwarden.identity import UpstreamIdentity, person_subject, resolve_principal
from pgwarden.mcp_server import GatewayDeps
from pgwarden.oauth import binding, pkce, store
from pgwarden.oauth.redirects import redirect_uri_matches
from pgwarden.oauth.server import CODE_TTL_S, OAuthService, resource_matches
from pgwarden.oauth.upstream import UpstreamError, UpstreamProvider
from pgwarden.state import audit
from pgwarden.state.conn import AnyConn
from pgwarden.web import sessions
from pgwarden.web.render import message, render
from pgwarden.web.security import CookiePolicy, cookie_policy, csrf_ok, csrf_token, safe_next_path

BINDING_COOKIE = "pgw_authz"
PENDING_TTL_S = 15 * 60
CONFIRM_TTL_S = 5 * 60
WEB_CLIENT_ID = "pgwarden-web"


def _h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _with_query(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = f"{parts.query}&{urlencode(params)}" if parts.query else urlencode(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _redirect_host(uri: str) -> str:
    parts = urlsplit(uri)
    return parts.netloc or f"{parts.scheme}:"


@dataclasses.dataclass
class WebAuth:
    """Everything the browser flow needs."""

    gateway: GatewayDeps
    oauth: OAuthService
    upstream: UpstreamProvider
    session_secret: str

    @property
    def cookies(self) -> CookiePolicy:
        return cookie_policy(self.gateway.config.public_url)

    def now(self) -> dt.datetime:
        return self.gateway.now()

    async def current_session(self, request: Request) -> sessions.WebSession | None:
        raw = self.cookies.get(request, sessions.SESSION_COOKIE)
        async with self.gateway.require_state_pool().acquire() as conn:
            return await sessions.load_session(conn, raw, self.now())


def _browser_binding(web: WebAuth, request: Request) -> tuple[str, bool]:
    existing = web.cookies.get(request, BINDING_COOKIE)
    if existing and len(existing) >= 32:
        return existing, False
    return secrets.token_urlsafe(32), True


def _set_binding(web: WebAuth, response: Response, value: str) -> None:
    web.cookies.set(response, BINDING_COOKIE, value, max_age=PENDING_TTL_S)


async def _audit(conn: AnyConn, **fields: Any) -> None:
    # Fail closed: if the event cannot be recorded, the flow stops with an error.
    await audit.record(conn, **fields)


def _error_redirect(
    redirect_uri: str, error: str, description: str, state: str | None, iss: str
) -> Response:
    params = {"error": error, "error_description": description, "iss": iss}
    if state:
        params["state"] = state
    return RedirectResponse(_with_query(redirect_uri, params), status_code=303)


async def _load_pending(conn: AnyConn, pending_id: str) -> asyncpg.Record | None:
    return await conn.fetchrow(
        "SELECT * FROM pgwarden.pending_authorizations WHERE id = $1 AND consumed_at IS NULL",
        pending_id,
    )


def _binding_ok(web: WebAuth, request: Request, row: asyncpg.Record) -> bool:
    raw = web.cookies.get(request, BINDING_COOKIE)
    return bool(raw) and secrets.compare_digest(_h(raw or ""), str(row["browser_binding_hash"]))


async def _start_upstream(web: WebAuth, conn: AnyConn, pending_id: str) -> str:
    """Fresh single-use state, nonce and PKCE verifier for this pending request."""
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)[:64]
    await conn.execute(
        "UPDATE pgwarden.pending_authorizations SET stage = 'upstream', upstream_state_hash = $2, "
        "upstream_nonce = $3, upstream_code_verifier = $4 WHERE id = $1",
        pending_id,
        _h(state),
        nonce,
        verifier,
    )
    return await web.upstream.authorization_url(state=state, nonce=nonce, code_verifier=verifier)


def build_authorize_router(web: WebAuth) -> APIRouter:
    router = APIRouter()
    config = web.gateway.config
    issuer = web.oauth.issuer

    @router.get("/oauth/authorize")
    async def authorize(request: Request) -> Response:
        q = request.query_params
        client_id = q.get("client_id")
        redirect_uri = q.get("redirect_uri")
        if not client_id:
            return message("Invalid request", "client_id is missing.")
        async with web.gateway.require_state_pool().acquire() as conn:
            client = await web.oauth.resolve_client(conn, client_id)
        if client is None:
            return message("Unknown application", "This application is not registered.")
        if not redirect_uri or not redirect_uri_matches(redirect_uri, client.redirect_uris):
            return message(
                "Invalid redirect",
                "The redirect URI does not match any URI registered for this application.",
            )
        state = q.get("state")
        if q.get("response_type") != "code":
            return _error_redirect(
                redirect_uri, "unsupported_response_type", "only response_type=code", state, issuer
            )
        challenge = q.get("code_challenge")
        if not pkce.is_valid_challenge(challenge, q.get("code_challenge_method")):
            return _error_redirect(
                redirect_uri, "invalid_request", "PKCE with S256 is required", state, issuer
            )
        if not state:
            return _error_redirect(
                redirect_uri, "invalid_request", "state is required", None, issuer
            )
        resource = q.get("resource")
        if not resource_matches(resource, web.oauth.resource):
            return _error_redirect(
                redirect_uri,
                "invalid_target",
                f"resource must be {web.oauth.resource}",
                state,
                issuer,
            )

        binding_value, is_new = _browser_binding(web, request)
        pending_id = secrets.token_urlsafe(24)
        now = web.now()
        async with web.gateway.require_state_pool().acquire() as conn:
            await conn.execute(
                "INSERT INTO pgwarden.pending_authorizations (id, client_id, redirect_uri, "
                "client_state, code_challenge, resource, scope, stage, browser_binding_hash, "
                "created_at, expires_at, purpose) VALUES ($1,$2,$3,$4,$5,$6,$7,'consent',$8,$9,$10,"
                "'authorize')",
                pending_id,
                client.client_id,
                redirect_uri,
                state,
                challenge,
                resource,
                q.get("scope"),
                _h(binding_value),
                now,
                now + dt.timedelta(seconds=PENDING_TTL_S),
            )
        response = render(
            "consent.html",
            {
                "client_name": client.client_name,
                "redirect_host": _redirect_host(redirect_uri),
                "resource": web.oauth.resource,
                "idp_name": config.upstream.name,
                "pending_id": pending_id,
                "csrf": csrf_token(web.session_secret, "consent", pending_id, binding_value),
            },
            form_targets=(redirect_uri, (await web.upstream.endpoints()).authorization_endpoint),
        )
        if is_new:
            _set_binding(web, response, binding_value)
        return response

    @router.post("/oauth/authorize/consent")
    async def consent(request: Request) -> Response:
        form = await request.form()
        pending_id = str(form.get("pending_id") or "")
        decision = str(form.get("decision") or "")
        now = web.now()
        async with web.gateway.require_state_pool().acquire() as conn:
            row = await _load_pending(conn, pending_id)
            if row is None or row["purpose"] != "authorize" or not _binding_ok(web, request, row):
                return message("Request not found", "This sign-in request is unknown or finished.")
            raw_binding = web.cookies.get(request, BINDING_COOKIE) or ""
            if not csrf_ok(
                web.session_secret, str(form.get("csrf") or ""), "consent", pending_id, raw_binding
            ):
                return message(
                    "Invalid form", "The form token is invalid. Start again from your app."
                )
            if now >= row["expires_at"]:
                return message(
                    "Request expired", "This request expired. Start again from your app."
                )
            if row["stage"] not in ("consent", "upstream"):
                return message("Request already used", "This consent step was already completed.")
            if decision != "approve":
                await conn.execute(
                    "UPDATE pgwarden.pending_authorizations SET consumed_at = $2 WHERE id = $1",
                    pending_id,
                    now,
                )
                await _audit(
                    conn,
                    event="consent",
                    outcome="denied",
                    tool="oauth.consent",
                    client_id=row["client_id"],
                )
                return _error_redirect(
                    row["redirect_uri"],
                    "access_denied",
                    "the user cancelled",
                    row["client_state"],
                    issuer,
                )
            await _audit(
                conn,
                event="consent",
                outcome="ok",
                tool="oauth.consent",
                client_id=row["client_id"],
            )
            url = await _start_upstream(web, conn, pending_id)
        return RedirectResponse(url, status_code=303)

    @router.get("/oauth/callback")
    async def callback(request: Request) -> Response:
        q = request.query_params
        state = q.get("state")
        if not state:
            return message("Invalid callback", "The sign-in response has no state.")
        now = web.now()
        async with web.gateway.require_state_pool().acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE pgwarden.pending_authorizations SET upstream_state_hash = NULL, "
                "stage = 'exchanging' WHERE upstream_state_hash = $1 AND stage = 'upstream' "
                "AND consumed_at IS NULL RETURNING *",
                _h(state),
            )
            if row is None:
                return message(
                    "Sign-in link already used",
                    "This sign-in response is unknown, expired or was already used.",
                )
            if not _binding_ok(web, request, row):
                await conn.execute(
                    "UPDATE pgwarden.pending_authorizations SET consumed_at = $2 WHERE id = $1",
                    row["id"],
                    now,
                )
                return message(
                    "Wrong browser", "This sign-in was started in a different browser session."
                )
            if now >= row["expires_at"]:
                return message("Request expired", "This request expired. Start again.")
            if q.get("error") or not q.get("code"):
                await conn.execute(
                    "UPDATE pgwarden.pending_authorizations SET consumed_at = $2 WHERE id = $1",
                    row["id"],
                    now,
                )
                if row["purpose"] == "authorize":
                    return _error_redirect(
                        row["redirect_uri"],
                        "access_denied",
                        "sign-in was not completed",
                        row["client_state"],
                        issuer,
                    )
                return message("Sign-in cancelled", "The identity provider did not sign you in.")

        try:
            identity = await web.upstream.exchange(
                code=str(q.get("code")),
                code_verifier=str(row["upstream_code_verifier"]),
                nonce=str(row["upstream_nonce"]),
            )
        except UpstreamError as exc:
            async with web.gateway.require_state_pool().acquire() as conn:
                await _audit(conn, event="auth", outcome="denied", tool="oauth.callback")
            return message(
                "Sign-in failed", "The identity provider's response was rejected.", detail=str(exc)
            )

        if row["purpose"] == "login":
            return await _finish_login(web, row, identity, now)
        return await _show_confirmation(web, request, row, identity, now)

    @router.post("/oauth/authorize/confirm")
    async def confirm(request: Request) -> Response:
        form = await request.form()
        pending_id = str(form.get("pending_id") or "")
        decision = str(form.get("decision") or "")
        now = web.now()
        async with web.gateway.require_state_pool().acquire() as conn:
            row = await _load_pending(conn, pending_id)
            if row is None or row["purpose"] != "authorize" or not _binding_ok(web, request, row):
                return message("Request not found", "This sign-in request is unknown or finished.")
            raw_binding = web.cookies.get(request, BINDING_COOKIE) or ""
            if not csrf_ok(
                web.session_secret, str(form.get("csrf") or ""), "confirm", pending_id, raw_binding
            ):
                return message(
                    "Invalid form", "The form token is invalid. Start again from your app."
                )
            if now >= row["expires_at"]:
                return message(
                    "Request expired", "This request expired. Start again from your app."
                )
            if row["stage"] != "confirm" or row["identity_at"] is None:
                return message("Request already used", "This request is not awaiting confirmation.")
            if decision != "confirm":
                await conn.execute(
                    "UPDATE pgwarden.pending_authorizations SET consumed_at = $2 WHERE id = $1",
                    pending_id,
                    now,
                )
                await _audit(
                    conn,
                    event="consent",
                    outcome="denied",
                    tool="oauth.confirm",
                    client_id=row["client_id"],
                    identity_email=row["identity_email"],
                )
                return _error_redirect(
                    row["redirect_uri"],
                    "access_denied",
                    "the user denied access",
                    row["client_state"],
                    issuer,
                )
            if now - row["identity_at"] > dt.timedelta(seconds=CONFIRM_TTL_S):
                # The sign-in is stale: restart upstream login for the same request.
                url = await _start_upstream(web, conn, pending_id)
                return RedirectResponse(url, status_code=303)

            identity = UpstreamIdentity(
                provider=str(row["identity_provider"]),
                subject=str(row["identity_subject"]),
                email=row["identity_email"],
                email_verified=bool(row["identity_email_verified"]),
            )
            person = await binding.resolve_person(conn, config, identity, now)
            principal = resolve_principal(config, person_subject(person.role)) if person else None
            if principal is None or await store.is_suspended(conn, principal.role_name):
                return message(
                    "Access not available",
                    "Your identity is not mapped to a database role, or it is suspended. "
                    "Ask an administrator.",
                    status_code=403,
                )
            code = secrets.token_urlsafe(32)
            async with conn.transaction():
                claimed = await conn.fetchval(
                    "UPDATE pgwarden.pending_authorizations SET consumed_at = $2, "
                    "stage = 'completed' "
                    "WHERE id = $1 AND consumed_at IS NULL AND stage = 'confirm' RETURNING id",
                    pending_id,
                    now,
                )
                if claimed is None:
                    return message("Request already used", "This request was already completed.")
                await store.insert_auth_code(
                    conn,
                    code=code,
                    client_id=row["client_id"],
                    redirect_uri=row["redirect_uri"],
                    code_challenge=row["code_challenge"],
                    resource=row["resource"],
                    principal_subject=principal.subject,
                    identity_email=identity.email,
                    upstream_login_at=row["identity_at"],
                    expires_at=now + dt.timedelta(seconds=CODE_TTL_S),
                )
                await _audit(
                    conn,
                    event="consent",
                    outcome="ok",
                    tool="oauth.confirm",
                    client_id=row["client_id"],
                    identity_sub=principal.subject,
                    identity_email=identity.email,
                    pg_role=principal.role_name,
                )
        params = {"code": code, "iss": issuer}
        if row["client_state"]:
            params["state"] = row["client_state"]
        return RedirectResponse(_with_query(row["redirect_uri"], params), status_code=303)

    @router.get("/login")
    async def login(request: Request) -> Response:
        next_path = safe_next_path(request.query_params.get("next"))
        if await web.current_session(request) is not None:
            return RedirectResponse(next_path, status_code=303)
        binding_value, is_new = _browser_binding(web, request)
        pending_id = secrets.token_urlsafe(24)
        now = web.now()
        async with web.gateway.require_state_pool().acquire() as conn:
            await conn.execute(
                "INSERT INTO pgwarden.pending_authorizations (id, client_id, redirect_uri, "
                "code_challenge, stage, browser_binding_hash, created_at, expires_at, purpose, "
                "next_path) VALUES ($1, $2, $3, '', 'upstream', $4, $5, $6, 'login', $3)",
                pending_id,
                WEB_CLIENT_ID,
                next_path,
                _h(binding_value),
                now,
                now + dt.timedelta(seconds=PENDING_TTL_S),
            )
            url = await _start_upstream(web, conn, pending_id)
        response = RedirectResponse(url, status_code=303)
        if is_new:
            _set_binding(web, response, binding_value)
        return response

    @router.post("/logout")
    async def logout(request: Request) -> Response:
        raw = web.cookies.get(request, sessions.SESSION_COOKIE)
        form = await request.form()
        session = await web.current_session(request)
        if session is not None and not secrets.compare_digest(
            str(form.get("csrf") or ""), session.csrf_token
        ):
            return message("Invalid form", "The form token is invalid.")
        async with web.gateway.require_state_pool().acquire() as conn:
            await sessions.revoke_session(conn, raw, web.now())
        response = RedirectResponse("/", status_code=303)
        web.cookies.clear(response, sessions.SESSION_COOKIE)
        return response

    return router


async def _finish_login(
    web: WebAuth, row: asyncpg.Record, identity: UpstreamIdentity, now: dt.datetime
) -> Response:
    async with web.gateway.require_state_pool().acquire() as conn:
        await conn.execute(
            "UPDATE pgwarden.pending_authorizations SET consumed_at = $2, stage = 'completed' "
            "WHERE id = $1",
            row["id"],
            now,
        )
        raw, _session = await sessions.create_session(conn, identity, now)
        await _audit(
            conn,
            event="auth",
            outcome="ok",
            tool="web.login",
            identity_sub=identity.subject,
            identity_email=identity.email,
        )
    response = RedirectResponse(safe_next_path(row["next_path"]), status_code=303)
    web.cookies.set(response, sessions.SESSION_COOKIE, raw, max_age=sessions.ABSOLUTE_TIMEOUT_S)
    return response


async def _show_confirmation(
    web: WebAuth,
    request: Request,
    row: asyncpg.Record,
    identity: UpstreamIdentity,
    now: dt.datetime,
) -> Response:
    config = web.gateway.config
    async with web.gateway.require_state_pool().acquire() as conn:
        person = await binding.resolve_person(conn, config, identity, now)
        principal = resolve_principal(config, person_subject(person.role)) if person else None
        if principal is None:
            await conn.execute(
                "UPDATE pgwarden.pending_authorizations SET consumed_at = $2 WHERE id = $1",
                row["id"],
                now,
            )
            await _audit(
                conn,
                event="auth",
                outcome="denied",
                tool="oauth.callback",
                identity_sub=identity.subject,
                identity_email=identity.email,
                client_id=row["client_id"],
            )
            return message(
                "Not set up for database access",
                "You signed in successfully, but your identity is not mapped to a database role. "
                "Ask an administrator to add you.",
                status_code=403,
            )
        if await store.is_suspended(conn, principal.role_name):
            await conn.execute(
                "UPDATE pgwarden.pending_authorizations SET consumed_at = $2 WHERE id = $1",
                row["id"],
                now,
            )
            return message(
                "Access suspended",
                "Your access is suspended. Ask an administrator.",
                status_code=403,
            )
        await conn.execute(
            "UPDATE pgwarden.pending_authorizations SET stage = 'confirm', identity_provider = $2, "
            "identity_subject = $3, identity_email = $4, identity_email_verified = $5, "
            "identity_at = $6 WHERE id = $1",
            row["id"],
            identity.provider,
            identity.subject,
            identity.email,
            identity.email_verified,
            now,
        )
        client = await store.get_client(conn, row["client_id"])
    raw_binding = web.cookies.get(request, BINDING_COOKIE) or ""
    return render(
        "confirm.html",
        {
            "client_name": client.client_name if client else row["client_id"],
            "redirect_host": _redirect_host(row["redirect_uri"]),
            "identity": identity.email or identity.subject,
            "pg_role": principal.role_name,
            "bundles": ", ".join(principal.bundles) or "none",
            "masked": principal.masked,
            "pending_id": row["id"],
            "csrf": csrf_token(web.session_secret, "confirm", str(row["id"]), raw_binding),
        },
        form_targets=(
            str(row["redirect_uri"]),
            (await web.upstream.endpoints()).authorization_endpoint,
        ),
    )


__all__ = ["BINDING_COOKIE", "WebAuth", "build_authorize_router"]
