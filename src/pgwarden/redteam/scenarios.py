"""Procedural red-team scenarios: categories H (approval abuse) and I (OAuth and session).

A YAML case that carries ``scenario: <name>`` is not a single tool call. It needs
several steps and often several identities (an approver's browser session, a
proposer's token, a second person), so it names one of the procedures below. A
procedure returns a :class:`Verdict`: whether the attack was blocked, the layer
that was observed to block it, and a one-line detail. The runner records it like
any other case: a must-block case passes only when it is blocked *and* the
observed layer equals the expected one; a benign scenario passes when it is not
blocked.

Everything here is black-box HTTP, the way a real attacker or a real approver
would drive the deployment: the MCP endpoint with bearer tokens, the OAuth
endpoints, and the ``/approve`` and ``/admin`` pages with a signed-in browser
session (mock-IdP sign-in as ``carol``, the configured approver and admin). The
verdicts come from state: the proposal's state read back through the tool, the
target table's checksum, marked rows counted over the admin connection, the HTTP
status. They never rely on the wording of an error.

Not covered here, because a black-box client cannot forge them without the
gateway's private signing key or its clock: a token with the wrong audience, an
expired token, and a refresh chain past its 8-hour lifetime. The integration
tests in ``tests/integration/test_oauth_server.py`` and ``test_mcp_gateway.py``
cover those with an injectable clock and the test signing key. Self-approval (a
proposer who is also a configured approver) cannot be staged in the demo, whose
only approver is not a person; ``tests/integration/test_approvals.py`` covers it.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import html
import json
import re
import secrets
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import asyncpg
import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pgwarden.oauth.jwt import ACCESS_TOKEN_TYP, mint_access_token
from pgwarden.redteam import mcp_client
from pgwarden.redteam.mcp_client import ToolResponse, response_from_httpx
from pgwarden.redteam.oracles import ORACLES, OracleContext, OracleOutcome, table_checksum
from pgwarden.redteam.stack import StackClient, StackError, Tokens, WebSession

# Refusal codes the write path returns to the tool caller (see approvals/service.py).
APPROVAL_CODES = frozenset(
    {
        "rejected_by_validation",
        "no_writer_role",
        "self_approval",
        "not_an_approver",
        "not_executable",
        "binding_mismatch",
        "not_pending",
        "not_found",
    }
)
_OAUTH_ERRORS = frozenset(
    {
        "invalid_request",
        "invalid_grant",
        "invalid_target",
        "invalid_client",
        "invalid_token",
        "unsupported_grant_type",
        "unsupported_response_type",
        "access_denied",
    }
)

CAROL = "usr_carol"  # the demo's only approver and admin; not a person with a database role
# A ticket in each restricted person's own region, for proposals that must be legitimate.
_NOTE_TICKET = {"bob": 2702, "dana": 1301}
_NOTE_SQL = "INSERT INTO ticket_notes (ticket_id, note_body) VALUES ($1, $2)"


class ScenarioError(RuntimeError):
    """A scenario could not be staged (a login failed, a page was missing), so it proves nothing."""


@dataclasses.dataclass(frozen=True)
class Verdict:
    blocked: bool
    observed_layer: str
    detail: str


CallFn = Callable[[str, str, dict[str, Any]], Awaitable[ToolResponse]]
ScenarioFn = Callable[["ScenarioContext", dict[str, Any]], Awaitable[Verdict]]
SCENARIOS: dict[str, ScenarioFn] = {}


def scenario(name: str) -> Callable[[ScenarioFn], ScenarioFn]:
    def register(fn: ScenarioFn) -> ScenarioFn:
        SCENARIOS[name] = fn
        return fn

    return register


@dataclasses.dataclass
class ScenarioContext:
    """What a scenario may use: the stack client, an admin connection, tokens and sessions."""

    client: StackClient
    admin: asyncpg.Connection
    call: CallFn  # (identity, tool, args): paced and rate-limit-aware, provided by the runner
    tokens: Callable[[str], Awaitable[Tokens]]
    client_id: Callable[[], Awaitable[str]]
    machine_secrets: dict[str, str]
    region_for_identity: dict[str, str]
    masked_identities: frozenset[str] = frozenset()
    _web: dict[str, WebSession] = dataclasses.field(default_factory=dict)
    # Proposals that stay pending, shared by the link and page cases, so the run does
    # not spend the person's 10-proposals-per-hour budget on one proposal per case.
    _pending: dict[str, _PendingProposal] = dataclasses.field(default_factory=dict)

    async def web(self, user_sub: str) -> WebSession:
        """A signed-in browser session for a mock-IdP user, created once per run."""
        if user_sub not in self._web:
            try:
                self._web[user_sub] = await self.client.web_login(user_sub)
            except StackError as exc:
                raise ScenarioError(f"web sign-in as {user_sub} failed: {exc}") from exc
        return self._web[user_sub]

    async def aclose(self) -> None:
        for session in self._web.values():
            await session.aclose()
        self._web.clear()

    async def oracle(
        self, name: str, response: ToolResponse, identity: str = "bob", **spec: Any
    ) -> OracleOutcome:
        ctx = OracleContext(
            response=response,
            admin=self.admin,
            identity=identity,
            region_for_identity=self.region_for_identity,
            masked_identities=self.masked_identities,
        )
        return await ORACLES[name](ctx, spec)

    async def rows_marked(self, marker: str) -> int:
        return int(
            await self.admin.fetchval(
                "SELECT count(*) FROM ticket_notes WHERE note_body = $1", marker
            )
        )


def _verdict(layer: str, checks: list[tuple[str, OracleOutcome]], *, extra: str = "") -> Verdict:
    detail = "; ".join(f"{name}: {outcome.detail}" for name, outcome in checks)
    if extra:
        detail = f"{extra}; {detail}" if detail else extra
    return Verdict(all(outcome.blocked for _, outcome in checks), layer, detail)


def _ok(detail: str) -> OracleOutcome:
    return OracleOutcome(True, detail)


def _fail(detail: str) -> OracleOutcome:
    return OracleOutcome(False, detail)


# --- layer derivation: what refused the request, read from status codes and error fields ---


def oauth_layer(status: int, *, location: str | None = None, error: str | None = None) -> str:
    """``oauth`` when the OAuth layer refused: 401/403, a 400 error page or an error redirect."""
    if status in (401, 403):
        return "oauth"
    if status == 400 and (error is None or error in _OAUTH_ERRORS):
        return "oauth"
    if status in (302, 303) and location:
        redirect_error = parse_qs(urlsplit(location).query).get("error", [""])[0]
        if redirect_error in _OAUTH_ERRORS:
            return "oauth"
    return f"none:{status}"


def approval_layer(response: ToolResponse) -> str:
    """``approval`` when the write path refused the tool call with one of its own codes."""
    err = response.tool_error
    if err is not None and err.get("code") in APPROVAL_CODES:
        return "approval"
    return "none:accepted" if err is None else f"none:{err.get('code') or err.get('sqlstate')}"


def approval_page_layer(status: int) -> str:
    """``approval`` when the approval page refused (bad link, no session, not an approver, ...)."""
    return "approval" if status in (400, 401, 403, 404, 409) else f"none:{status}"


def _oauth_error(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    return str(body.get("error")) if isinstance(body, dict) and "error" in body else None


def _location_error(response: httpx.Response) -> str | None:
    location = response.headers.get("location")
    if not location:
        return None
    values = parse_qs(urlsplit(location).query).get("error")
    return values[0] if values else None


# --- helpers shared by the scenarios ---


async def _authorize_get(ctx: ScenarioContext, **overrides: str) -> httpx.Response:
    url, _, _ = ctx.client.authorize_url(await ctx.client_id(), **overrides)
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
        return await http.get(url)


async def _post_token(ctx: ScenarioContext, data: dict[str, str], **kwargs: Any) -> httpx.Response:
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
        return await http.post(f"{ctx.client.base_url}/oauth/token", data=data, **kwargs)


async def _issuer(ctx: ScenarioContext) -> str:
    async with httpx.AsyncClient(timeout=30) as http:
        meta = await http.get(f"{ctx.client.base_url}/.well-known/oauth-authorization-server")
    return str(meta.json()["issuer"])


async def _observed_kid(ctx: ScenarioContext) -> str:
    """The signing key id any legitimate token carries (an attacker can read it from their own)."""
    token = (await ctx.tokens("alice")).access_token
    return str(jwt.get_unverified_header(token)["kid"])


def _claims(issuer: str, audience: str, subject: str, client_id: str) -> dict[str, Any]:
    now = dt.datetime.now(dt.UTC)
    return {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "client_id": client_id,
        "jti": secrets.token_urlsafe(16),
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(minutes=10)).timestamp()),
    }


async def _forged_whoami(ctx: ScenarioContext, token: str | None) -> Verdict:
    """Present ``token`` at /mcp as a whoami call; blocked iff refused with 401 and no identity."""
    response = await mcp_client.call_tool(ctx.client.resource, token, "whoami", {})
    status = await ctx.oracle("http_status", response, statuses=[401])
    leaked = "pg_role" in response.text
    checks = [
        ("http_status", status),
        ("no_identity", _fail("identity returned") if leaked else _ok("no identity returned")),
    ]
    return _verdict(oauth_layer(response.status), checks)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _tokens_from(response: httpx.Response, client_id: str) -> Tokens:
    body = response.json()
    return Tokens(str(body["access_token"]), body.get("refresh_token"), client_id, 0)


# ===================================================================================
# Category I: OAuth and session
# ===================================================================================


@scenario("oauth_no_bearer")
async def oauth_no_bearer(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    return await _forged_whoami(ctx, None)


@scenario("oauth_foreign_key")
async def oauth_foreign_key(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A token for bob signed with the attacker's own Ed25519 key, carrying the real key id."""
    token = mint_access_token(
        Ed25519PrivateKey.generate(),
        await _observed_kid(ctx),
        issuer=await _issuer(ctx),
        audience=ctx.client.resource,
        subject="person:bob",
        client_id=await ctx.client_id(),
        now=dt.datetime.now(dt.UTC),
    )
    return await _forged_whoami(ctx, token)


@scenario("oauth_alg_none")
async def oauth_alg_none(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """An unsigned token (``alg: none``) with otherwise perfect claims for bob."""
    header = {"alg": "none", "typ": ACCESS_TOKEN_TYP, "kid": await _observed_kid(ctx)}
    payload = _claims(await _issuer(ctx), ctx.client.resource, "person:bob", await ctx.client_id())
    token = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}."
    return await _forged_whoami(ctx, token)


@scenario("oauth_wrong_typ")
async def oauth_wrong_typ(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """Attacker key and a generic ``typ: JWT`` header instead of the access-token type."""
    payload = _claims(await _issuer(ctx), ctx.client.resource, "person:bob", await ctx.client_id())
    token = jwt.encode(
        payload,
        Ed25519PrivateKey.generate(),
        algorithm="EdDSA",
        headers={"typ": "JWT", "kid": await _observed_kid(ctx)},
    )
    return await _forged_whoami(ctx, token)


@scenario("oauth_upstream_token")
async def oauth_upstream_token(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A raw upstream-IdP-style RS256 ID token presented as the access token (passthrough)."""
    now = dt.datetime.now(dt.UTC)
    payload = {
        "iss": "https://idp.example.com/",
        "aud": "pgwarden-demo",
        "sub": "usr_bob",
        "email": "bob@example.com",
        "email_verified": True,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(minutes=5)).timestamp()),
    }
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(payload, key, algorithm="RS256", headers={"kid": "upstream-signing-key"})
    return await _forged_whoami(ctx, token)


@scenario("oauth_plain_pkce")
async def oauth_plain_pkce(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """``code_challenge_method=plain`` at /authorize must come back as invalid_request."""
    resp = await _authorize_get(ctx, code_challenge_method="plain")
    location = resp.headers.get("location", "")
    error = _location_error(resp)
    redirected_back = location.startswith(ctx.client.redirect_uri) and "code=" not in location
    ok = resp.status_code in (302, 303) and error == "invalid_request" and redirected_back
    checks = [
        (
            "error_redirect",
            _ok(f"error={error}") if ok else _fail(f"HTTP {resp.status_code}, error={error}"),
        )
    ]
    return _verdict(oauth_layer(resp.status_code, location=location), checks)


@scenario("oauth_redirect_mismatch")
async def oauth_redirect_mismatch(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A redirect_uri the client never registered: 400 and never a redirect to the attacker."""
    resp = await _authorize_get(ctx, redirect_uri="http://attacker.example.com/callback")
    ok = resp.status_code == 400 and "location" not in resp.headers
    checks = [
        ("no_redirect", _ok("HTTP 400, no redirect") if ok else _fail(f"HTTP {resp.status_code}"))
    ]
    return _verdict(oauth_layer(resp.status_code), checks)


@scenario("oauth_unknown_client")
async def oauth_unknown_client(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """An authorization request for a client_id nobody registered."""
    url, _, _ = ctx.client.authorize_url("client-nobody-registered")
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
        resp = await http.get(url)
    ok = resp.status_code == 400 and "location" not in resp.headers
    checks = [
        ("no_redirect", _ok("HTTP 400, no redirect") if ok else _fail(f"HTTP {resp.status_code}"))
    ]
    return _verdict(oauth_layer(resp.status_code), checks)


@scenario("oauth_resource_mismatch")
async def oauth_resource_mismatch(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A ``resource`` naming another server at /authorize must come back as invalid_target."""
    resp = await _authorize_get(ctx, resource="http://attacker.example.com/mcp")
    error = _location_error(resp)
    ok = resp.status_code in (302, 303) and error == "invalid_target"
    checks = [
        (
            "error_redirect",
            _ok(f"error={error}") if ok else _fail(f"HTTP {resp.status_code}, error={error}"),
        )
    ]
    return _verdict(oauth_layer(resp.status_code, location=resp.headers.get("location")), checks)


@scenario("oauth_implicit_grant")
async def oauth_implicit_grant(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """The removed implicit flow (``response_type=token``) must not hand out a token."""
    resp = await _authorize_get(ctx, response_type="token")
    location = resp.headers.get("location", "")
    error = _location_error(resp)
    ok = resp.status_code in (302, 303) and error == "unsupported_response_type"
    leaked = "access_token" in location
    checks = [
        (
            "error_redirect",
            _ok(f"error={error}") if ok else _fail(f"HTTP {resp.status_code}, error={error}"),
        ),
        ("no_token", _fail("token in redirect") if leaked else _ok("no token in the redirect")),
    ]
    return _verdict(oauth_layer(resp.status_code, location=location), checks)


@scenario("oauth_unmapped_identity")
async def oauth_unmapped_identity(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """mallory signs in at the upstream IdP but is mapped to no database role: 403, no code."""
    try:
        await ctx.client.authorize_code(
            case.get("args", {}).get("user", "usr_mallory"), client_id=await ctx.client_id()
        )
    except StackError as exc:
        status = exc.status or 0
        checks = [
            (
                "http_status",
                _ok(f"HTTP {status}") if status == 403 else _fail(f"HTTP {status}: {exc}"),
            )
        ]
        return _verdict(oauth_layer(status), checks)
    return _verdict("none:code-issued", [("no_code", _fail("an authorization code was issued"))])


@scenario("oauth_cross_identity")
async def oauth_cross_identity(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """Each token maps to exactly its own role; bob never acts as alice or dana, nor the reverse."""
    outcomes: list[tuple[str, OracleOutcome]] = []
    layer = "oauth"
    for person in ("bob", "alice"):
        who = await ctx.call(person, "whoami", {})
        probe = await ctx.call(
            person, "query", {"sql": "SELECT session_user AS u, current_user AS c"}
        )
        role = who.result.get("pg_role")
        rows = probe.result.get("rows_untrusted") or [{}]
        own = role == f"pw_u_{person}" and rows[0].get("u") == f"pw_u_{person}"
        seen = who.text + probe.text
        strangers = [n for n in ("alice", "bob", "dana") if n != person and f"pw_u_{n}" in seen]
        isolated = own and not strangers
        detail = f"{person} is {role}" if isolated else f"{person} saw {role} and {strangers}"
        outcomes.append((f"{person}_isolated", _ok(detail) if isolated else _fail(detail)))
        if not isolated:
            layer = "none:crossed"
    return _verdict(layer, outcomes)


@scenario("oauth_refresh_reuse")
async def oauth_refresh_reuse(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """Replaying a rotated refresh token revokes the whole family, including the newest token."""
    first = await ctx.client.login("usr_bob", client_id=await ctx.client_id())
    rotated = await ctx.client.refresh(first)
    if rotated.status_code != 200:
        raise ScenarioError(f"the first refresh returned {rotated.status_code}")
    newest = _tokens_from(rotated, first.client_id)
    replay = await ctx.client.refresh(first)  # the old token again: reuse
    after = await ctx.client.refresh(newest)  # the family must now be dead
    replay_err, after_err = _oauth_error(replay), _oauth_error(after)
    ok_replay = replay.status_code == 400 and replay_err == "invalid_grant"
    ok_after = after.status_code == 400 and after_err == "invalid_grant"
    checks = [
        (
            "reuse_refused",
            _ok("reuse returned invalid_grant")
            if ok_replay
            else _fail(f"reuse returned HTTP {replay.status_code}"),
        ),
        (
            "family_revoked",
            _ok("the newest token also failed")
            if ok_after
            else _fail(f"the newest token returned HTTP {after.status_code}"),
        ),
    ]
    return _verdict(oauth_layer(replay.status_code, error=replay_err), checks)


async def _set_suspended(ctx: ScenarioContext, role: str, suspended: bool) -> None:
    carol = await ctx.web(CAROL)
    csrf = await carol.csrf_from("/admin/people")
    action = "suspend" if suspended else "unsuspend"
    resp = await carol.post(f"/admin/people/{role}/{action}", {"csrf": csrf})
    if resp.status_code != 303:
        raise ScenarioError(f"/admin/people/{role}/{action} returned {resp.status_code}")


@scenario("oauth_suspended_token")
async def oauth_suspended_token(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A token issued before an admin suspends the person stops working at once (401)."""
    person = case.get("args", {}).get("person", "dana")
    tokens = await ctx.client.login(f"usr_{person}", client_id=await ctx.client_id())
    before = await mcp_client.call_tool(ctx.client.resource, tokens.access_token, "whoami", {})
    if before.status != 200:
        raise ScenarioError(f"the token did not work before suspension (HTTP {before.status})")
    await _set_suspended(ctx, f"pw_u_{person}", True)
    try:
        during = await mcp_client.call_tool(ctx.client.resource, tokens.access_token, "whoami", {})
        during_query = await mcp_client.call_tool(
            ctx.client.resource, tokens.access_token, "query", {"sql": "SELECT 1"}
        )
    finally:
        await _set_suspended(ctx, f"pw_u_{person}", False)
    after = await mcp_client.call_tool(ctx.client.resource, tokens.access_token, "whoami", {})
    ok = during.status == 401 and during_query.status == 401 and "pg_role" not in during.text
    checks = [
        (
            "suspended_refused",
            _ok("whoami and query returned 401")
            if ok
            else _fail(f"HTTP {during.status}/{during_query.status}"),
        ),
        (
            "restored",
            _ok("access is back after unsuspend")
            if after.status == 200
            else _fail(f"HTTP {after.status} after unsuspend"),
        ),
    ]
    return _verdict(oauth_layer(during.status), checks)


@scenario("oauth_suspended_login")
async def oauth_suspended_login(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A suspended person cannot start a new session: the sign-in ends in a 403, no code."""
    person = case.get("args", {}).get("person", "dana")
    await _set_suspended(ctx, f"pw_u_{person}", True)
    try:
        try:
            await ctx.client.authorize_code(f"usr_{person}", client_id=await ctx.client_id())
            outcome = _fail("an authorization code was issued to a suspended person")
            status = 200
        except StackError as exc:
            status = exc.status or 0
            outcome = _ok(f"HTTP {status}") if status == 403 else _fail(f"HTTP {status}: {exc}")
    finally:
        await _set_suspended(ctx, f"pw_u_{person}", False)
    return _verdict(oauth_layer(status), [("http_status", outcome)])


@scenario("oauth_resource_at_token")
async def oauth_resource_at_token(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A machine credential asking for a token for a different resource: invalid_target."""
    name = case.get("args", {}).get("machine", "nightly-report")
    secret = ctx.machine_secrets.get(name)
    if secret is None:
        raise ScenarioError(f"no machine secret for {name}; give --machine-secret-file")
    resp = await _post_token(
        ctx,
        {"grant_type": "client_credentials", "resource": "http://attacker.example.com/mcp"},
        auth=(name, secret),
    )
    error = _oauth_error(resp)
    ok = resp.status_code == 400 and error == "invalid_target" and "access_token" not in resp.text
    checks = [
        (
            "invalid_target",
            _ok("invalid_target, no token")
            if ok
            else _fail(f"HTTP {resp.status_code}, error={error}"),
        )
    ]
    return _verdict(oauth_layer(resp.status_code, error=error), checks)


@scenario("oauth_bad_machine_secret")
async def oauth_bad_machine_secret(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A machine name with a wrong secret: invalid_client, 401, no token."""
    name = case.get("args", {}).get("machine", "nightly-report")
    resp = await _post_token(
        ctx,
        {"grant_type": "client_credentials", "resource": ctx.client.resource},
        auth=(name, secrets.token_urlsafe(32)),
    )
    error = _oauth_error(resp)
    ok = resp.status_code == 401 and error == "invalid_client" and "access_token" not in resp.text
    checks = [
        (
            "invalid_client",
            _ok("invalid_client, no token")
            if ok
            else _fail(f"HTTP {resp.status_code}, error={error}"),
        )
    ]
    return _verdict(oauth_layer(resp.status_code, error=error), checks)


@scenario("oauth_code_replay")
async def oauth_code_replay(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """An authorization code redeemed a second time is refused (invalid_grant)."""
    auth = await ctx.client.authorize_code("usr_alice", client_id=await ctx.client_id())
    first = await ctx.client.exchange_code(auth)
    if first.status_code != 200:
        raise ScenarioError(f"the first redemption returned {first.status_code}")
    second = await ctx.client.exchange_code(auth)
    error = _oauth_error(second)
    ok = (
        second.status_code == 400 and error == "invalid_grant" and "access_token" not in second.text
    )
    checks = [
        (
            "replay_refused",
            _ok("the replay returned invalid_grant")
            if ok
            else _fail(f"HTTP {second.status_code}, error={error}"),
        )
    ]
    return _verdict(oauth_layer(second.status_code, error=error), checks)


@scenario("oauth_wrong_verifier")
async def oauth_wrong_verifier(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A stolen code redeemed with the wrong PKCE verifier fails, and the code is burned."""
    auth = await ctx.client.authorize_code("usr_alice", client_id=await ctx.client_id())
    wrong = await ctx.client.exchange_code(auth, code_verifier=secrets.token_urlsafe(48)[:64])
    legit = await ctx.client.exchange_code(auth)  # the real verifier, after the failed attempt
    wrong_err = _oauth_error(wrong)
    ok_wrong = wrong.status_code == 400 and wrong_err == "invalid_grant"
    ok_burned = legit.status_code == 400 and "access_token" not in legit.text
    checks = [
        (
            "wrong_verifier",
            _ok("invalid_grant")
            if ok_wrong
            else _fail(f"HTTP {wrong.status_code}, error={wrong_err}"),
        ),
        (
            "code_burned",
            _ok("the code cannot be redeemed afterwards")
            if ok_burned
            else _fail(f"HTTP {legit.status_code}"),
        ),
    ]
    return _verdict(oauth_layer(wrong.status_code, error=wrong_err), checks)


@scenario("oauth_code_redirect_swap")
async def oauth_code_redirect_swap(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A code redeemed with a different redirect_uri than the one it was issued for."""
    auth = await ctx.client.authorize_code("usr_alice", client_id=await ctx.client_id())
    swapped = await ctx.client.exchange_code(
        auth, redirect_uri="http://attacker.example.com/callback"
    )
    error = _oauth_error(swapped)
    ok = (
        swapped.status_code == 400
        and error == "invalid_grant"
        and "access_token" not in swapped.text
    )
    checks = [
        (
            "redirect_swap",
            _ok("invalid_grant") if ok else _fail(f"HTTP {swapped.status_code}, error={error}"),
        )
    ]
    return _verdict(oauth_layer(swapped.status_code, error=error), checks)


# ===================================================================================
# Category H: approval abuse
# ===================================================================================


def _marker(name: str) -> str:
    return f"redteam-{name}-{secrets.token_hex(4)}"


async def _proposal_state(ctx: ScenarioContext, identity: str, proposal_id: str) -> str:
    response = await ctx.call(identity, "get_proposal", {"proposal_id": proposal_id})
    return str(response.result.get("state") or f"error:{(response.tool_error or {}).get('code')}")


async def _review_link(ctx: ScenarioContext, proposal_id: str) -> str:
    """The signed review link, as the approver finds it on the admin approvals page."""
    carol = await ctx.web(CAROL)
    page = await carol.get("/admin/approvals")
    for href in re.findall(r'href="([^"]+)"', page.text):
        link = html.unescape(href)
        if link.startswith(f"/approve/{proposal_id}?"):
            return link
    raise ScenarioError(f"the approvals page has no review link for {proposal_id}")


async def _decide(
    ctx: ScenarioContext,
    session: WebSession,
    proposal_id: str,
    link: str,
    decision: str,
    *,
    csrf: str | None = None,
) -> httpx.Response:
    """POST an approve/reject decision the way the review page's form does."""
    query = parse_qs(urlsplit(link).query)
    if csrf is None:
        page = await session.get(link)
        if page.status_code != 200:
            raise ScenarioError(f"the review page returned {page.status_code}")
        found = re.search(r'name="csrf" value="([^"]+)"', page.text)
        if found is None:
            raise ScenarioError("the review page has no form token")
        csrf = found.group(1)
    return await session.post(
        f"/approve/{proposal_id}",
        {"csrf": csrf, "exp": query["exp"][0], "sig": query["sig"][0], "decision": decision},
    )


async def _propose_note(
    ctx: ScenarioContext, identity: str, marker: str, *, sql: str = _NOTE_SQL, max_rows: int = 1
) -> str:
    response = await ctx.call(
        identity,
        "propose_write",
        {
            "sql": sql,
            "params": [_NOTE_TICKET[identity], marker],
            "reason": "red-team scenario: a routine support note",
            "max_rows": max_rows,
        },
    )
    proposal_id = response.result.get("proposal_id")
    if not proposal_id:
        raise ScenarioError(f"the proposal was refused: {response.text[:200]}")
    return str(proposal_id)


async def _approved_note(ctx: ScenarioContext, identity: str, marker: str) -> str:
    """Propose a legitimate note, have carol approve it on the page, return the proposal id."""
    proposal_id = await _propose_note(ctx, identity, marker)
    carol = await ctx.web(CAROL)
    await _decide(ctx, carol, proposal_id, await _review_link(ctx, proposal_id), "approve")
    state = await _proposal_state(ctx, identity, proposal_id)
    if state != "approved":
        raise ScenarioError(f"carol's approval left the proposal {state}")
    return proposal_id


@scenario("propose_rejected")
async def propose_rejected(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A proposal the write path must refuse: nothing is queued and the target is untouched.

    YAML args: ``identity``, ``sql``, ``params``, an optional ``prelude_sql`` run on the
    read path first (for the EXECUTE-of-a-prepared-statement attack), the ``table``
    whose checksum must not change, and the ``expect_code`` of the refusal.
    """
    args = case["args"]
    identity = args["identity"]
    table = args.get("table", "public.support_tickets")
    before = await table_checksum(ctx.admin, table)
    prelude = ""
    if args.get("prelude_sql"):
        pre = await ctx.call(identity, "query", {"sql": args["prelude_sql"], "params": []})
        prelude = f"read path answered {'an error' if pre.tool_error else 'ok'} to the prelude; "
    response = await ctx.call(
        identity,
        "propose_write",
        {
            "sql": args["sql"],
            "params": args.get("params", []),
            "reason": "red-team scenario: a proposal the write path must refuse",
            "max_rows": 1,
        },
    )
    err = response.tool_error
    expected = args.get("expect_code", "rejected_by_validation")
    refused = err is not None and err.get("code") == expected
    checks = [
        (
            "refused",
            _ok(f"refused with {expected}")
            if refused
            else _fail(f"the proposal was not refused as {expected}: {response.text[:120]}"),
        ),
        ("proposal_state", await ctx.oracle("proposal_state", response, identity)),
        (
            "table_unchanged",
            await ctx.oracle(
                "table_checksum_unchanged", response, identity, table=table, before=before
            ),
        ),
    ]
    return _verdict(approval_layer(response), checks, extra=prelude.rstrip("; "))


@scenario("execute_before_approval")
async def execute_before_approval(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """Executing a proposal that is still pending: not_executable, and nothing is written."""
    p = await _pending_proposal(ctx, "bob")
    response = await ctx.call("bob", "execute_approved_write", {"proposal_id": p.proposal_id})
    err = response.tool_error
    refused = err is not None and err.get("code") == "not_executable"
    checks = [
        (
            "refused",
            _ok("not_executable")
            if refused
            else _fail(f"unexpected answer: {response.text[:120]}"),
        ),
        ("still_pending", await _still_pending(ctx, p)),
        (
            "nothing_written",
            await ctx.oracle(
                "rows_written_at_most",
                response,
                table="ticket_notes",
                column="note_body",
                value=p.marker,
                at_most=0,
            ),
        ),
    ]
    return _verdict(approval_layer(response), checks)


@scenario("proposal_other_person")
async def proposal_other_person(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A second person reaches for someone else's proposal.

    ``mode: get``: ``other`` asks for the proposer's pending proposal by id and must be
    told it does not exist. ``mode: execute``: the proposer's proposal is approved, and
    ``other`` tries to execute it, which must also answer not_found and write nothing.
    """
    args = case["args"]
    proposer, other = args["proposer"], args["other"]
    if args["mode"] == "get":
        p = await _pending_proposal(ctx, proposer)
        peek = await ctx.call(other, "get_proposal", {"proposal_id": p.proposal_id})
        seen = (peek.tool_error or {}).get("code") == "not_found" and p.marker not in peek.text
        checks = [
            (
                "get_hidden",
                _ok("get_proposal answered not_found")
                if seen
                else _fail(f"{other} saw: {peek.text[:120]}"),
            ),
            ("still_pending", await _still_pending(ctx, p)),
        ]
        return _verdict(approval_layer(peek), checks)
    marker = _marker("foreign")
    proposal_id = await _approved_note(ctx, proposer, marker)
    run = await ctx.call(other, "execute_approved_write", {"proposal_id": proposal_id})
    state = await _proposal_state(ctx, proposer, proposal_id)
    checks = [
        (
            "execute_refused",
            _ok("execute answered not_found")
            if (run.tool_error or {}).get("code") == "not_found"
            else _fail(f"{other}'s execute answered: {run.text[:120]}"),
        ),
        (
            "still_approved",
            _ok(f"{proposer}'s proposal is untouched")
            if state == "approved"
            else _fail(f"state is {state}"),
        ),
        (
            "nothing_written",
            await ctx.oracle(
                "rows_written_at_most",
                run,
                other,
                table="ticket_notes",
                column="note_body",
                value=marker,
                at_most=0,
            ),
        ),
    ]
    return _verdict(approval_layer(run), checks)


@dataclasses.dataclass
class _PendingProposal:
    proposal_id: str
    marker: str
    link: str
    exp: str
    sig: str


async def _pending_proposal(ctx: ScenarioContext, identity: str = "bob") -> _PendingProposal:
    """The run's shared pending proposal for ``identity`` (proposed on first use)."""
    if identity not in ctx._pending:
        marker = _marker("pending")
        proposal_id = await _propose_note(ctx, identity, marker)
        link = await _review_link(ctx, proposal_id)
        query = parse_qs(urlsplit(link).query)
        ctx._pending[identity] = _PendingProposal(
            proposal_id, marker, link, query["exp"][0], query["sig"][0]
        )
    return ctx._pending[identity]


async def _still_pending(ctx: ScenarioContext, p: _PendingProposal) -> OracleOutcome:
    state = await _proposal_state(ctx, "bob", p.proposal_id)
    return (
        _ok("the proposal is still pending") if state == "pending" else _fail(f"state is {state}")
    )


@scenario("approve_page_non_approver")
async def approve_page_non_approver(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """bob, signed in but not an approver, opens a valid link: 403 and no SQL shown."""
    p = await _pending_proposal(ctx)
    bob = await ctx.web("usr_bob")
    page = await bob.get(p.link)
    shown = p.marker in page.text or "ticket_notes" in page.text
    checks = [
        ("http_status", await ctx.oracle("http_status", response_from_httpx(page), statuses=[403])),
        (
            "nothing_shown",
            _fail("the page disclosed the statement") if shown else _ok("no statement on the page"),
        ),
        ("still_pending", await _still_pending(ctx, p)),
    ]
    return _verdict(approval_page_layer(page.status_code), checks)


@scenario("approve_post_non_approver")
async def approve_post_non_approver(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """bob POSTs an approval for his own proposal. He has no way to obtain a CSRF token.

    The CSRF check runs before the approver check, and a non-approver is never shown
    a form, so the refusal is 400 (bad form token) or 403 (not an approver): either
    way the proposal stays pending.
    """
    p = await _pending_proposal(ctx)
    bob = await ctx.web("usr_bob")
    resp = await _decide(ctx, bob, p.proposal_id, p.link, "approve", csrf=secrets.token_urlsafe(24))
    checks = [
        (
            "http_status",
            await ctx.oracle("http_status", response_from_httpx(resp), statuses=[400, 403]),
        ),
        ("still_pending", await _still_pending(ctx, p)),
    ]
    return _verdict(approval_page_layer(resp.status_code), checks)


@scenario("approve_tampered_signature")
async def approve_tampered_signature(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """The approver opens a link whose signature was altered: 404, the proposal is not shown."""
    p = await _pending_proposal(ctx)
    carol = await ctx.web(CAROL)
    flipped = ("0" if p.sig[0] != "0" else "1") + p.sig[1:]
    resp = await carol.get(f"/approve/{p.proposal_id}?exp={p.exp}&sig={flipped}")
    checks = [
        ("http_status", await ctx.oracle("http_status", response_from_httpx(resp), statuses=[404])),
        (
            "nothing_shown",
            _fail("statement shown") if p.marker in resp.text else _ok("no statement on the page"),
        ),
        ("still_pending", await _still_pending(ctx, p)),
    ]
    return _verdict(approval_page_layer(resp.status_code), checks)


@scenario("approve_extended_expiry")
async def approve_extended_expiry(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A link whose expiry was pushed out but keeps the old signature: 404 for GET and POST."""
    p = await _pending_proposal(ctx)
    carol = await ctx.web(CAROL)
    later = str(int(p.exp) + 30 * 24 * 3600)
    got = await carol.get(f"/approve/{p.proposal_id}?exp={later}&sig={p.sig}")
    csrf = await carol.csrf_from(p.link)
    posted = await carol.post(
        f"/approve/{p.proposal_id}",
        {"csrf": csrf, "exp": later, "sig": p.sig, "decision": "approve"},
    )
    checks = [
        ("get_refused", await ctx.oracle("http_status", response_from_httpx(got), statuses=[404])),
        (
            "post_refused",
            await ctx.oracle("http_status", response_from_httpx(posted), statuses=[404]),
        ),
        ("still_pending", await _still_pending(ctx, p)),
    ]
    return _verdict(approval_page_layer(got.status_code), checks)


@scenario("approve_without_session")
async def approve_without_session(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A valid link and a forged form, but no signed-in session at all: refused, still pending."""
    p = await _pending_proposal(ctx)
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as anonymous:
        resp = await anonymous.post(
            f"{ctx.client.base_url}/approve/{p.proposal_id}",
            data={"csrf": "x", "exp": p.exp, "sig": p.sig, "decision": "approve"},
        )
    checks = [
        (
            "http_status",
            await ctx.oracle("http_status", response_from_httpx(resp), statuses=[400, 401, 403]),
        ),
        ("still_pending", await _still_pending(ctx, p)),
    ]
    return _verdict(approval_page_layer(resp.status_code), checks)


@scenario("approve_csrf")
async def approve_csrf(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """A cross-site form post with the approver's cookie but no valid CSRF token: 400."""
    p = await _pending_proposal(ctx)
    carol = await ctx.web(CAROL)
    forged = await carol.post(
        f"/approve/{p.proposal_id}",
        {"csrf": "forged-by-another-site", "exp": p.exp, "sig": p.sig, "decision": "approve"},
    )
    missing = await carol.post(
        f"/approve/{p.proposal_id}", {"exp": p.exp, "sig": p.sig, "decision": "approve"}
    )
    checks = [
        (
            "forged_token",
            await ctx.oracle("http_status", response_from_httpx(forged), statuses=[400]),
        ),
        (
            "missing_token",
            await ctx.oracle("http_status", response_from_httpx(missing), statuses=[400]),
        ),
        ("still_pending", await _still_pending(ctx, p)),
    ]
    return _verdict(approval_page_layer(forged.status_code), checks)


@scenario("approve_replay")
async def approve_replay(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """Replaying the approval POST after the decision is made: 409, no second grant."""
    identity = case.get("args", {}).get("identity", "dana")
    marker = _marker("replay")
    proposal_id = await _propose_note(ctx, identity, marker)
    carol = await ctx.web(CAROL)
    link = await _review_link(ctx, proposal_id)
    csrf = await carol.csrf_from(link)  # the form token the review page rendered
    await _decide(ctx, carol, proposal_id, link, "approve", csrf=csrf)
    again = await _decide(ctx, carol, proposal_id, link, "approve", csrf=csrf)
    state = await _proposal_state(ctx, identity, proposal_id)
    checks = [
        (
            "http_status",
            await ctx.oracle("http_status", response_from_httpx(again), statuses=[409]),
        ),
        (
            "single_grant",
            _ok("the proposal is still approved once")
            if state == "approved"
            else _fail(f"state is {state}"),
        ),
    ]
    return _verdict(approval_page_layer(again.status_code), checks)


@scenario("execute_rejected")
async def execute_rejected(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """The approver rejects; the proposer executes anyway: not_executable, nothing written."""
    identity = case.get("args", {}).get("identity", "dana")
    marker = _marker("rejected")
    proposal_id = await _propose_note(ctx, identity, marker)
    carol = await ctx.web(CAROL)
    await _decide(ctx, carol, proposal_id, await _review_link(ctx, proposal_id), "reject")
    state = await _proposal_state(ctx, identity, proposal_id)
    if state != "rejected":
        raise ScenarioError(f"carol's rejection left the proposal {state}")
    run = await ctx.call(identity, "execute_approved_write", {"proposal_id": proposal_id})
    refused = (run.tool_error or {}).get("code") == "not_executable"
    checks = [
        (
            "refused",
            _ok("not_executable") if refused else _fail(f"execute answered: {run.text[:120]}"),
        ),
        (
            "nothing_written",
            await ctx.oracle(
                "rows_written_at_most",
                run,
                identity,
                table="ticket_notes",
                column="note_body",
                value=marker,
                at_most=0,
            ),
        ),
    ]
    return _verdict(approval_layer(run), checks)


@scenario("execute_max_rows")
async def execute_max_rows(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """An approved UPDATE that touches far more rows than max_rows is rolled back and fails."""
    identity = case.get("args", {}).get("identity", "bob")
    table = "public.support_tickets"
    marker = _marker("maxrows")
    before = await table_checksum(ctx.admin, table)
    response = await ctx.call(
        identity,
        "propose_write",
        {
            "sql": "UPDATE support_tickets SET status = $1 WHERE region = $2",
            "params": [marker, ctx.region_for_identity[identity]],
            "reason": "red-team scenario: an update far larger than max_rows",
            "max_rows": 1,
        },
    )
    proposal_id = response.result.get("proposal_id")
    if not proposal_id:
        raise ScenarioError(f"the proposal was refused: {response.text[:200]}")
    carol = await ctx.web(CAROL)
    await _decide(
        ctx, carol, str(proposal_id), await _review_link(ctx, str(proposal_id)), "approve"
    )
    run = await ctx.call(identity, "execute_approved_write", {"proposal_id": proposal_id})
    result = run.result
    touched = int(result.get("rows_affected") or 0)
    failed = result.get("state") == "failed" and touched > 1
    marked = int(
        await ctx.admin.fetchval("SELECT count(*) FROM support_tickets WHERE status = $1", marker)
    )
    checks = [
        (
            "execution_failed",
            _ok(f"failed after {touched} affected rows")
            if failed
            else _fail(f"execute answered: {run.text[:160]}"),
        ),
        (
            "table_unchanged",
            await ctx.oracle("table_checksum_unchanged", run, identity, table=table, before=before),
        ),
        (
            "no_marked_rows",
            _ok("no ticket carries the marker")
            if marked == 0
            else _fail(f"{marked} tickets carry the marker"),
        ),
    ]
    return _verdict("approval" if failed else "none:executed", checks)


@scenario("execute_twice")
async def execute_twice(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """One approval, two sequential executions: exactly one 'executed', one marked row."""
    identity = case.get("args", {}).get("identity", "dana")
    marker = _marker("twice")
    proposal_id = await _approved_note(ctx, identity, marker)
    first = await ctx.call(identity, "execute_approved_write", {"proposal_id": proposal_id})
    second = await ctx.call(identity, "execute_approved_write", {"proposal_id": proposal_id})
    executed = sum(1 for r in (first, second) if r.result.get("state") == "executed")
    refused = (second.tool_error or {}).get("code") == "not_executable"
    checks = [
        (
            "exactly_one_executed",
            _ok("one execution") if executed == 1 else _fail(f"{executed} executions"),
        ),
        (
            "second_refused",
            _ok("not_executable") if refused else _fail(f"second answered: {second.text[:120]}"),
        ),
        (
            "rows_written",
            await ctx.oracle(
                "rows_written_at_most",
                second,
                identity,
                table="ticket_notes",
                column="note_body",
                value=marker,
                at_most=1,
            ),
        ),
    ]
    return _verdict(approval_layer(second), checks)


@scenario("execute_concurrent")
async def execute_concurrent(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """Two simultaneous executions of one approval: the atomic claim lets exactly one run."""
    identity = case.get("args", {}).get("identity", "dana")
    marker = _marker("concurrent")
    proposal_id = await _approved_note(ctx, identity, marker)
    args = {"proposal_id": proposal_id}
    first, second = await asyncio.gather(
        ctx.call(identity, "execute_approved_write", args),
        ctx.call(identity, "execute_approved_write", args),
    )
    executed = sum(1 for r in (first, second) if r.result.get("state") == "executed")
    loser = first if first.tool_error else second
    refused = (loser.tool_error or {}).get("code") == "not_executable"
    checks = [
        (
            "exactly_one_executed",
            _ok("one execution") if executed == 1 else _fail(f"{executed} executions"),
        ),
        (
            "loser_refused",
            _ok("not_executable") if refused else _fail(f"the other answered: {loser.text[:120]}"),
        ),
        (
            "rows_written",
            await ctx.oracle(
                "rows_written_at_most",
                loser,
                identity,
                table="ticket_notes",
                column="note_body",
                value=marker,
                at_most=1,
            ),
        ),
    ]
    return _verdict(approval_layer(loser), checks)


@scenario("write_lifecycle")
async def write_lifecycle(ctx: ScenarioContext, case: dict[str, Any]) -> Verdict:
    """Benign: a legitimate write, proposed, approved on the page by carol and executed once.

    Not blocked (passes) when the proposal ends ``executed`` with exactly one row written.
    """
    identity = case.get("args", {}).get("identity", "bob")
    marker = _marker("lifecycle")
    proposal_id = await _approved_note(ctx, identity, marker)
    run = await ctx.call(identity, "execute_approved_write", {"proposal_id": proposal_id})
    state = await _proposal_state(ctx, identity, proposal_id)
    written = await ctx.rows_marked(marker)
    ok = run.result.get("state") == "executed" and state == "executed" and written == 1
    detail = f"executed={run.result.get('state')}, state={state}, rows written={written}"
    return Verdict(blocked=not ok, observed_layer="ok" if ok else "none:failed", detail=detail)


__all__ = [
    "APPROVAL_CODES",
    "SCENARIOS",
    "ScenarioContext",
    "ScenarioError",
    "Verdict",
    "approval_layer",
    "approval_page_layer",
    "oauth_layer",
    "scenario",
]
