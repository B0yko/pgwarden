"""A client for a running pgwarden deployment, used by the red-team runner, the
LLM harness, the benchmarks and the stack tests.

``login`` performs the real browser flow without a browser: register a public
client (or reuse one), ``/oauth/authorize`` with PKCE, ``resource`` and
``state``, the pre-login consent POST, the upstream sign-in, the callback, the
confirmation POST and the code exchange. The upstream sign-in step drives the
in-repo mock IdP's user picker, so person logins work against the demo stack
only; machine identities (``client_credentials``) work against any deployment.
Nothing here bypasses authentication: every token comes from the gateway's own
token endpoint after the same checks a real client goes through.
"""

from __future__ import annotations

import dataclasses
import re
import secrets
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from pgwarden.oauth import pkce

DEFAULT_REDIRECT_URI = "http://127.0.0.1:9/callback"  # never listened on; read from Location


class StackError(RuntimeError):
    """A step of the flow did not go the way a working deployment answers.

    ``status`` carries the HTTP status of the refused step when there is one, so
    a red-team case can tell "the gateway said 403" from "the flow broke".
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclasses.dataclass(frozen=True)
class Tokens:
    access_token: str
    refresh_token: str | None
    client_id: str
    expires_in: int


@dataclasses.dataclass(frozen=True)
class AuthCode:
    """An authorization code and everything needed to redeem it at ``/oauth/token``."""

    code: str
    verifier: str
    state: str
    client_id: str
    redirect_uri: str


@dataclasses.dataclass
class WebSession:
    """A signed-in browser session (the ``pgw_session`` cookie) for the gateway's pages.

    Drives ``/approve`` and ``/admin`` the way an approver's browser does: the
    cookie jar lives in the underlying client, and ``csrf_from`` reads the form
    token out of a rendered page.
    """

    base_url: str
    http: httpx.AsyncClient

    async def get(self, path_or_url: str) -> httpx.Response:
        return await self.http.get(self._url(path_or_url))

    async def post(self, path_or_url: str, data: dict[str, str]) -> httpx.Response:
        return await self.http.post(self._url(path_or_url), data=data)

    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return f"{self.base_url}{path_or_url}"

    async def csrf_from(self, path_or_url: str) -> str:
        page = await self.get(path_or_url)
        if page.status_code != 200:
            raise StackError(f"{path_or_url} returned {page.status_code}", status=page.status_code)
        return _hidden(page.text, "csrf")

    async def aclose(self) -> None:
        await self.http.aclose()


def _hidden(html: str, name: str) -> str:
    match = re.search(rf'name="{re.escape(name)}" value="([^"]+)"', html)
    if not match:
        raise StackError(f"expected a hidden form field {name!r} on the page")
    return match.group(1)


@dataclasses.dataclass
class StackClient:
    """Talks to a gateway whose public URL is ``base_url``.

    ``connect_url`` is for a client that cannot reach the public URL, such as the
    benchmark container on the compose network (``http://gateway:8080`` while the
    gateway's public URL is ``http://localhost:<port>``). Requests then go to
    ``connect_url`` with the public host in the ``Host`` header, so the gateway's
    host check still passes, while the token audience stays the public resource.
    """

    base_url: str
    redirect_uri: str = DEFAULT_REDIRECT_URI
    timeout_s: float = 30.0
    connect_url: str | None = None

    @property
    def resource(self) -> str:
        return f"{self.base_url.rstrip('/')}/mcp"

    @property
    def origin(self) -> str:
        """Where requests are actually sent."""
        return (self.connect_url or self.base_url).rstrip("/")

    @property
    def mcp_endpoint(self) -> str:
        """The URL the MCP calls are POSTed to (differs from ``resource`` with ``connect_url``)."""
        return f"{self.origin}/mcp"

    def _http(self) -> httpx.AsyncClient:
        return self.http_client(follow_redirects=False, timeout=self.timeout_s)

    def http_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """An HTTP client for this gateway, with the public ``Host`` when ``connect_url`` is set."""
        if self.connect_url:
            headers = dict(kwargs.pop("headers", None) or {})
            headers.setdefault("Host", urlsplit(self.base_url).netloc)
            kwargs["headers"] = headers
        return httpx.AsyncClient(**kwargs)

    async def register_client(self, name: str = "pgwarden red team") -> str:
        async with self._http() as http:
            resp = await http.post(
                f"{self.base_url}/oauth/register",
                json={
                    "client_name": name,
                    "redirect_uris": [self.redirect_uri],
                    "token_endpoint_auth_method": "none",
                },
            )
        if resp.status_code != 201:
            raise StackError(f"client registration returned {resp.status_code}: {resp.text[:200]}")
        return str(resp.json()["client_id"])

    def authorize_url(self, client_id: str, **overrides: str) -> tuple[str, str, str]:
        """Return ``(url, code_verifier, state)`` for an authorization request."""
        verifier = secrets.token_urlsafe(48)[:64]
        state = secrets.token_urlsafe(16)
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": self.redirect_uri,
            "code_challenge": pkce.s256_challenge(verifier),
            "code_challenge_method": "S256",
            "state": state,
            "resource": self.resource,
        }
        params.update(overrides)
        return f"{self.base_url}/oauth/authorize?{urlencode(params)}", verifier, state

    async def authorize_code(self, user_sub: str, *, client_id: str | None = None) -> AuthCode:
        """Run the browser flow up to the authorization code (not yet redeemed)."""
        client_id = client_id or await self.register_client()
        url, verifier, state = self.authorize_url(client_id)
        async with self._http() as http:
            consent = await http.get(url)
            if consent.status_code != 200:
                raise StackError(
                    f"authorize returned {consent.status_code}: {consent.text[:200]}",
                    status=consent.status_code,
                )
            to_idp = await http.post(
                f"{self.base_url}/oauth/authorize/consent",
                data={
                    "pending_id": _hidden(consent.text, "pending_id"),
                    "csrf": _hidden(consent.text, "csrf"),
                    "decision": "approve",
                },
            )
            if to_idp.status_code != 303:
                raise StackError(
                    f"consent returned {to_idp.status_code}", status=to_idp.status_code
                )
            idp_url = to_idp.headers["location"]
            picker = await http.get(idp_url)
            if picker.status_code != 200:
                raise StackError(f"the sign-in page returned {picker.status_code}")
            idp_origin = "{0.scheme}://{0.netloc}".format(urlsplit(idp_url))
            chosen = await http.post(
                f"{idp_origin}/authorize/login",
                data={"request_id": _hidden(picker.text, "request_id"), "sub": user_sub},
            )
            if chosen.status_code not in (302, 303):
                raise StackError(f"the sign-in form returned {chosen.status_code}")
            confirmation = await http.get(chosen.headers["location"])
            if confirmation.status_code != 200:
                raise StackError(
                    f"the callback returned {confirmation.status_code}: {confirmation.text[:200]}",
                    status=confirmation.status_code,
                )
            done = await http.post(
                f"{self.base_url}/oauth/authorize/confirm",
                data={
                    "pending_id": _hidden(confirmation.text, "pending_id"),
                    "csrf": _hidden(confirmation.text, "csrf"),
                    "decision": "confirm",
                },
            )
            if done.status_code != 303:
                raise StackError(
                    f"confirmation returned {done.status_code}", status=done.status_code
                )
            params = {
                k: v[0] for k, v in parse_qs(urlsplit(done.headers["location"]).query).items()
            }
        if params.get("state") != state or "code" not in params:
            raise StackError("the authorization response lacks the code or the state")
        return AuthCode(
            code=params["code"],
            verifier=verifier,
            state=state,
            client_id=client_id,
            redirect_uri=self.redirect_uri,
        )

    async def exchange_code(self, auth: AuthCode, **overrides: str) -> httpx.Response:
        """Redeem an authorization code; ``overrides`` replace form fields (attacks)."""
        data = {
            "grant_type": "authorization_code",
            "code": auth.code,
            "redirect_uri": auth.redirect_uri,
            "code_verifier": auth.verifier,
            "client_id": auth.client_id,
            "resource": self.resource,
        }
        data.update(overrides)
        async with self._http() as http:
            return await http.post(f"{self.base_url}/oauth/token", data=data)

    def _tokens_from(self, token: httpx.Response, client_id: str) -> Tokens:
        if token.status_code != 200:
            raise StackError(
                f"token exchange returned {token.status_code}: {token.text[:200]}",
                status=token.status_code,
            )
        body: dict[str, Any] = token.json()
        return Tokens(
            access_token=str(body["access_token"]),
            refresh_token=body.get("refresh_token"),
            client_id=client_id,
            expires_in=int(body.get("expires_in", 0)),
        )

    async def login(self, user_sub: str, *, client_id: str | None = None) -> Tokens:
        """Sign in as the mock IdP user ``user_sub`` (for example ``usr_bob``)."""
        auth = await self.authorize_code(user_sub, client_id=client_id)
        return self._tokens_from(await self.exchange_code(auth), auth.client_id)

    async def web_login(self, user_sub: str, *, next_path: str = "/") -> WebSession:
        """Sign in to the gateway's own pages (``/approve``, ``/admin``) as ``user_sub``."""
        http = self._http()
        try:
            start = await http.get(f"{self.base_url}/login", params={"next": next_path})
            if start.status_code != 303:
                raise StackError(f"/login returned {start.status_code}", status=start.status_code)
            idp_url = start.headers["location"]
            picker = await http.get(idp_url)
            if picker.status_code != 200:
                raise StackError(f"the sign-in page returned {picker.status_code}")
            idp_origin = "{0.scheme}://{0.netloc}".format(urlsplit(idp_url))
            chosen = await http.post(
                f"{idp_origin}/authorize/login",
                data={"request_id": _hidden(picker.text, "request_id"), "sub": user_sub},
            )
            if chosen.status_code not in (302, 303):
                raise StackError(f"the sign-in form returned {chosen.status_code}")
            callback = await http.get(chosen.headers["location"])
            if callback.status_code != 303 or not any(
                c.name.endswith("pgw_session") for c in http.cookies.jar
            ):
                raise StackError(
                    f"the web callback returned {callback.status_code}: {callback.text[:200]}",
                    status=callback.status_code,
                )
        except BaseException:
            await http.aclose()
            raise
        return WebSession(self.base_url, http)

    async def machine_token(self, name: str, secret: str) -> Tokens:
        async with self._http() as http:
            resp = await http.post(
                f"{self.origin}/oauth/token",
                auth=(name, secret),
                data={"grant_type": "client_credentials", "resource": self.resource},
            )
        if resp.status_code != 200:
            raise StackError(f"client_credentials returned {resp.status_code}: {resp.text[:200]}")
        body = resp.json()
        return Tokens(str(body["access_token"]), None, name, int(body.get("expires_in", 0)))

    async def refresh(self, tokens: Tokens) -> httpx.Response:
        async with self._http() as http:
            return await http.post(
                f"{self.base_url}/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": tokens.refresh_token or "",
                    "client_id": tokens.client_id,
                },
            )


__all__ = [
    "DEFAULT_REDIRECT_URI",
    "AuthCode",
    "StackClient",
    "StackError",
    "Tokens",
    "WebSession",
]
