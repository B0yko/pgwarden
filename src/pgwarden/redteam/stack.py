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
    """A step of the flow did not go the way a working deployment answers."""


@dataclasses.dataclass(frozen=True)
class Tokens:
    access_token: str
    refresh_token: str | None
    client_id: str
    expires_in: int


def _hidden(html: str, name: str) -> str:
    match = re.search(rf'name="{re.escape(name)}" value="([^"]+)"', html)
    if not match:
        raise StackError(f"expected a hidden form field {name!r} on the page")
    return match.group(1)


@dataclasses.dataclass
class StackClient:
    base_url: str
    redirect_uri: str = DEFAULT_REDIRECT_URI
    timeout_s: float = 30.0

    @property
    def resource(self) -> str:
        return f"{self.base_url.rstrip('/')}/mcp"

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(follow_redirects=False, timeout=self.timeout_s)

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

    async def login(self, user_sub: str, *, client_id: str | None = None) -> Tokens:
        """Sign in as the mock IdP user ``user_sub`` (for example ``usr_bob``)."""
        client_id = client_id or await self.register_client()
        url, verifier, state = self.authorize_url(client_id)
        async with self._http() as http:
            consent = await http.get(url)
            if consent.status_code != 200:
                raise StackError(f"authorize returned {consent.status_code}: {consent.text[:200]}")
            to_idp = await http.post(
                f"{self.base_url}/oauth/authorize/consent",
                data={
                    "pending_id": _hidden(consent.text, "pending_id"),
                    "csrf": _hidden(consent.text, "csrf"),
                    "decision": "approve",
                },
            )
            if to_idp.status_code != 303:
                raise StackError(f"consent returned {to_idp.status_code}")
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
                    f"the callback returned {confirmation.status_code}: {confirmation.text[:200]}"
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
                raise StackError(f"confirmation returned {done.status_code}")
            params = {
                k: v[0] for k, v in parse_qs(urlsplit(done.headers["location"]).query).items()
            }
            if params.get("state") != state or "code" not in params:
                raise StackError("the authorization response lacks the code or the state")
            token = await http.post(
                f"{self.base_url}/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": params["code"],
                    "redirect_uri": self.redirect_uri,
                    "code_verifier": verifier,
                    "client_id": client_id,
                    "resource": self.resource,
                },
            )
        if token.status_code != 200:
            raise StackError(f"token exchange returned {token.status_code}: {token.text[:200]}")
        body: dict[str, Any] = token.json()
        return Tokens(
            access_token=str(body["access_token"]),
            refresh_token=body.get("refresh_token"),
            client_id=client_id,
            expires_in=int(body.get("expires_in", 0)),
        )

    async def machine_token(self, name: str, secret: str) -> Tokens:
        async with self._http() as http:
            resp = await http.post(
                f"{self.base_url}/oauth/token",
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


__all__ = ["DEFAULT_REDIRECT_URI", "StackClient", "StackError", "Tokens"]
