"""Upstream login: the organisation's IdP proves who the person is.

Presets:

* ``oidc`` (generic): discovery from ``upstream.discovery_url`` (or the issuer's
  well-known URL), authorization code flow with PKCE S256 and a nonce, and the ID
  token validated for signature (JWKS), ``iss``, ``aud``, ``exp`` and ``nonce``.
  ``issuer`` and ``discovery_url`` may differ (the compose demo's IdP is reached
  as ``mock-idp`` from the gateway but as ``localhost`` from the browser).
* ``google``: OIDC with Google's discovery document.
* ``entra``: single-tenant Microsoft Entra ID; the identity is ``<tid>:<oid>``
  and the ``email`` claim is never treated as verified.
* ``github``: GitHub OAuth apps are OAuth 2.0 without ID tokens, so the identity
  is the numeric user id from ``GET /user`` and the verified primary email from
  ``GET /user/emails``.

The code flow uses Authlib's OAuth 2 client (on httpx2, like the MCP SDK); ID
tokens are verified with PyJWT against the provider's JWKS, accepting asymmetric
algorithms only.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import httpx2
import jwt
from authlib.integrations.httpx_client import AsyncOAuth2Client

from pgwarden.config import UpstreamConfig
from pgwarden.identity import UpstreamIdentity, entra_subject

_ASYMMETRIC_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"]
_GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
_GITHUB_API = "https://api.github.com"


class UpstreamError(Exception):
    """The upstream login failed or returned an identity pgwarden will not accept."""


@dataclasses.dataclass(frozen=True)
class Endpoints:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str | None


def _truthy(value: object) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


class UpstreamProvider:
    """One configured upstream IdP."""

    def __init__(
        self,
        config: UpstreamConfig,
        *,
        client_secret: str,
        redirect_uri: str,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.transport = transport
        self._endpoints: Endpoints | None = None
        self._jwks: dict[str, Any] | None = None

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def uses_oidc(self) -> bool:
        return self.config.preset != "github"

    def _http(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=self.transport, timeout=10.0)

    def _oauth_client(self) -> AsyncOAuth2Client:
        return AsyncOAuth2Client(
            client_id=self.config.client_id,
            client_secret=self.client_secret,
            scope=" ".join(self._scopes()),
            redirect_uri=self.redirect_uri,
            code_challenge_method="S256",
            token_endpoint_auth_method="client_secret_basic",
            transport=self.transport,
            timeout=10.0,
        )

    def _scopes(self) -> list[str]:
        if self.config.preset == "github":
            return ["read:user", "user:email"]
        return self.config.scopes

    def _discovery_url(self) -> str:
        if self.config.discovery_url:
            return self.config.discovery_url
        if self.config.preset == "google":
            return "https://accounts.google.com/.well-known/openid-configuration"
        if self.config.preset == "entra":
            return (
                f"https://login.microsoftonline.com/{self.config.tenant_id}/v2.0/"
                ".well-known/openid-configuration"
            )
        return f"{self.config.issuer.rstrip('/')}/.well-known/openid-configuration"

    def expected_issuer(self) -> str:
        if self.config.preset == "entra":
            return f"https://login.microsoftonline.com/{self.config.tenant_id}/v2.0"
        return self.config.issuer

    async def endpoints(self) -> Endpoints:
        if self._endpoints is not None:
            return self._endpoints
        if self.config.preset == "github":
            self._endpoints = Endpoints(
                issuer="https://github.com",
                authorization_endpoint=_GITHUB_AUTHORIZE,
                token_endpoint=_GITHUB_TOKEN,
                jwks_uri=None,
            )
            return self._endpoints
        async with self._http() as http:
            response = await http.get(self._discovery_url())
        if response.status_code != 200:
            raise UpstreamError(f"upstream discovery returned HTTP {response.status_code}")
        doc = response.json()
        if doc.get("issuer") != self.expected_issuer():
            raise UpstreamError(
                f"upstream discovery issuer {doc.get('issuer')!r} does not match the configured "
                f"issuer {self.expected_issuer()!r}"
            )
        methods = doc.get("code_challenge_methods_supported")
        if methods is not None and "S256" not in methods:
            raise UpstreamError("the upstream provider does not support PKCE S256")
        self._endpoints = Endpoints(
            issuer=str(doc["issuer"]),
            authorization_endpoint=str(doc["authorization_endpoint"]),
            token_endpoint=str(doc["token_endpoint"]),
            jwks_uri=str(doc["jwks_uri"]),
        )
        return self._endpoints

    async def authorization_url(self, *, state: str, nonce: str, code_verifier: str) -> str:
        endpoints = await self.endpoints()
        client = self._oauth_client()
        try:
            extra: dict[str, str] = {}
            if self.uses_oidc:
                extra["nonce"] = nonce
            url, _ = client.create_authorization_url(
                endpoints.authorization_endpoint,
                state=state,
                code_verifier=code_verifier,
                **extra,
            )
        finally:
            await client.aclose()
        return str(url)

    async def exchange(self, *, code: str, code_verifier: str, nonce: str) -> UpstreamIdentity:
        endpoints = await self.endpoints()
        client = self._oauth_client()
        try:
            token = await client.fetch_token(
                endpoints.token_endpoint, code=code, code_verifier=code_verifier
            )
        except Exception as exc:  # noqa: BLE001 - any failure is an upstream login failure
            raise UpstreamError(f"upstream token exchange failed: {exc}") from exc
        finally:
            await client.aclose()
        if "error" in token:
            raise UpstreamError(f"upstream token exchange failed: {token.get('error')}")
        if self.config.preset == "github":
            return await self._github_identity(str(token.get("access_token", "")))
        id_token = token.get("id_token")
        if not isinstance(id_token, str):
            raise UpstreamError("the upstream provider returned no ID token")
        claims = await self.validate_id_token(id_token, nonce=nonce)
        return self.identity_from_claims(claims)

    async def _jwk_set(self, *, refresh: bool = False) -> dict[str, Any]:
        if self._jwks is not None and not refresh:
            return self._jwks
        endpoints = await self.endpoints()
        if endpoints.jwks_uri is None:  # pragma: no cover - only OIDC presets reach here
            raise UpstreamError("no JWKS for this provider")
        async with self._http() as http:
            response = await http.get(endpoints.jwks_uri)
        if response.status_code != 200:
            raise UpstreamError(f"JWKS fetch returned HTTP {response.status_code}")
        self._jwks = dict(response.json())
        return self._jwks

    async def validate_id_token(self, id_token: str, *, nonce: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise UpstreamError(f"malformed ID token: {exc}") from exc
        alg = header.get("alg")
        if alg not in _ASYMMETRIC_ALGS:
            raise UpstreamError(f"ID token algorithm {alg!r} is not accepted")
        kid = header.get("kid")
        key = await self._find_key(kid)
        if key is None:
            key = await self._find_key(kid, refresh=True)
        if key is None:
            raise UpstreamError("ID token signing key is not in the provider's JWKS")
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=[str(alg)],
                audience=self.config.client_id,
                issuer=self.expected_issuer(),
                leeway=60,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise UpstreamError(f"ID token rejected: {exc}") from exc
        if claims.get("nonce") != nonce:
            raise UpstreamError("ID token nonce does not match this login")
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.config.client_id:
            raise UpstreamError("ID token azp does not name this client")
        return claims

    async def _find_key(self, kid: str | None, *, refresh: bool = False) -> Any:
        jwks = await self._jwk_set(refresh=refresh)
        try:
            key_set = jwt.PyJWKSet.from_dict(jwks)
        except jwt.PyJWTError as exc:
            raise UpstreamError(f"unusable JWKS: {exc}") from exc
        for key in key_set.keys:
            if kid is None or key.key_id == kid:
                return key.key
        return None

    def identity_from_claims(self, claims: dict[str, Any]) -> UpstreamIdentity:
        if self.config.preset == "entra":
            tid, oid = claims.get("tid"), claims.get("oid")
            if not tid or not oid:
                raise UpstreamError("Entra ID token lacks tid/oid")
            if tid != self.config.tenant_id:
                raise UpstreamError("Entra ID token is from another tenant")
            email = claims.get("email") or claims.get("preferred_username")
            # The Entra email claim is not verified: never treat it as such.
            return UpstreamIdentity(
                provider=self.name,
                subject=entra_subject(str(tid), str(oid)),
                email=str(email) if email else None,
                email_verified=False,
            )
        email = claims.get("email")
        return UpstreamIdentity(
            provider=self.name,
            subject=str(claims["sub"]),
            email=str(email) if email else None,
            email_verified=_truthy(claims.get("email_verified")),
        )

    async def _github_identity(self, access_token: str) -> UpstreamIdentity:
        if not access_token:
            raise UpstreamError("GitHub returned no access token")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with self._http() as http:
            user = await http.get(f"{_GITHUB_API}/user", headers=headers)
            emails = await http.get(f"{_GITHUB_API}/user/emails", headers=headers)
        if user.status_code != 200:
            raise UpstreamError(f"GitHub /user returned HTTP {user.status_code}")
        user_id = user.json().get("id")
        if not isinstance(user_id, int):
            raise UpstreamError("GitHub /user has no numeric id")
        email: str | None = None
        if emails.status_code == 200:
            for entry in emails.json():
                if entry.get("primary") and entry.get("verified"):
                    email = str(entry.get("email"))
                    break
        return UpstreamIdentity(
            provider=self.name,
            subject=str(user_id),
            email=email,
            email_verified=email is not None,
        )


__all__ = ["Endpoints", "UpstreamError", "UpstreamProvider"]
