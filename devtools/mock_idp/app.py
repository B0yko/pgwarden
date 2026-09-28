"""Development-only mock OIDC identity provider for the pgwarden demo stack.

Standalone FastAPI application. It is not part of the pgwarden distribution
and must never import the ``pgwarden`` package. It refuses to start unless
``MOCK_IDP_DEV_ONLY=1`` is set, because it hands out tokens for a fixed list
of demo users with no real authentication.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import jwt
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.datastructures import FormData


def _require_dev_only() -> None:
    """Refuse to start unless explicitly confirmed as a dev-only instance."""
    if os.environ.get("MOCK_IDP_DEV_ONLY") != "1":
        sys.exit(
            "mock_idp: refusing to start. This is a development-only OIDC "
            "provider with hardcoded demo users and no real authentication. "
            "Set MOCK_IDP_DEV_ONLY=1 to confirm you want to run it."
        )


_require_dev_only()

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))

CODE_TTL_SECONDS = 60
AUTH_REQUEST_TTL_SECONDS = 300
ID_TOKEN_TTL_SECONDS = 300
ACCESS_TOKEN_TTL_SECONDS = 300


@dataclass(frozen=True)
class DemoUser:
    sub: str
    email: str
    email_verified: bool
    name: str


@dataclass
class PendingAuthRequest:
    client_id: str
    redirect_uri: str
    code_challenge: str
    state: str | None
    nonce: str | None
    scope: str
    created_at: float

    def is_expired(self) -> bool:
        return time.time() - self.created_at > AUTH_REQUEST_TTL_SECONDS


@dataclass
class IssuedCode:
    sub: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    nonce: str | None
    scope: str
    auth_time: int
    created_at: float
    used: bool = False

    def is_expired(self) -> bool:
        return time.time() - self.created_at > CODE_TTL_SECONDS


@dataclass
class AccessTokenRecord:
    sub: str
    scope: str
    created_at: float

    def is_expired(self) -> bool:
        return time.time() - self.created_at > ACCESS_TOKEN_TTL_SECONDS


@dataclass
class Settings:
    issuer: str
    internal_url: str
    client_id: str
    client_secret: str
    redirect_uris: list[str]
    users_file: Path
    signing_key_file: Path | None


def _read_secret(env_value: str | None, env_file: str | None, name: str) -> str:
    if env_file:
        path = Path(env_file)
        if not path.is_file():
            sys.exit(f"mock_idp: {name}_FILE points to a missing file: {path}")
        return path.read_text(encoding="utf-8").strip()
    if env_value:
        return env_value
    sys.exit(f"mock_idp: set {name} or {name}_FILE")


def load_settings() -> Settings:
    issuer = os.environ.get("MOCK_IDP_ISSUER")
    internal_url = os.environ.get("MOCK_IDP_INTERNAL_URL")
    client_id = os.environ.get("MOCK_IDP_CLIENT_ID")
    redirect_uris_raw = os.environ.get("MOCK_IDP_REDIRECT_URIS")
    if not issuer:
        sys.exit("mock_idp: set MOCK_IDP_ISSUER (browser-facing base URL)")
    if not internal_url:
        sys.exit("mock_idp: set MOCK_IDP_INTERNAL_URL (container-facing base URL)")
    if not client_id:
        sys.exit("mock_idp: set MOCK_IDP_CLIENT_ID")
    if not redirect_uris_raw:
        sys.exit("mock_idp: set MOCK_IDP_REDIRECT_URIS (comma-separated exact URIs)")
    client_secret = _read_secret(
        os.environ.get("MOCK_IDP_CLIENT_SECRET"),
        os.environ.get("MOCK_IDP_CLIENT_SECRET_FILE"),
        "MOCK_IDP_CLIENT_SECRET",
    )
    redirect_uris = [uri.strip() for uri in redirect_uris_raw.split(",") if uri.strip()]
    users_file = Path(os.environ.get("MOCK_IDP_USERS_FILE", str(BASE_DIR / "users.yaml")))
    signing_key_file_raw = os.environ.get("MOCK_IDP_SIGNING_KEY_FILE")
    signing_key_file = Path(signing_key_file_raw) if signing_key_file_raw else None
    return Settings(
        issuer=issuer.rstrip("/"),
        internal_url=internal_url.rstrip("/"),
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=redirect_uris,
        users_file=users_file,
        signing_key_file=signing_key_file,
    )


def load_users(path: Path) -> dict[str, DemoUser]:
    if not path.is_file():
        sys.exit(f"mock_idp: users file not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    users: dict[str, DemoUser] = {}
    for entry in raw.get("users", []):
        user = DemoUser(
            sub=str(entry["sub"]),
            email=str(entry["email"]),
            email_verified=bool(entry["email_verified"]),
            name=str(entry["name"]),
        )
        users[user.sub] = user
    if not users:
        sys.exit(f"mock_idp: no users defined in {path}")
    return users


def load_or_generate_signing_key(path: Path | None) -> rsa.RSAPrivateKey:
    if path is not None:
        if not path.is_file():
            sys.exit(f"mock_idp: MOCK_IDP_SIGNING_KEY_FILE points to a missing file: {path}")
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            sys.exit("mock_idp: MOCK_IDP_SIGNING_KEY_FILE must hold an RSA private key")
        return key
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8 or 1
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def key_id_for(public_key: rsa.RSAPublicKey) -> str:
    numbers = public_key.public_numbers()
    digest = hashlib.sha256(f"{numbers.n}:{numbers.e}".encode("ascii")).hexdigest()
    return digest[:16]


def jwk_for(public_key: rsa.RSAPublicKey, kid: str) -> dict[str, str]:
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def _extract_client_credentials(request: Request, form: FormData) -> tuple[str | None, str | None]:
    """Support both client_secret_basic and client_secret_post."""
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None, None
        if ":" not in decoded:
            return None, None
        client_id, _, client_secret = decoded.partition(":")
        return client_id, client_secret
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    return (
        str(client_id) if client_id is not None else None,
        str(client_secret) if client_secret is not None else None,
    )


def _redirect_error(
    redirect_uri: str, error: str, state: str | None, description: str | None = None
) -> RedirectResponse:
    query: dict[str, str] = {"error": error}
    if description:
        query["error_description"] = description
    if state:
        query["state"] = state
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(query)}", status_code=302)


def create_app() -> FastAPI:
    settings = load_settings()
    users = load_users(settings.users_file)
    private_key = load_or_generate_signing_key(settings.signing_key_file)
    public_key = private_key.public_key()
    kid = key_id_for(public_key)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    app = FastAPI(title="pgwarden mock IdP", docs_url=None, redoc_url=None)

    pending: dict[str, PendingAuthRequest] = {}
    codes: dict[str, IssuedCode] = {}
    access_tokens: dict[str, AccessTokenRecord] = {}

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/openid-configuration")
    async def discovery() -> JSONResponse:
        issuer = settings.issuer
        internal = settings.internal_url
        return JSONResponse(
            {
                "issuer": issuer,
                "authorization_endpoint": f"{issuer}/authorize",
                "token_endpoint": f"{internal}/token",
                "jwks_uri": f"{internal}/jwks",
                "userinfo_endpoint": f"{internal}/userinfo",
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "subject_types_supported": ["public"],
                "scopes_supported": ["openid", "email", "profile"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                ],
            }
        )

    @app.get("/jwks")
    async def jwks() -> JSONResponse:
        return JSONResponse({"keys": [jwk_for(public_key, kid)]})

    @app.get("/authorize")
    async def authorize_get(request: Request) -> Any:
        params = request.query_params
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        response_type = params.get("response_type")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method")
        state = params.get("state")
        nonce = params.get("nonce")
        scope = params.get("scope", "openid")

        # client_id and redirect_uri are checked before anything else: an
        # invalid redirect_uri must never be used as a redirect target.
        if client_id != settings.client_id:
            raise HTTPException(status_code=400, detail="unknown client_id")
        if redirect_uri is None or redirect_uri not in settings.redirect_uris:
            raise HTTPException(status_code=400, detail="redirect_uri is not registered")

        if response_type != "code":
            return _redirect_error(redirect_uri, "unsupported_response_type", state)
        if not code_challenge or code_challenge_method != "S256":
            return _redirect_error(redirect_uri, "invalid_request", state, "PKCE S256 is required")

        request_id = secrets.token_urlsafe(24)
        pending[request_id] = PendingAuthRequest(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            state=state,
            nonce=nonce,
            scope=scope,
            created_at=time.time(),
        )
        return TEMPLATES.TemplateResponse(
            request,
            "login.html",
            {"users": list(users.values()), "request_id": request_id},
        )

    @app.post("/authorize/login")
    async def authorize_login(
        request_id: str = Form(...), sub: str = Form(...)
    ) -> RedirectResponse:
        pending_req = pending.pop(request_id, None)
        if pending_req is None or pending_req.is_expired():
            raise HTTPException(
                status_code=400, detail="login request expired or unknown; restart login"
            )
        user = users.get(sub)
        if user is None:
            raise HTTPException(status_code=400, detail="unknown demo user")

        code = secrets.token_urlsafe(32)
        codes[code] = IssuedCode(
            sub=user.sub,
            client_id=pending_req.client_id,
            redirect_uri=pending_req.redirect_uri,
            code_challenge=pending_req.code_challenge,
            nonce=pending_req.nonce,
            scope=pending_req.scope,
            auth_time=int(time.time()),
            created_at=time.time(),
        )
        query: dict[str, str] = {"code": code}
        if pending_req.state:
            query["state"] = pending_req.state
        return RedirectResponse(
            url=f"{pending_req.redirect_uri}?{urlencode(query)}", status_code=302
        )

    @app.post("/token")
    async def token(request: Request) -> JSONResponse:
        form = await request.form()
        grant_type = form.get("grant_type")
        if grant_type != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        auth_client_id, auth_client_secret = _extract_client_credentials(request, form)
        if auth_client_id != settings.client_id or not secrets.compare_digest(
            auth_client_secret or "", settings.client_secret
        ):
            return JSONResponse({"error": "invalid_client"}, status_code=401)

        code_value = form.get("code")
        redirect_uri = form.get("redirect_uri")
        code_verifier = form.get("code_verifier")
        if not code_value or not redirect_uri or not code_verifier:
            return JSONResponse({"error": "invalid_request"}, status_code=400)

        issued = codes.get(str(code_value))
        if issued is None or issued.used or issued.is_expired():
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if issued.redirect_uri != redirect_uri or issued.client_id != auth_client_id:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        expected_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(str(code_verifier).encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        # The code is consumed on the first attempt whether or not the
        # verifier matches, so a replayed code can never succeed later.
        issued.used = True
        if not secrets.compare_digest(expected_challenge, issued.code_challenge):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        user = users[issued.sub]
        now = int(time.time())
        access_token = secrets.token_urlsafe(32)
        access_tokens[access_token] = AccessTokenRecord(
            sub=user.sub, scope=issued.scope, created_at=time.time()
        )

        id_claims: dict[str, Any] = {
            "iss": settings.issuer,
            "aud": settings.client_id,
            "sub": user.sub,
            "email": user.email,
            "email_verified": user.email_verified,
            "name": user.name,
            "iat": now,
            "exp": now + ID_TOKEN_TTL_SECONDS,
            "auth_time": issued.auth_time,
        }
        if issued.nonce:
            id_claims["nonce"] = issued.nonce

        id_token = jwt.encode(id_claims, private_pem, algorithm="RS256", headers={"kid": kid})

        return JSONResponse(
            {
                "access_token": access_token,
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
            }
        )

    @app.get("/userinfo")
    async def userinfo(authorization: str | None = Header(default=None)) -> JSONResponse:
        if not authorization or not authorization.lower().startswith("bearer "):
            return JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        token_value = authorization[len("Bearer ") :]
        record = access_tokens.get(token_value)
        if record is None or record.is_expired():
            return JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        user = users[record.sub]
        return JSONResponse(
            {
                "sub": user.sub,
                "email": user.email,
                "email_verified": user.email_verified,
                "name": user.name,
            }
        )

    return app


app = create_app()
