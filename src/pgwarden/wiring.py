"""Build the running gateway from configuration and environment secrets.

Used by ``pgwarden serve``. The server reads only its own secrets (each also as
``<NAME>_FILE``): ``PGWARDEN_STATE_DSN``, ``PGWARDEN_ROLE_SECRET``,
``PGWARDEN_SIGNING_KEY``, ``PGWARDEN_SESSION_SECRET``,
``PGWARDEN_OIDC_CLIENT_SECRET`` and optionally ``PGWARDEN_SLACK_WEBHOOK_URL`` and
``PGWARDEN_SMTP_URL``. It refuses to start if ``PGWARDEN_ADMIN_DSN`` (or its
``_FILE`` variant) is present at all: the provisioning credential must never be
held by the running server.
"""

from __future__ import annotations

import datetime as dt
import os

from fastapi import FastAPI

from pgwarden.app import Authenticator, create_app
from pgwarden.approvals.notifiers import LogNotifier, Notifier, SlackNotifier, SmtpNotifier
from pgwarden.approvals.service import ApprovalService
from pgwarden.config import Config, load_config
from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig
from pgwarden.mcp_server import GatewayDeps
from pgwarden.oauth.authorize import WebAuth, build_authorize_router
from pgwarden.oauth.keys import load_signing_key
from pgwarden.oauth.server import OAuthService, build_oauth_router, canonical_resource
from pgwarden.oauth.upstream import UpstreamProvider
from pgwarden.secrets import read_secret


class WiringError(RuntimeError):
    """The environment is not a valid gateway configuration."""


FORBIDDEN_SERVER_ENV = ("PGWARDEN_ADMIN_DSN", "PGWARDEN_ADMIN_DSN_FILE")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(tz=dt.UTC)


def _require(name: str) -> str:
    value = read_secret(name)
    if not value:
        raise WiringError(f"{name} (or {name}_FILE) is required")
    return value


def build_notifiers(config: Config) -> list[Notifier]:
    notifiers: list[Notifier] = []
    for channel in config.notifications.channels:
        if channel == "log":
            notifiers.append(LogNotifier())
        elif channel == "slack":
            notifiers.append(SlackNotifier(_require("PGWARDEN_SLACK_WEBHOOK_URL")))
        elif channel == "smtp":
            recipients = list(config.notifications.smtp_to) or [
                ref.email for ref in config.approvers if ref.email
            ]
            sender = config.notifications.smtp_from or "pgwarden@localhost"
            notifiers.append(
                SmtpNotifier(_require("PGWARDEN_SMTP_URL"), sender=sender, recipients=recipients)
            )
    return notifiers


def build_app() -> FastAPI:
    """Build the gateway from ``os.environ`` (secrets also via ``*_FILE``)."""
    environ = os.environ
    present = [name for name in FORBIDDEN_SERVER_ENV if name in environ]
    if present:
        raise WiringError(
            f"{', '.join(present)} must not be set for `pgwarden serve`: the running server never "
            "holds the admin credential (provisioning commands use it; the server does not)"
        )
    config_path = environ.get("PGWARDEN_CONFIG")
    if not config_path:
        raise WiringError("PGWARDEN_CONFIG is required")
    target_dsn = environ.get("PGWARDEN_TARGET_DSN")
    if not target_dsn:
        raise WiringError("PGWARDEN_TARGET_DSN is required")
    config = load_config(config_path)

    signing = load_signing_key(_require("PGWARDEN_SIGNING_KEY"))
    session_secret = _require("PGWARDEN_SESSION_SECRET")
    deps = GatewayDeps(
        config=config,
        pool_manager=PoolManager(
            target_dsn=target_dsn,
            role_secret=_require("PGWARDEN_ROLE_SECRET"),
            max_size=config.pool.max_size,
            idle_timeout_s=config.pool.idle_timeout_s,
            max_lifetime_s=config.pool.max_lifetime_s,
            global_cap=config.pool.global_cap,
        ),
        state_dsn=_require("PGWARDEN_STATE_DSN"),
        read_config=ReadConfig(**config.read.model_dump()),
        now=_utcnow,
    )
    deps.approvals = ApprovalService(
        gateway=deps, session_secret=session_secret, notifiers=build_notifiers(config)
    )
    oauth = OAuthService(gateway=deps, signing_key=signing)
    public_url = config.public_url.rstrip("/")
    upstream = UpstreamProvider(
        config.upstream,
        client_secret=_require("PGWARDEN_OIDC_CLIENT_SECRET"),
        redirect_uri=f"{public_url}/oauth/callback",
    )
    web = WebAuth(gateway=deps, oauth=oauth, upstream=upstream, session_secret=session_secret)
    authenticator = Authenticator(
        config=config,
        signing_key=signing,
        issuer=public_url,
        audience=canonical_resource(public_url),
        now=_utcnow,
    )
    routers = [build_oauth_router(oauth), build_authorize_router(web)]
    return create_app(
        deps,
        authenticator,
        server_timing=environ.get("PGWARDEN_SERVER_TIMING") == "1",
        routers=routers,
    )


__all__ = ["FORBIDDEN_SERVER_ENV", "WiringError", "build_app", "build_notifiers"]
