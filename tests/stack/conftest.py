"""Fixtures for tests that run against a live `docker compose` stack (marker `stack`).

Ports come from .env (or PGWARDEN_STACK_ENV_FILE), secrets from ./.pgwarden-dev/.
Without a reachable stack these tests skip, unless PGWARDEN_REQUIRE_STACK=1 (CI),
which turns the skip into a failure.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from helpers.stack import Stack, _dotenv

REPO_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture(scope="session")
def stack() -> Stack:
    env_file = Path(os.environ.get("PGWARDEN_STACK_ENV_FILE", REPO_ROOT / ".env"))
    env = {**_dotenv(env_file), **{k: v for k, v in os.environ.items() if k.endswith("_PORT")}}
    st = Stack(
        base_url=f"http://localhost:{env.get('GATEWAY_PORT', '8080')}",
        idp_url=f"http://localhost:{env.get('IDP_PORT', '9400')}",
        mailpit_url=f"http://localhost:{env.get('MAILPIT_WEB_PORT', '8025')}",
        secrets_dir=Path(os.environ.get("PGWARDEN_STACK_SECRETS", REPO_ROOT / ".pgwarden-dev")),
        project=env.get("COMPOSE_PROJECT_NAME", "pgwarden"),
    )
    try:
        ok = httpx.get(f"{st.base_url}/readyz", timeout=3).status_code == 200
    except httpx.HTTPError:
        ok = False
    if not ok:
        if os.environ.get("PGWARDEN_REQUIRE_STACK") == "1":
            pytest.fail(f"the compose stack is not ready at {st.base_url}")
        pytest.skip(f"no compose stack at {st.base_url}; run docker compose up -d --wait")
    return st
