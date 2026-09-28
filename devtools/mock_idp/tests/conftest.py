"""Shared fixtures for the mock IdP test suite.

Sets the environment the app needs *before* it is imported, since app.py
validates its configuration (including the MOCK_IDP_DEV_ONLY guard) at
import time.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

APP_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_DIR))

CLIENT_ID = "pgwarden-gateway"
CLIENT_SECRET = "test-only-client-secret"
REDIRECT_URI = "http://localhost:8080/oauth/upstream/callback"
ISSUER = "http://localhost:9400"
INTERNAL_URL = "http://mock-idp:9400"

os.environ.setdefault("MOCK_IDP_DEV_ONLY", "1")
os.environ.setdefault("MOCK_IDP_ISSUER", ISSUER)
os.environ.setdefault("MOCK_IDP_INTERNAL_URL", INTERNAL_URL)
os.environ.setdefault("MOCK_IDP_CLIENT_ID", CLIENT_ID)
os.environ.setdefault("MOCK_IDP_CLIENT_SECRET", CLIENT_SECRET)
os.environ.setdefault("MOCK_IDP_REDIRECT_URIS", REDIRECT_URI)

from app import app as fastapi_app  # noqa: E402  (import after env setup)


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=fastapi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
