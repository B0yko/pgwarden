"""Client ID Metadata Documents: a ``client_id`` that is an https URL, whose
metadata this authorization server fetches.

Fetching a client-supplied URL from the server is an SSRF risk, so the fetch is
deliberately narrow: https only; the host is resolved first and every resolved
address must be globally routable (private, loopback, link-local, CGNAT,
reserved, multicast and documentation ranges are refused, including
IPv4-mapped IPv6); the connection then goes to the checked IP (so a second DNS
answer cannot swap in an internal address) with the original host kept for SNI
and certificate verification; no redirects; a 5 s timeout and a 64 KiB cap.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from pgwarden.oauth.redirects import RedirectUriError, validate_redirect_uri

Resolver = Callable[[str, int], Awaitable[list[str]]]

DEFAULT_TIMEOUT_S = 5.0
DEFAULT_MAX_BYTES = 64 * 1024


class CimdError(ValueError):
    """The client_id URL could not be fetched or its document is not acceptable."""


def looks_like_cimd_client_id(client_id: str) -> bool:
    parts = urlsplit(client_id)
    return parts.scheme == "https" and bool(parts.hostname) and parts.path not in ("", "/")


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def is_public_address(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


async def fetch_client_metadata(
    client_id: str,
    *,
    resolver: Resolver = system_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    """Fetch and validate the metadata document at ``client_id``."""
    if not looks_like_cimd_client_id(client_id):
        raise CimdError("client_id is not an https URL with a path")
    parts = urlsplit(client_id)
    host = parts.hostname or ""
    port = parts.port or 443

    try:
        addresses = await asyncio.wait_for(resolver(host, port), timeout=timeout_s)
    except (TimeoutError, OSError) as exc:
        raise CimdError(f"could not resolve {host}: {exc}") from exc
    if not addresses:
        raise CimdError(f"{host} did not resolve")
    for ip in addresses:
        if not is_public_address(ip):
            raise CimdError(f"{host} resolves to a non-public address; refusing to fetch")

    ip = addresses[0]
    ip_netloc = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    pinned_url = urlunsplit(("https", ip_netloc, parts.path, parts.query, ""))
    host_header = host if port == 443 else f"{host}:{port}"

    async def _get() -> bytes:
        async with (
            httpx.AsyncClient(
                transport=transport, timeout=timeout_s, follow_redirects=False
            ) as client,
            client.stream(
                "GET",
                pinned_url,
                headers={"Host": host_header, "Accept": "application/json"},
                extensions={"sni_hostname": host},
            ) as response,
        ):
            if response.status_code != 200:
                raise CimdError(f"metadata fetch returned HTTP {response.status_code}")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    raise CimdError(f"metadata document exceeds {max_bytes} bytes")
            return bytes(body)

    try:
        raw = await asyncio.wait_for(_get(), timeout=timeout_s)
    except TimeoutError as exc:
        raise CimdError("metadata fetch timed out") from exc
    except httpx.HTTPError as exc:
        raise CimdError(f"metadata fetch failed: {exc}") from exc

    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise CimdError("metadata document is not JSON") from exc
    return validate_metadata_document(client_id, doc)


def validate_metadata_document(client_id: str, doc: object) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise CimdError("metadata document must be a JSON object")
    if doc.get("client_id") != client_id:
        raise CimdError("metadata client_id does not equal the URL it was fetched from")
    name = doc.get("client_name")
    if not isinstance(name, str) or not name.strip():
        raise CimdError("metadata document needs a client_name")
    uris = doc.get("redirect_uris")
    if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
        raise CimdError("metadata document needs a non-empty redirect_uris list")
    for uri in uris:
        try:
            validate_redirect_uri(uri)
        except RedirectUriError as exc:
            raise CimdError(str(exc)) from exc
    method = doc.get("token_endpoint_auth_method", "none")
    if method != "none":
        raise CimdError(
            "metadata-document clients must be public (token_endpoint_auth_method none)"
        )
    return doc


__all__ = [
    "CimdError",
    "Resolver",
    "fetch_client_metadata",
    "is_public_address",
    "looks_like_cimd_client_id",
    "system_resolver",
    "validate_metadata_document",
]
