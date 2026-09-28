"""The gateway's Ed25519 signing key and its public JWK.

Access tokens are signed with EdDSA (Ed25519). The signing key is an Ed25519
private key in PEM, supplied via ``PGWARDEN_SIGNING_KEY`` (or ``keys generate``).
The ``kid`` is the RFC 7638 JWK thumbprint of the public key, so it is stable
and derivable by anyone holding the public JWK.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_jwk(public_key: Ed25519PublicKey) -> dict[str, str]:
    """The public key as an OKP/Ed25519 JWK, including its ``kid`` thumbprint."""
    x = _b64url(_raw_public_bytes(public_key))
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    jwk["kid"] = jwk_thumbprint(jwk)
    jwk["use"] = "sig"
    jwk["alg"] = "EdDSA"
    return jwk


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 thumbprint over the required OKP members, in lexicographic order."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


@dataclasses.dataclass(frozen=True)
class SigningKey:
    """A loaded Ed25519 signing key and its derived ``kid``/public JWK."""

    private_key: Ed25519PrivateKey
    kid: str
    jwk: dict[str, str]

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()


def load_signing_key(pem: str | bytes) -> SigningKey:
    """Load an Ed25519 private key from PEM and derive its ``kid`` and public JWK."""
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("PGWARDEN_SIGNING_KEY must be an Ed25519 private key in PEM")
    jwk = public_jwk(key.public_key())
    return SigningKey(private_key=key, kid=jwk["kid"], jwk=jwk)


def generate_signing_key_pem() -> str:
    """A fresh Ed25519 private key as an unencrypted PKCS#8 PEM string."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


__all__ = [
    "SigningKey",
    "generate_signing_key_pem",
    "jwk_thumbprint",
    "load_signing_key",
    "public_jwk",
]
