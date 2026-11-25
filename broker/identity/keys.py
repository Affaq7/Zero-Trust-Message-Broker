"""Ed25519 key helpers: base64url, public JWK, RFC 7638 thumbprint, key text.

Shared by the issue script, the registry, the wrapper's credential loader and
(K2) the verifier, so every side computes cnf.jkt the same way.
"""

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ED25519_KEY_BYTES = 32


def b64url(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Inverse of b64url(); raises ValueError on bad input."""
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ValueError("not base64url") from exc


def public_jwk(public_key: Ed25519PublicKey) -> dict[str, str]:
    """The public key as an OKP JWK (RFC 8037)."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    """RFC 7638 SHA-256 thumbprint (the value of cnf.jkt and the token kid)."""
    canonical = json.dumps(public_jwk(public_key), separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def public_key_from_jwk(jwk: Mapping[str, str]) -> Ed25519PublicKey:
    """Load an Ed25519 public key from an OKP JWK; raises ValueError if it is not one."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        raise ValueError("not an Ed25519 OKP JWK")
    raw = b64url_decode(jwk["x"])
    if len(raw) != ED25519_KEY_BYTES:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_to_text(private_key: Ed25519PrivateKey) -> str:
    """Raw 32-byte private key as base64url (the credential file format)."""
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return b64url(raw)


def private_key_from_text(text: str) -> Ed25519PrivateKey:
    """Inverse of private_key_to_text(); raises ValueError on bad input."""
    raw = b64url_decode(text)
    if len(raw) != ED25519_KEY_BYTES:
        raise ValueError("Ed25519 private key must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)
