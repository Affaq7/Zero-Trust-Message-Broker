"""STUB credentials: each agent process mints its own unverifiable tokens.

Real credentials will come from a teammate's issuing script. Until then each
wrapper process generates one throwaway Ed25519 key in memory (never saved)
and signs tokens with it. aud is the receiver in direct mode (Q6), so one
token is minted per receiver and cached until shortly before it expires.
Direct mode never checks these tokens.
"""

import base64
import hashlib
import json
import threading
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from contracts.tokens import BROKER_ISSUER, TokenClaims

ISSUER = BROKER_ISSUER          # agreed issuer value (S9); still a stub signer
LIFETIME_SECONDS = 300
REFRESH_MARGIN_SECONDS = 30


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    """RFC 7638 SHA-256 thumbprint of an Ed25519 public key (for cnf.jkt)."""
    x = _b64url(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x},
                           separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def make_stub_token(sub: str, role: str, aud: str, now: int | None = None,
                    key: Ed25519PrivateKey | None = None) -> str:
    key = key or Ed25519PrivateKey.generate()  # throwaway, never saved
    now = int(time.time()) if now is None else now
    claims = TokenClaims(
        sub=sub, role=role, iss=ISSUER, aud=aud,
        iat=now, nbf=now, exp=now + LIFETIME_SECONDS,
        jti=str(uuid.uuid4()), cnf={"jkt": jwk_thumbprint(key.public_key())},
    )
    return jwt.encode(claims.model_dump(), key, algorithm="EdDSA", headers={"typ": "JWT"})


class StubCredentials:
    """One process identity: sub = AGENT_NAME, its role, one in-memory key."""

    def __init__(self, sub: str, role: str):
        self.sub = sub
        self.role = role
        self._key = Ed25519PrivateKey.generate()
        self._cache: dict[str, tuple[str, int]] = {}
        self._lock = threading.Lock()

    @property
    def jkt(self) -> str:
        return jwk_thumbprint(self._key.public_key())

    def token_for(self, receiver: str, now: int | None = None) -> str:
        now = int(time.time()) if now is None else now
        with self._lock:
            cached = self._cache.get(receiver)
            if cached and cached[1] - REFRESH_MARGIN_SECONDS > now:
                return cached[0]
            token = make_stub_token(self.sub, self.role, receiver, now=now, key=self._key)
            self._cache[receiver] = (token, now + LIFETIME_SECONDS)
            return token
