"""Agent credentials: issued files from keys/, or the old STUB.

Issued credentials (K1, docs/identity-spec.md): when the operator sets
AGENT_CREDENTIALS=<name>, the process loads keys/<name>.json written by
scripts/issue_credentials.py and sends that file's token to every receiver
(aud = ztbroker). AGENT_KEYS_DIR overrides the keys/ folder.

STUB (when AGENT_CREDENTIALS is not set): each wrapper process generates one
throwaway Ed25519 key in memory (never saved) and signs tokens with it. aud is
the receiver in direct mode (Q6), so one token is minted per receiver and
cached until shortly before it expires. Direct mode never checks tokens.
"""

import base64
import hashlib
import json
import os
import re
import threading
import time
import uuid
from collections.abc import Mapping
from pathlib import Path

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


def make_expired_token(sub: str, role: str, aud: str,
                       key: Ed25519PrivateKey | None = None) -> str:
    """A structurally valid JWT that expired 600 s ago."""
    past = int(time.time()) - 900
    return make_stub_token(sub, role, aud, now=past, key=key)


def make_wrong_key_token(sub: str, role: str, aud: str) -> str:
    """A JWT signed with a throwaway key that no agent recognises."""
    return make_stub_token(sub, role, aud, key=Ed25519PrivateKey.generate())


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


# --- issued credentials (K1, Kissa) ---------------------------------------------

KEYS_DIR = Path(__file__).resolve().parents[1] / "keys"
CREDENTIALS_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class CredentialsError(RuntimeError):
    """The credential file is missing, unreadable or belongs to another agent."""


class FileCredentials:
    """One agent instance's issued key and token (keys/<name>.json)."""

    def __init__(self, path: Path):
        # Imported here so the stub path never needs the broker package.
        from broker.identity.keys import private_key_from_text

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.sub: str = data["agent"]
            self.role: str = data["role"]
            self.instance_id: str = data["instance_id"]
            self.token: str = data["token"]
            self._key = private_key_from_text(data["private_key"])
        except FileNotFoundError:
            raise CredentialsError(f"{path.name} not found; run scripts/issue_credentials.py") from None
        except (OSError, ValueError, KeyError, TypeError):
            raise CredentialsError(f"{path.name} is unreadable; issue it again") from None

    @property
    def private_key(self) -> Ed25519PrivateKey:
        """The key the per-message proof is signed with (K2 make_proof)."""
        return self._key

    @property
    def jkt(self) -> str:
        return jwk_thumbprint(self._key.public_key())

    def token_for(self, receiver: str, now: int | None = None) -> str:
        """The issued token; the same for every receiver (aud = ztbroker)."""
        return self.token


def load_credentials(agent_name: str, role: str,
                     environ: Mapping[str, str] = os.environ) -> StubCredentials | FileCredentials:
    """Issued credentials if AGENT_CREDENTIALS is set, else the stub."""
    name = environ.get("AGENT_CREDENTIALS", "").strip()
    if not name:
        return StubCredentials(agent_name, role)
    if not CREDENTIALS_NAME.match(name):
        raise CredentialsError(f"invalid AGENT_CREDENTIALS {name!r}")
    keys_dir = Path(environ.get("AGENT_KEYS_DIR", "").strip() or KEYS_DIR)
    creds = FileCredentials(keys_dir / f"{name}.json")
    if creds.sub != agent_name:
        raise CredentialsError(f"{name}.json belongs to {creds.sub!r}, not {agent_name!r}")
    if creds.role != role:
        raise CredentialsError(f"{name}.json has role {creds.role!r}, not {role!r}")
    return creds
