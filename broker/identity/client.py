"""Sender side of the per-message proof (docs/identity-spec.md section 3).

make_proof() builds the X-Agent-Proof JWT; Afaq calls it from wrapper/send.py.
envelope_hash() and token_hash() are shared with the verifier, so both sides
hash exactly the same bytes.
"""

import hashlib
import json
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity.keys import b64url
from contracts.envelope import BROKER_FIELDS, Envelope
from contracts.tokens import BROKER_AUDIENCE

PROOF_TYP = "ztb-proof+jwt"


def _b64_sha256(data: bytes) -> str:
    return b64url(hashlib.sha256(data).digest())


def envelope_hash(env: Envelope) -> str:
    """SHA-256 of the canonical envelope JSON, broker fields left out (msg_hash)."""
    body = env.model_dump(mode="json", exclude=set(BROKER_FIELDS))
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _b64_sha256(raw.encode("utf-8"))


def token_hash(token: str) -> str:
    """SHA-256 of the token's ASCII bytes (ath): binds the proof to one token."""
    return _b64_sha256(token.encode("ascii"))


def make_proof(env: Envelope, token: str, private_key: Ed25519PrivateKey,
               now: int | None = None) -> str:
    """The X-Agent-Proof JWT for sending ``env`` with ``token``.

    ``private_key`` must be the key named by the token's cnf.jkt.
    """
    claims = {
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()) if now is None else now,
        "aud": BROKER_AUDIENCE,
        "ath": token_hash(token),
        "msg_hash": envelope_hash(env),
        "trace_id": env.trace_id,
    }
    return jwt.encode(claims, private_key, algorithm="EdDSA", headers={"typ": PROOF_TYP})
