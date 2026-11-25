"""verify_identity(): pipeline step 2, is the sender who it claims to be?

Grown from the identity proof of concept (final report, Appendix A) and
following docs/identity-spec.md section 7: token checks, then the per-message
proof, then the registry state. The first failing check gives one reason code.
The algorithm is never read from a token to decide how to verify it (report
section 6.2): only EdDSA is accepted, and the key always comes from the registry.
Each JWT is parsed once and its Ed25519 signature checked directly with the
cryptography library (PyJWT re-parsed every token on each call, which tripled
the cost). No network or model calls; all state is in memory.
"""

import hmac
import json
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, ValidationError

from broker.identity.keys import b64url_decode

from broker.identity.client import PROOF_TYP, envelope_hash, token_hash
from broker.identity.registry import AgentRecord, AgentRegistry, Instance
from broker.identity.replay import ReplayCache
from broker.identity.tokens import TOKEN_LIFETIME_SECONDS, IdentityClaims
from contracts.envelope import Envelope
from contracts.tokens import (
    BROKER_AUDIENCE,
    BROKER_ISSUER,
    PROOF_HEADER,
    PROOF_STUB_VALUE,
    sub_matches_sender,
)

CLOCK_LEEWAY_SECONDS = 5
PROOF_MAX_AGE_SECONDS = 30
ALGORITHM = "EdDSA"
PROOF_CLAIMS = frozenset({"jti", "iat", "aud", "ath", "msg_hash", "trace_id"})
DEFAULT_KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"

IDENTITY_REASON_CODES = (
    "TOKEN_MISSING", "TOKEN_MALFORMED", "BAD_ALGORITHM", "UNKNOWN_AGENT", "BAD_SIGNATURE",
    "WRONG_ISSUER", "WRONG_AUDIENCE", "TOKEN_EXPIRED", "TOKEN_NOT_YET_VALID", "SUB_MISMATCH",
    "ROLE_MISMATCH", "PROOF_MISSING", "PROOF_MALFORMED", "PROOF_KEY_MISMATCH", "PROOF_STALE",
    "PROOF_TOKEN_MISMATCH", "MSG_HASH_MISMATCH", "PROOF_REPLAY", "AGENT_REVOKED",
    "AGENT_SUSPENDED", "STALE_EPOCH",
)


class IdentityResult(BaseModel):
    """Outcome of step 2. On failure every identity field is None (nothing unverified leaks)."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    agent: str | None
    role: str | None
    instance_id: str | None
    epoch: int | None
    reason_code: str | None


class _Reject(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _fail(reason_code: str) -> IdentityResult:
    return IdentityResult(ok=False, agent=None, role=None, instance_id=None, epoch=None,
                          reason_code=reason_code)


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _bearer(value: object) -> str:
    parts = value.split() if isinstance(value, str) else []
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise _Reject("TOKEN_MISSING")
    return parts[1]


@dataclass(frozen=True)
class _Compact:
    """A compact JWS split once: header and payload JSON, signing input, signature."""

    header: dict
    payload: dict
    signing_input: bytes
    signature: bytes

    def signed_by(self, key: Ed25519PublicKey) -> bool:
        try:
            key.verify(self.signature, self.signing_input)
            return True
        except InvalidSignature:
            return False


def _parse(compact: str, malformed: str) -> _Compact:
    """Split and decode a compact JWT; anything that is not one is ``malformed``."""
    parts = compact.split(".")
    if len(parts) != 3:
        raise _Reject(malformed)
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except ValueError:                  # bad base64url, bad UTF-8 or bad JSON
        raise _Reject(malformed) from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise _Reject(malformed)
    return _Compact(header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), signature)


class IdentityVerifier:
    """Checks a token and its per-message proof against one registry and replay cache."""

    def __init__(self, registry: AgentRegistry, replay: ReplayCache | None = None) -> None:
        self.registry = registry
        self.replay = replay or ReplayCache()

    def verify(self, headers: Mapping[str, str], env: Envelope, now: int | None = None) -> IdentityResult:
        """Run checks 1 to 23 of docs/identity-spec.md section 7."""
        now = int(time.time()) if now is None else now
        lowered = {str(k).lower(): v for k, v in headers.items()}
        try:
            token = _bearer(lowered.get("authorization"))
            instance, claims = self._check_token(token, env, now)
            self._check_proof(lowered.get(PROOF_HEADER.lower()), token, instance, env, now)
            record = self._check_state(claims)
        except _Reject as reject:
            return _fail(reject.reason_code)
        return IdentityResult(ok=True, agent=record.agent_uri, role=record.role,
                              instance_id=instance.instance_id, epoch=record.epoch, reason_code=None)

    # --- checks 2 to 12: the token ---------------------------------------------------------

    def _check_token(self, token: str, env: Envelope, now: int) -> tuple[Instance, IdentityClaims]:
        parsed = _parse(token, "TOKEN_MALFORMED")
        if parsed.header.get("alg") != ALGORITHM:
            raise _Reject("BAD_ALGORITHM")
        record, instance = self._signing_instance(parsed)
        if not parsed.signed_by(instance.public_key):
            raise _Reject("BAD_SIGNATURE")
        try:
            claims = IdentityClaims.model_validate(parsed.payload)
        except ValidationError:
            raise _Reject("TOKEN_MALFORMED") from None
        if claims.cnf.jkt != instance.jkt or claims.exp - claims.iat > TOKEN_LIFETIME_SECONDS:
            raise _Reject("TOKEN_MALFORMED")
        self._check_token_claims(claims, record, env, now)
        return instance, claims

    def _signing_instance(self, parsed: _Compact) -> tuple[AgentRecord, Instance]:
        """The registered instance named by sub and kid, still unverified (checks 4 and 5)."""
        sub = parsed.payload.get("sub")
        record = self.registry.get(sub) if isinstance(sub, str) else None
        if record is None:
            raise _Reject("UNKNOWN_AGENT")
        kid = parsed.header.get("kid")
        instance = record.instance_by_jkt(kid) if isinstance(kid, str) else None
        if instance is None:
            raise _Reject("BAD_SIGNATURE")
        return record, instance

    @staticmethod
    def _check_token_claims(claims: IdentityClaims, record: AgentRecord, env: Envelope, now: int) -> None:
        if claims.iss != BROKER_ISSUER:
            raise _Reject("WRONG_ISSUER")
        if claims.aud != BROKER_AUDIENCE:
            raise _Reject("WRONG_AUDIENCE")
        if now - CLOCK_LEEWAY_SECONDS >= claims.exp:
            raise _Reject("TOKEN_EXPIRED")
        if now + CLOCK_LEEWAY_SECONDS < max(claims.nbf, claims.iat):
            raise _Reject("TOKEN_NOT_YET_VALID")
        if not sub_matches_sender(claims, env):
            raise _Reject("SUB_MISMATCH")
        if claims.role != record.role:
            raise _Reject("ROLE_MISMATCH")

    # --- checks 13 to 20: the per-message proof ----------------------------------------------

    def _check_proof(self, proof: object, token: str, instance: Instance, env: Envelope, now: int) -> None:
        if not isinstance(proof, str) or not proof or proof == PROOF_STUB_VALUE:
            raise _Reject("PROOF_MISSING")
        parsed = _parse(proof, "PROOF_MALFORMED")
        if parsed.header.get("typ") != PROOF_TYP or parsed.header.get("alg") != ALGORITHM:
            raise _Reject("PROOF_MALFORMED")
        if not parsed.signed_by(instance.public_key):
            raise _Reject("PROOF_KEY_MISMATCH")
        claims = parsed.payload
        if not _proof_shape_ok(claims):
            raise _Reject("PROOF_MALFORMED")
        if not now - PROOF_MAX_AGE_SECONDS <= claims["iat"] <= now + CLOCK_LEEWAY_SECONDS:
            raise _Reject("PROOF_STALE")
        if claims["aud"] != BROKER_AUDIENCE:
            raise _Reject("WRONG_AUDIENCE")
        if not _same(claims["ath"], token_hash(token)):
            raise _Reject("PROOF_TOKEN_MISMATCH")
        if not _same(claims["msg_hash"], envelope_hash(env)) or claims["trace_id"] != env.trace_id:
            raise _Reject("MSG_HASH_MISMATCH")
        if self.replay.seen_or_record(claims["jti"], now=now):
            raise _Reject("PROOF_REPLAY")

    # --- checks 21 to 23: registry state ---------------------------------------------------------

    def _check_state(self, claims: IdentityClaims) -> AgentRecord:
        record = self.registry.get(claims.sub)          # fresh: status may have changed
        if record is None:
            raise _Reject("UNKNOWN_AGENT")
        if record.status == "revoked":
            raise _Reject("AGENT_REVOKED")
        if record.status == "suspended":
            raise _Reject("AGENT_SUSPENDED")
        if claims.epoch != record.epoch:
            raise _Reject("STALE_EPOCH")
        return record


def _proof_shape_ok(claims: dict) -> bool:
    """Exactly the six proof claims, iat a whole number, the rest non-empty strings."""
    if set(claims) != PROOF_CLAIMS:
        return False
    iat = claims["iat"]
    if not isinstance(iat, int) or isinstance(iat, bool):
        return False
    return all(isinstance(claims[k], str) and claims[k] for k in PROOF_CLAIMS - {"iat"})


# --- the broker's shared verifier --------------------------------------------------------------

_default: IdentityVerifier | None = None
_default_lock = threading.Lock()


def default_verifier() -> IdentityVerifier:
    """The broker's verifier, with its registry loaded once from keys/.

    Amna's revocation code changes status through ``default_verifier().registry``.
    """
    global _default
    with _default_lock:
        if _default is None:
            _default = IdentityVerifier(AgentRegistry.from_credentials_dir(DEFAULT_KEYS_DIR))
        return _default


def verify_identity(headers: dict, env: Envelope) -> IdentityResult:
    """Pipeline step 2 with the broker's shared registry and replay cache."""
    return default_verifier().verify(headers, env)
