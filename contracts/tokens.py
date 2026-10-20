"""JWT claim model (contract v0.2) and the per-message PROOF STUB.

The JWT travels in ``Authorization: Bearer``, never in the envelope. EdDSA is
the only allowed algorithm. Credentials (keys and tokens) are issued by a
teammate's script; this module only describes and checks claims. Direct mode
never checks tokens at all.

Provisional details (docs/open-questions.md Q6): aud is the receiver agent in
direct mode and the broker in broker mode; cnf is {"jkt": <key thumbprint>};
iss is a local issuer name.
"""

from typing import Annotated

import jwt
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from contracts.catalog import get_catalog
from contracts.envelope import Envelope

ALLOWED_ALGORITHMS = ("EdDSA",)

NonEmptyStr = Annotated[str, Field(min_length=1, max_length=128)]
# JWT NumericDate: whole seconds since the epoch. strict rejects bool/float.
NumericDate = Annotated[int, Field(strict=True, ge=0)]
# RFC 7638 SHA-256 JWK thumbprint, base64url without padding (43 chars).
Thumbprint = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]


class Confirmation(BaseModel):
    """``cnf`` claim (RFC 7800) holding the agent key's thumbprint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    jkt: Thumbprint


class TokenClaims(BaseModel):
    # extra="forbid": trust scores and test labels must never be in a token.
    model_config = ConfigDict(extra="forbid", frozen=True)

    sub: NonEmptyStr  # must equal the envelope's sender
    role: str
    iss: NonEmptyStr
    aud: NonEmptyStr
    iat: NumericDate
    nbf: NumericDate
    exp: NumericDate
    jti: NonEmptyStr
    cnf: Confirmation

    @field_validator("role")
    @classmethod
    def _role_in_catalog(cls, value: str) -> str:
        if value not in get_catalog().roles:
            raise ValueError(f"unknown role {value!r}")
        return value

    @model_validator(mode="after")
    def _times_consistent(self) -> "TokenClaims":
        if not self.iat <= self.exp or not self.nbf < self.exp:
            raise ValueError("need iat <= exp and nbf < exp")
        return self

    def time_problems(self, now: int, leeway: int = 0) -> list[str]:
        problems = []
        if now + leeway < self.nbf:
            problems.append("token not yet valid (nbf)")
        if now - leeway >= self.exp:
            problems.append("token expired (exp)")
        return problems


def sub_matches_sender(claims: TokenClaims, env: Envelope) -> bool:
    return claims.sub == env.sender


def algorithm_allowed(token: str) -> bool:
    """True if the token's header names an allowed algorithm (EdDSA).

    Reads the header only; it does NOT verify the signature.
    """
    try:
        return jwt.get_unverified_header(token).get("alg") in ALLOWED_ALGORITHMS
    except jwt.DecodeError:
        return False


# PROOF STUB ---------------------------------------------------------------
# A per-message proof signed with the agent's private key is planned, probably
# sent as an X-Agent-Proof header outside the envelope. Its format is NOT
# defined yet and is not ours to define. Agents may send this placeholder;
# nothing verifies it. Replace the whole block when the format is agreed.
PROOF_HEADER = "X-Agent-Proof"  # PROOF STUB: provisional header name (Q6)
PROOF_STUB_VALUE = "PROOF-STUB-NOT-IMPLEMENTED"  # PROOF STUB


def make_proof_stub(env: Envelope) -> str:  # PROOF STUB
    """Placeholder proof for ``env``. Carries no data and proves nothing."""
    return PROOF_STUB_VALUE
# END PROOF STUB -----------------------------------------------------------
