"""Broker token claims and token issuing (docs/identity-spec.md section 2).

IdentityClaims is contracts.tokens.TokenClaims plus the ``epoch`` claim. It
lives here so contracts/ stays frozen; open question C-ID1 proposes adding
``epoch`` to TokenClaims itself. Tokens are self-signed by the agent
instance's own Ed25519 key; the header ``kid`` equals ``cnf.jkt``.
"""

import time
import uuid
from typing import Annotated

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field

from broker.identity.keys import jwk_thumbprint
from contracts.tokens import BROKER_AUDIENCE, BROKER_ISSUER, TokenClaims

TOKEN_LIFETIME_SECONDS = 3600     # 60 minutes, so a live run never expires mid-task (Q21)
EXPIRED_TOKEN_AGE_SECONDS = 7200  # --expired: issued 2 h ago, so it expired 1 h ago (A6)


class IdentityClaims(TokenClaims):
    """Token claims the broker accepts: TokenClaims plus a required epoch."""

    epoch: Annotated[int, Field(strict=True, ge=0)]


def issue_token(private_key: Ed25519PrivateKey, *, agent: str, role: str,
                epoch: int = 0, now: int | None = None) -> str:
    """A 60-minute EdDSA token for ``agent``, bound to (and signed by) ``private_key``."""
    now = int(time.time()) if now is None else now
    jkt = jwk_thumbprint(private_key.public_key())
    claims = IdentityClaims(
        iss=BROKER_ISSUER, aud=BROKER_AUDIENCE, sub=agent, role=role,
        iat=now, nbf=now, exp=now + TOKEN_LIFETIME_SECONDS,
        jti=str(uuid.uuid4()), epoch=epoch, cnf={"jkt": jkt},
    )
    return jwt.encode(claims.model_dump(), private_key, algorithm="EdDSA",
                      headers={"typ": "JWT", "kid": jkt})


def issue_expired_token(private_key: Ed25519PrivateKey, *, agent: str, role: str,
                        epoch: int = 0, now: int | None = None) -> str:
    """Like issue_token(), but issued 2 h ago, so it expired 1 h ago (scenario A6)."""
    now = int(time.time()) if now is None else now
    return issue_token(private_key, agent=agent, role=role, epoch=epoch,
                       now=now - EXPIRED_TOKEN_AGE_SECONDS)
