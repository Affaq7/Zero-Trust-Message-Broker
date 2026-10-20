"""Print a STUB JWT for manual tests. Direct mode never checks it.

STUB: real credentials come from a teammate's issuing script. This token is
signed with a throwaway Ed25519 key that exists only in memory and is
discarded when the script exits, so nobody can ever verify it. Nothing is
written to disk.

Usage (from the repo root):
  & ".\\.venv\\Scripts\\python.exe" "scripts\\print_stub_token.py" [--sub planner] [--role planner] [--aud dummy]
"""

import argparse
import base64
import hashlib
import json
import sys
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from contracts.tokens import TokenClaims

ISSUER = "zt-local-stub-issuer"
LIFETIME_SECONDS = 300


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    """RFC 7638 SHA-256 thumbprint of an Ed25519 public key (for cnf.jkt)."""
    x = _b64url(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x},
                           separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def make_stub_token(sub: str, role: str, aud: str, now: int | None = None) -> str:
    key = Ed25519PrivateKey.generate()  # throwaway, never saved
    now = int(time.time()) if now is None else now
    claims = TokenClaims(
        sub=sub, role=role, iss=ISSUER, aud=aud,
        iat=now, nbf=now, exp=now + LIFETIME_SECONDS,
        jti=str(uuid.uuid4()), cnf={"jkt": jwk_thumbprint(key.public_key())},
    )
    return jwt.encode(claims.model_dump(), key, algorithm="EdDSA", headers={"typ": "JWT"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print a STUB JWT (unverifiable).")
    parser.add_argument("--sub", default="planner", help="must equal the envelope sender")
    parser.add_argument("--role", default="planner")
    parser.add_argument("--aud", default="dummy", help="receiver agent in direct mode")
    args = parser.parse_args(argv)
    try:
        print(make_stub_token(args.sub, args.role, args.aud))
    except ValidationError as exc:
        print(f"invalid claims: {exc.errors(include_url=False)[0]['msg']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
