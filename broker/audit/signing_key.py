"""The broker's Ed25519 signing key (task A4, Amna; reused by A5).

One key signs every audit line (A4) and, later, every broker decision (A5).
The private key lives in keys/broker_signing.key and the public key in
keys/broker_signing.pub (a JWK). keys/ is gitignored: never commit either file,
and never print or log the private key.

Create the pair once, from the repo root:
    python -m broker.audit.signing_key create
It refuses to overwrite an existing key.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from broker.identity.keys import (
    private_key_from_text, private_key_to_text, public_jwk, public_key_from_jwk,
)

KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "broker_signing.key"
PUBLIC_KEY_PATH = KEYS_DIR / "broker_signing.pub"


def create_key(private_path: Path = PRIVATE_KEY_PATH,
               public_path: Path = PUBLIC_KEY_PATH) -> Ed25519PublicKey:
    """Make a new key pair and write both files. Raises FileExistsError if either exists."""
    for p in (private_path, public_path):
        if p.exists():
            raise FileExistsError(f"{p.name} already exists; not overwriting a signing key")
    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(private_key_to_text(key) + "\n")
    public_path.write_text(json.dumps(public_jwk(key.public_key())) + "\n", encoding="utf-8")
    return key.public_key()


def load_private_key(path: Path = PRIVATE_KEY_PATH) -> Ed25519PrivateKey:
    return private_key_from_text(path.read_text(encoding="utf-8").strip())


def load_public_key(path: Path = PUBLIC_KEY_PATH) -> Ed25519PublicKey:
    return public_key_from_jwk(json.loads(path.read_text(encoding="utf-8")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create the broker signing key pair in keys/.")
    parser.add_argument("command", choices=["create"])
    args = parser.parse_args(argv)
    if args.command == "create":
        try:
            create_key()
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"created keys/{PRIVATE_KEY_PATH.name} and keys/{PUBLIC_KEY_PATH.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
