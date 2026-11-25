"""Check the audit log (task A4, Amna).

From the repo root:
    python -m broker.audit.verify [file] [--public-key keys/broker_signing.pub]

Prints "OK: N lines verified" and exits 0, or "FAIL: line N: reason" for the
first bad line and exits 1. A line is bad when it is not JSON, its seq is not
its line number, it is not byte for byte the form the broker writes, its
prev_hash is not the previous line's entry_hash, its
entry_hash does not match its content, or its signature does not verify with
the broker's public key.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from broker.audit.log import GENESIS_HASH, _log_path, canonical, entry_hash_of
from broker.identity.keys import b64url_decode


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    lines: int                     # lines checked (all of them when ok)
    bad_line: int | None = None    # 1-based number of the first bad line
    reason: str | None = None


def _check_line(n: int, text: str, prev: str, key: Ed25519PublicKey) -> tuple[str | None, str]:
    try:
        rec = json.loads(text)
    except ValueError:
        return "not valid JSON", prev
    if not isinstance(rec, dict):
        return "not a JSON object", prev
    for f in ("seq", "prev_hash", "entry_hash", "signature"):
        if f not in rec:
            return f"missing {f}", prev
    if rec["seq"] != n:
        return f"seq is {rec['seq']!r}, expected {n} (line removed, added or moved)", prev
    if rec["prev_hash"] != prev:
        return "prev_hash does not match the previous line (chain broken)", prev
    if canonical(rec).decode("utf-8") != text:
        return "line is not in the form the broker writes (line edited)", prev
    if entry_hash_of(rec) != rec["entry_hash"]:
        return "entry_hash does not match the line's content (line edited)", prev
    try:
        key.verify(b64url_decode(rec["signature"]), str(rec["entry_hash"]).encode("ascii"))
    except (InvalidSignature, ValueError, TypeError):
        return "signature does not verify with the broker public key", prev
    return None, rec["entry_hash"]


def verify_chain(path: Path | None = None, public_key: Ed25519PublicKey | None = None) -> VerifyResult:
    """Return ok, or the first bad line and why. An empty or missing file is ok with 0 lines."""
    path = Path(path) if path is not None else _log_path()
    if public_key is None:
        from broker.audit.signing_key import load_public_key
        public_key = load_public_key()
    if not path.exists():
        return VerifyResult(ok=True, lines=0)
    prev, n = GENESIS_HASH, 0
    with open(path, encoding="utf-8", newline="") as f:
        for n, raw in enumerate(f, 1):
            text = raw[:-1] if raw.endswith("\n") else raw
            reason, prev = _check_line(n, text, prev, public_key)
            if reason:
                return VerifyResult(ok=False, lines=n, bad_line=n, reason=reason)
    return VerifyResult(ok=True, lines=n)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the broker audit log (hash chain and signatures).")
    parser.add_argument("file", nargs="?", type=Path, help="audit file (default: logs/broker_audit.jsonl)")
    parser.add_argument("--public-key", type=Path, help="public key JWK (default: keys/broker_signing.pub)")
    args = parser.parse_args(argv)
    try:
        key = None
        if args.public_key:
            from broker.audit.signing_key import load_public_key
            key = load_public_key(args.public_key)
        result = verify_chain(args.file, key)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if result.ok:
        print(f"OK: {result.lines} lines verified")
        return 0
    print(f"FAIL: line {result.bad_line}: {result.reason}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
