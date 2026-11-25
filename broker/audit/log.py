"""Signed, hash-chained audit log (task A4, Amna). Pipeline step 10.

append(entry) writes one JSON line per event to logs/broker_audit.jsonl
(LOG_DIR overrides the folder, as for the wrapper's message log; logs/ is
gitignored) and returns the line's entry_hash.

Each line holds:
- the entry's own fields (see DECISION_FIELDS and EVENT_FIELDS; anything else
  is refused, so a payload, a token or a scenario label can never be written);
- seq, the line number (1 for the first line);
- prev_hash, the entry_hash of the line before (64 zeros for the first line);
- entry_hash, the SHA-256 of the canonical JSON of everything above;
- signature, the broker's Ed25519 signature of entry_hash (base64url).

Why both: with the hash chain alone, someone who can write the file could
change a line and recompute every later hash, and the chain would still look
right. Re-signing the lines needs the broker's private key, which stays in
keys/. A known limit: cutting lines off the end of the file leaves a valid
shorter chain, so the file alone cannot show it (A-R3 report, FYP-II).

The audit log is broker-side only. Trust scores are allowed here; they must
never reach an envelope, a token or an agent's message log.

Pure Python, no network calls. The pipeline passes the broker's clock as ts;
without it the current UTC time is used. Verification: broker/audit/verify.py.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity.keys import b64url

REPO = Path(__file__).resolve().parents[2]
LOG_NAME = "broker_audit.jsonl"
GENESIS_HASH = "0" * 64

DECISIONS = ("ALLOW", "SANITIZE", "HITL", "DENY", "QUARANTINE")
EVENT_KINDS = ("quarantine", "release", "revoke", "restore")

# kind "decision": one line per message the broker decided on.
DECISION_FIELDS = (
    "kind", "ts", "trace_id", "msg_id", "parent_msg_id", "msg_type", "sender", "receiver",
    "action", "resource", "payload_hash", "identity", "trust", "risk", "compound_high",
    "decision", "reason_code", "events", "redacted_fields",
)
DECISION_REQUIRED = ("trace_id", "msg_id", "sender", "receiver", "action", "decision")

# kinds quarantine, release, revoke, restore: A3 events and who did them.
EVENT_FIELDS = ("kind", "ts", "agent", "by", "reason_code", "denials")
EVENT_REQUIRED = {
    "quarantine": ("agent", "reason_code"),
    "release": ("agent", "by"),
    "revoke": ("agent", "by"),
    "restore": ("agent", "by"),
}

CHAIN_FIELDS = ("seq", "prev_hash")


def canonical(obj: Any) -> bytes:
    """The one JSON form that is hashed: sorted keys, no spaces, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_hash(payload: dict) -> str:
    """SHA-256 of the canonical payload. The log keeps this, never the payload."""
    return sha256_hex(canonical(payload))


def entry_hash_of(record: dict) -> str:
    """Hash of a line without its entry_hash and signature."""
    body = {k: v for k, v in record.items() if k not in ("entry_hash", "signature")}
    return sha256_hex(canonical(body))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _plain(value: Any) -> Any:
    """Pydantic results (IdentityResult, TrustState) become dicts."""
    return value.model_dump(mode="json") if hasattr(value, "model_dump") else value


def build_record(entry: dict) -> dict:
    """Check the entry and fill missing optional fields with null. Raises ValueError."""
    if not isinstance(entry, dict):
        raise ValueError("an audit entry must be a dict")
    kind = entry.get("kind", "decision")
    if kind == "decision":
        allowed, required = DECISION_FIELDS, DECISION_REQUIRED
    elif kind in EVENT_KINDS:
        allowed, required = EVENT_FIELDS, EVENT_REQUIRED[kind]
    else:
        raise ValueError(f"unknown audit entry kind {kind!r}")
    extra = sorted(set(entry) - set(allowed))
    if extra:
        raise ValueError(f"fields not allowed in the audit log: {extra}")
    missing = [f for f in required if entry.get(f) in (None, "")]
    if missing:
        raise ValueError(f"missing audit fields: {missing}")
    if kind == "decision" and entry["decision"] not in DECISIONS:
        raise ValueError(f"unknown decision {entry['decision']!r}")
    record = {f: _plain(entry.get(f)) for f in allowed}
    record["kind"] = kind
    if record["ts"] is None:
        record["ts"] = _now()
    return record


def _log_path() -> Path:
    return Path(os.environ.get("LOG_DIR") or REPO / "logs") / LOG_NAME


class AuditLog:
    """One append-only audit file. Thread-safe within one process."""

    def __init__(self, path: Path, private_key: Ed25519PrivateKey):
        self.path = Path(path)
        self._key = private_key
        self._lock = threading.Lock()
        self._seq, self._prev = self._tail()

    def _tail(self) -> tuple[int, str]:
        """Continue the chain after a restart: seq and entry_hash of the last line."""
        if not self.path.exists():
            return 0, GENESIS_HASH
        last = None
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS_HASH
        try:
            rec = json.loads(last)
            return int(rec["seq"]), str(rec["entry_hash"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"cannot continue {self.path.name}: the last line is not an "
                             "audit line (run python -m broker.audit.verify)") from exc

    def append(self, entry: dict) -> str:
        record = build_record(entry)
        with self._lock:
            record["seq"] = self._seq + 1
            record["prev_hash"] = self._prev
            h = entry_hash_of(record)
            record["entry_hash"] = h
            record["signature"] = b64url(self._key.sign(h.encode("ascii")))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "ab") as f:
                f.write(canonical(record) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            self._seq, self._prev = record["seq"], h
        return h


_log: AuditLog | None = None


def configure(path: Path | None = None, private_key: Ed25519PrivateKey | None = None) -> AuditLog:
    """Choose the file and key that append() uses. The broker app calls this at
    startup; with no arguments it uses logs/broker_audit.jsonl and
    keys/broker_signing.key. Tests pass their own."""
    global _log
    if private_key is None:
        from broker.audit.signing_key import PRIVATE_KEY_PATH, load_private_key
        if not PRIVATE_KEY_PATH.exists():
            raise RuntimeError("no broker signing key: run python -m broker.audit.signing_key create")
        private_key = load_private_key()
    _log = AuditLog(path or _log_path(), private_key)
    return _log


def reset() -> None:
    """Forget the configured log (tests)."""
    global _log
    _log = None


def append(entry: dict) -> str:
    """Write one signed, chained line and return its entry_hash (interface, section 7)."""
    if _log is None:
        configure()
    return _log.append(entry)
