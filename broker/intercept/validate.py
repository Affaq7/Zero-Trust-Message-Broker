"""validate_envelope(): pipeline step 1, clean and check every incoming request.

Runs before identity and policy, so a forged field can never reach a decision
(docs/identity-spec.md section 8, step 1). Order: JSON object, payload size,
schema version, strip agent-set broker fields, envelope structure, request
only, envelope rules, age (broker clock), payload schema, duplicate msg_id.
Injection cues in free-text fields are flagged for the trust engine (Amna's
rule V3) and never block. Replies are checked in step 9 (Afaq's F3), not here.
No network or model calls; the msg_id cache is in memory.
"""

import json
import re
import threading
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from broker.identity.replay import ReplayCache
from contracts.envelope import BROKER_FIELDS, Envelope, rule_violations
from contracts.payloads import UnknownActionError, validate_payload
from contracts.version import SCHEMA_VERSION

MAX_PAYLOAD_BYTES = 64 * 1024          # compact JSON, UTF-8
MAX_AGE_SECONDS = 60
MAX_FUTURE_SECONDS = 5                 # clock leeway, same as identity
DUPLICATE_WINDOW_SECONDS = 120         # longer than MAX_AGE, so a replay is stale or a duplicate

# Free-text payload fields (docs/detection-design.md, rule V3).
CUE_FIELDS = ("justification", "query", "request", "suggested_action", "subject", "body")

# Phrases that try to steer an agent or the broker. Matched on lowercased text
# with whitespace collapsed. A hit only lowers trust; it never denies.
CUE_PATTERNS = tuple(re.compile(p) for p in (
    r"\b(?:ignore|disregard|forget)\s+(?:(?:all|the|any)\s+)*(?:previous|prior|above|earlier|your)\s+instructions\b",
    r"\bskip\s+(?:(?:all|the|any)\s+)*approvals?\b",
    r"\bbypass\s+(?:the\s+)?(?:approval|approvals|policy|security|checks?|broker)\b",
    r"\bsend\s+to\b",
    r"\b(?:send|forward|email)\s+(?:\w+\s+){0,2}to\s+\S+@",
    r"\byou\s+are\s+now\b",
    r"\bsystem\s+prompt\b",
))


class ValidationResult(BaseModel):
    """Outcome of step 1. ``env`` is the cleaned envelope when ``ok``."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    reason_code: str | None
    env: Envelope | None
    injection_cue: bool


class _Reject(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _fail(reason_code: str) -> ValidationResult:
    return ValidationResult(ok=False, reason_code=reason_code, env=None, injection_cue=False)


def _payload_size(payload: Any) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _strip_broker_fields(raw: dict) -> tuple[dict, bool]:
    """A copy without the four broker fields, and whether any of them was set."""
    forged = any(raw.get(field) is not None for field in BROKER_FIELDS)
    return {k: v for k, v in raw.items() if k not in BROKER_FIELDS}, forged


def has_injection_cue(payload: dict[str, Any]) -> bool:
    """True if a free-text field contains a steering phrase."""
    for field in CUE_FIELDS:
        value = payload.get(field)
        if isinstance(value, str):
            text = " ".join(value.lower().split())
            if any(p.search(text) for p in CUE_PATTERNS):
                return True
    return False


class EnvelopeValidator:
    """Step 1 with its own msg_id cache."""

    def __init__(self) -> None:
        self.seen_ids = ReplayCache(window=DUPLICATE_WINDOW_SECONDS)

    def validate_body(self, body: bytes, now: float | None = None) -> ValidationResult:
        """Parse an HTTP body as UTF-8 JSON, then validate it."""
        try:
            raw = json.loads(body.decode("utf-8"))
        except ValueError:                       # bad UTF-8 or bad JSON
            return _fail("MALFORMED_JSON")
        return self.validate(raw, now=now)

    def validate(self, raw: Any, now: float | None = None) -> ValidationResult:
        """Run the step-1 checks on one parsed message. Never changes ``raw``."""
        now = time.time() if now is None else now
        try:
            env, stripped = self._checked(raw, now)
        except _Reject as reject:
            return _fail(reject.reason_code)
        return ValidationResult(ok=True, reason_code="BROKER_FIELDS_STRIPPED" if stripped else None,
                                env=env, injection_cue=has_injection_cue(env.payload))

    def _checked(self, raw: Any, now: float) -> tuple[Envelope, bool]:
        if not isinstance(raw, dict):
            raise _Reject("MALFORMED_JSON")
        if _payload_size(raw.get("payload")) > MAX_PAYLOAD_BYTES:
            raise _Reject("PAYLOAD_TOO_LARGE")
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise _Reject("BAD_SCHEMA_VERSION")
        cleaned, stripped = _strip_broker_fields(raw)
        try:
            env = Envelope.model_validate(cleaned)
        except ValidationError:
            raise _Reject("BAD_ENVELOPE") from None
        if env.msg_type != "request":
            raise _Reject("BAD_ENVELOPE")
        if rule_violations(env):
            raise _Reject("RULE_VIOLATION")
        age = now - env.timestamp.timestamp()
        if age > MAX_AGE_SECONDS or age < -MAX_FUTURE_SECONDS:
            raise _Reject("STALE_MESSAGE")
        self._check_payload(env)
        if self.seen_ids.seen_or_record(env.msg_id, now=int(now)):
            raise _Reject("DUPLICATE_MSG")
        return env, stripped

    @staticmethod
    def _check_payload(env: Envelope) -> None:
        """The payload must fit its action's schema; an unknown action is left to policy."""
        try:
            validate_payload(env.action, env.payload)
        except UnknownActionError:
            return
        except ValidationError:
            raise _Reject("BAD_PAYLOAD") from None


# --- the broker's shared validator ---------------------------------------------------------

_default: EnvelopeValidator | None = None
_default_lock = threading.Lock()


def default_validator() -> EnvelopeValidator:
    """The broker's validator, with one msg_id cache for all messages."""
    global _default
    with _default_lock:
        if _default is None:
            _default = EnvelopeValidator()
        return _default


def validate_envelope(raw: dict) -> ValidationResult:
    """Pipeline step 1 for a parsed message, with the broker's shared msg_id cache."""
    return default_validator().validate(raw)


def validate_body(body: bytes) -> ValidationResult:
    """Pipeline step 1 for a raw HTTP body (MALFORMED_JSON if it is not JSON)."""
    return default_validator().validate_body(body)
