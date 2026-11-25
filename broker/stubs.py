"""Stand-ins for every broker module (F1). Deterministic, in memory, permissive.

Each stub has the frozen interface its real module will have (team plan section 7,
docs/identity-spec.md, docs/detection-design.md, S23 in docs/open-questions.md) and
answers ALLOW, so a normal task such as N1 passes all ten pipeline steps. Where the
real result type already exists on main it is reused, never redefined:
IdentityResult (broker/identity/verify.py), PolicyResult (broker/policy/engine.py),
TrustState (broker/trust/trust.py). ValidationResult is defined here until
broker/intercept/validate.py exists.

The pipeline picks between these and the real modules in one place
(broker.pipeline.Modules); tests replace single functions to force a failure.
No network, no model calls, no secrets.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from broker.identity.verify import IdentityResult
from broker.policy.engine import PolicyResult
from broker.trust.trust import TrustState
from contracts.catalog import get_catalog
from contracts.envelope import BROKER_FIELDS, Envelope

FACTORS = ("R", "T", "D", "E", "P", "A", "S")


# --- step 1: validate (real module: broker/intercept/validate.py, Kissa K4) ---------------

class ValidationResult(BaseModel):
    """Outcome of step 1. ``env`` is the parsed envelope with broker fields removed."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    ok: bool
    reason_code: str | None
    env: Envelope | None
    injection_cue: bool


def validate_envelope(raw: dict) -> ValidationResult:
    """Stub: structure only (the Envelope model). Forged broker fields on a request are
    removed with the note BROKER_FIELDS_STRIPPED, as the real step 1 does."""
    if not isinstance(raw, dict):
        return ValidationResult(ok=False, reason_code="MALFORMED_JSON", env=None, injection_cue=False)
    try:
        env = Envelope.model_validate(raw)
    except (ValidationError, ValueError, TypeError):
        return ValidationResult(ok=False, reason_code="BAD_ENVELOPE", env=None, injection_cue=False)
    note = None
    if env.msg_type == "request" and any(getattr(env, f) is not None for f in BROKER_FIELDS):
        env = env.model_copy(update={f: None for f in BROKER_FIELDS})
        note = "BROKER_FIELDS_STRIPPED"
    return ValidationResult(ok=True, reason_code=note, env=env, injection_cue=False)


# --- step 2: identity (real: broker/identity/verify.py) -----------------------------------

def verify_identity(headers: dict, env: Envelope) -> IdentityResult:
    """Stub: believes the envelope sender. Never reads or keeps the token."""
    role = env.sender if env.sender in get_catalog().roles else None
    return IdentityResult(ok=True, agent=env.sender, role=role, instance_id=f"{env.sender}-1",
                          epoch=0, reason_code=None)


# --- step 3: quarantine (real: broker/defence/quarantine.py, Amna A3) ---------------------

STUB_REVIEWERS = ("amna", "kissa", "afaq")   # as in PR #8's defence_settings.yaml


class DefenceManager:
    """Stub with PR #8's interface: DefenceManager(trust=None, settings=None).

    Never quarantines on its own (no V1 window); revoke(agent) blocks an agent for tests.
    is_blocked also follows the trust engine's Quarantined state, and release() needs an
    allowed reviewer, clears the block and calls TrustEngine.release, as the real one does.
    """

    def __init__(self, trust: Any = None, settings: dict | None = None) -> None:
        self.trust = trust
        self.reviewers = tuple((settings or {}).get("reviewers", STUB_REVIEWERS))
        self.decisions: list[tuple[str, str, float]] = []
        self.blocked: set[str] = set()
        self._log: list[dict] = []

    def record_decision(self, agent: str, decision: str, ts: float) -> None:
        if agent:
            self.decisions.append((agent, decision, ts))

    def is_blocked(self, agent: str) -> bool:
        if not agent:
            return False
        return agent in self.blocked or (self.trust is not None and self.trust.get(agent).state == "Quarantined")

    def release(self, agent: str, reviewer: str, ts: float | None = None) -> None:
        if reviewer not in self.reviewers:
            raise PermissionError(f"reviewer {reviewer!r} may not release agents")
        if not agent:
            raise ValueError("agent name is empty")
        if not self.is_blocked(agent):
            raise ValueError(f"{agent!r} is not quarantined")
        self.blocked.discard(agent)
        if self.trust is not None:
            self.trust.release(agent, reviewer)
        # Same entry shape as the real DefenceManager.log(): A4's audit field names.
        self._log.append({"kind": "release", "agent": agent, "by": reviewer, "ts": ts})

    def revoke(self, agent: str) -> None:
        """Test helper: block the agent as a quarantine would."""
        self.blocked.add(agent)

    def log(self) -> list[dict]:
        return [dict(e) for e in self._log]


# --- step 4: policy (real: broker/policy/engine.py) ---------------------------------------

def evaluate_policy(env: Envelope, identity: IdentityResult) -> PolicyResult:
    """Stub: ALLOW for everything, with the action's real catalog class."""
    spec = get_catalog().get(env.action)
    action_class = spec.action_class if spec else "Unknown"
    return PolicyResult(verdict="ALLOW", action_class=action_class, reason_code="POLICY_ALLOW",
                        needs_human=False)


# --- step 5 and 9: content (real: Afaq's F3) ----------------------------------------------

def check_request_content(env: Envelope) -> tuple[bool, str | None]:
    """Stub: every request is fine. (False, code) would DENY; (True, code) is a note,
    e.g. INDIVIDUAL_DATA_REQUEST (V5), passed on to the trust engine as an event."""
    return True, None


def sanitize_reply(env: Envelope) -> tuple[Envelope, list[str], bool]:
    """Stub: the reply unchanged, nothing redacted, no reply-side injection cue (S23)."""
    return env, [], False


# --- step 6: risk (real: broker/trust/risk.py) and trust (real: broker/trust/trust.py) -----

def risk_vector(action: str) -> dict:
    """Stub: every factor Low."""
    return {f: "L" for f in FACTORS}


def required_trust(action_class: str, risk: dict) -> float:
    """Stub: no trust needed (policy has already decided Prohibited and Unknown)."""
    return 0.0


class TrustEngine:
    """Stub: every agent Active with T = 1.0; calls are recorded for tests."""

    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []
        self.releases: list[tuple[str, str]] = []

    def get(self, agent: str) -> TrustState:
        return TrustState(agent=agent, T=1.0, state="Active")

    def update(self, agent: str, decision: str, risk: dict, injection_cue: bool,
               events: Iterable[str] = ()) -> TrustState:
        self.updates.append({"agent": agent, "decision": decision, "injection_cue": injection_cue,
                             "events": list(events)})
        return self.get(agent)

    def release(self, agent: str, reviewer: str) -> TrustState:
        if not reviewer or not reviewer.strip():
            raise ValueError("release needs a reviewer name")
        self.releases.append((agent, reviewer))
        return self.get(agent)


class BurstDetector:
    """Stub for V4 (real: broker/trust/rules.py): never reports a burst."""

    def observe(self, sender: str, trace_id: str) -> tuple[str, ...]:
        return ()

    def forget(self, trace_id: str) -> None:
        """Nothing is counted, so nothing to forget."""


# --- step 10: audit and signature (real: broker/audit/, Amna) -----------------------------

class AuditLog:
    """Stub: an in-memory hash chain. Entries hold metadata only, never payloads or headers."""

    def __init__(self) -> None:
        self.entries: list[dict] = []
        self._last = "0" * 64

    def append(self, entry: dict) -> str:
        body = json.dumps({"prev": self._last, "entry": entry}, sort_keys=True, separators=(",", ":"),
                          default=str)
        self._last = hashlib.sha256(body.encode("utf-8")).hexdigest()
        self.entries.append({**entry, "entry_hash": self._last})
        return self._last


_default_audit = AuditLog()


def append(entry: dict) -> str:
    """Frozen interface: append one audit entry, return its entry_hash."""
    return _default_audit.append(entry)


def sign_decision(env: Envelope) -> str:
    """SIGNATURE STUB: a hash of the envelope, not a signature. Format and key are open."""
    body = env.model_dump(mode="json", exclude={"broker_signature"})
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return "STUB-SIG-" + digest.hexdigest()[:32]
