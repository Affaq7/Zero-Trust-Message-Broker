"""The broker pipeline (F1): handle(raw, headers) -> response Envelope.

Steps, in this order:
   1 validate         ValidationResult        hard gate (DENY)
   2 identity         IdentityResult          hard gate (DENY)
   3 quarantine       DefenceManager          hard gate (QUARANTINE, AGENT_QUARANTINED)
   4 policy           PolicyResult            hard gate (DENY)
   5 request content  (ok, code)              DENY when not ok; a code with ok=True is a note/event
   6 risk and trust   risk vector, T          DENY TRUST_TOO_LOW when T < required_trust
   7 decision         ALLOW / HITL / DENY     trust may lower an answer, never raise a DENY
   8 forward          httpx POST to the receiver's /message (only on ALLOW)
   9 reply content    sanitize_reply          SANITIZE when fields were redacted
  10 audit and sign   append(), sign_decision()

A refusal is a response envelope with HTTP 200: decision, reason_code, payload
{"status": "denied"}, and it is never forwarded. needs_human puts the request on
the pending-approval list and answers HITL (the real queue is F3). Every message,
even one that cannot be parsed, gets an audit entry and an event record; neither
ever holds a payload, a header or a token.

Which implementation runs for each module is decided in one place, Modules: all
stubs by default; BROKER_REAL="identity,policy,..." switches named modules to the
real ones, imported lazily. A name whose module is not on this branch yet is
ignored and listed in /health.

Direct mode is untouched: nothing here is imported by wrapper/, agents/ or runner/.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import threading
import time
import uuid
from collections import Counter, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from pydantic import ValidationError

from broker import stubs
from contracts.catalog import get_catalog
from contracts.envelope import Envelope, new_id, utc_now
from contracts.version import SCHEMA_VERSION

log = logging.getLogger("broker")

DECISIONS = ("ALLOW", "SANITIZE", "HITL", "DENY", "QUARANTINE")
# Event codes the trust engine accepts (docs/detection-design.md section 4).
TRUST_EVENTS = ("INJECTION_CUE", "BURST_DETECTED", "INDIVIDUAL_DATA_REQUEST", "REPLY_SANITIZED")
DENIED_PAYLOAD = {"status": "denied"}
PENDING_PAYLOAD = {"status": "pending"}
DEFAULT_FORWARD_TIMEOUT_S = 60.0
MAX_EVENTS = 1000


# --- module registry ----------------------------------------------------------------------

def _real_validate(m):
    return {"validate_envelope": m.validate_envelope}


def _real_identity(m):
    return {"verify_identity": m.verify_identity}


def _real_defence(m):
    return {"defence": m.DefenceManager()}


def _real_policy(m):
    return {"evaluate_policy": m.evaluate_policy}


def _real_risk(m):
    return {"risk_vector": m.risk_vector, "required_trust": m.required_trust}


def _real_trust(m):
    return {"trust": m.TrustEngine()}


def _real_burst(m):
    return {"burst": m.BurstDetector()}


def _real_content(m):
    return {"check_request_content": m.check_request_content, "sanitize_reply": m.sanitize_reply}


def _real_audit(m):
    return {"append": m.append, "sign_decision": m.sign_decision}


# name -> (real module path, loader). Paths of modules that are not built yet are the
# planned ones; F3's content module path is a placeholder until F3 starts.
REAL_MODULES: dict[str, tuple[str, Callable[[Any], dict]]] = {
    "validate": ("broker.intercept.validate", _real_validate),
    "identity": ("broker.identity.verify", _real_identity),
    "defence": ("broker.defence.quarantine", _real_defence),
    "policy": ("broker.policy.engine", _real_policy),
    "risk": ("broker.trust.risk", _real_risk),
    "trust": ("broker.trust.trust", _real_trust),
    "burst": ("broker.trust.rules", _real_burst),
    "content": ("broker.content", _real_content),
    "audit": ("broker.audit.log", _real_audit),
}


def _module_exists(path: str) -> bool:
    try:
        return importlib.util.find_spec(path) is not None
    except ModuleNotFoundError:        # a parent package is missing
        return False


@dataclass
class Modules:
    """The one place that says which implementation each pipeline step uses."""

    validate_envelope: Callable = stubs.validate_envelope
    verify_identity: Callable = stubs.verify_identity
    defence: Any = field(default_factory=stubs.DefenceManager)
    evaluate_policy: Callable = stubs.evaluate_policy
    risk_vector: Callable = stubs.risk_vector
    required_trust: Callable = stubs.required_trust
    trust: Any = field(default_factory=stubs.TrustEngine)
    burst: Any = field(default_factory=stubs.BurstDetector)
    check_request_content: Callable = stubs.check_request_content
    sanitize_reply: Callable = stubs.sanitize_reply
    append: Callable = field(default_factory=lambda: stubs.AuditLog().append)
    sign_decision: Callable = stubs.sign_decision
    status: dict[str, str] = field(default_factory=lambda: {name: "stub" for name in REAL_MODULES})
    ignored: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "Modules":
        """All stubs, then each name in BROKER_REAL switched to its real module."""
        names = [n.strip() for n in environ.get("BROKER_REAL", "").split(",") if n.strip()]
        return cls.with_real(names)

    @classmethod
    def with_real(cls, names: list[str]) -> "Modules":
        mods = cls()
        for name in names:
            if name not in REAL_MODULES:
                mods.ignored[name] = "unknown module name"
                continue
            path, loader = REAL_MODULES[name]
            if not _module_exists(path):
                mods.ignored[name] = f"{path} does not exist on this branch yet; using the stub"
                continue
            try:
                parts = loader(importlib.import_module(path))
            except Exception as exc:  # noqa: BLE001 - a broken real module must not stop the broker
                mods.ignored[name] = f"{path} could not be loaded ({type(exc).__name__}); using the stub"
                continue
            for attr, value in parts.items():
                setattr(mods, attr, value)
            mods.status[name] = "real"
        return mods


# --- the pipeline ---------------------------------------------------------------------------

class _ForwardError(Exception):
    pass


@dataclass
class _Trace:
    """What one message did, for the audit entry and the event record (no payloads)."""

    raw_sender: str | None = None
    raw_msg_id: str | None = None
    env: Envelope | None = None
    agent: str | None = None
    step: int = 0
    decision: str | None = None
    reason_code: str | None = None
    events: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    redacted_fields: list[str] = field(default_factory=list)
    forwarded: bool = False


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _id_or(value: Any, default: str | None) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 128 else default


class Broker:
    """One broker: modules, forwarding, counters, events and pending approvals, in memory."""

    def __init__(self, modules: Modules | None = None, *, client: httpx.Client | None = None,
                 agent_urls: Mapping[str, str] | None = None, environ: Mapping[str, str] = os.environ,
                 clock: Callable[[], float] = time.time,
                 forward_timeout: float = DEFAULT_FORWARD_TIMEOUT_S) -> None:
        self.modules = modules or Modules.from_env(environ)
        self._client = client
        self._agent_urls = dict(agent_urls) if agent_urls is not None else None
        self._environ = environ
        self._clock = clock
        self._timeout = forward_timeout
        self._lock = threading.RLock()
        self.counters: Counter = Counter()
        self.events: deque = deque(maxlen=MAX_EVENTS)
        self.pending: dict[str, dict] = {}       # approval_id -> metadata (F3 adds the queue)
        self._pending_envs: dict[str, Envelope] = {}
        self._epochs: dict[str, int | None] = {}

    # --- entry point ------------------------------------------------------------------

    def handle(self, raw: Any, headers: Mapping[str, str] | None = None) -> Envelope:
        """Run the ten steps for one request. Never raises: any failure becomes a DENY."""
        r = raw if isinstance(raw, dict) else {}
        tr = _Trace(raw_sender=_id_or(r.get("sender"), None), raw_msg_id=_id_or(r.get("msg_id"), None))
        try:
            reply = self._run(raw, dict(headers or {}), tr)
        except Exception as exc:  # noqa: BLE001 - the broker must not crash on any message
            log.error("pipeline error at step %s: %s", tr.step, type(exc).__name__)
            tr.decision, tr.reason_code, tr.forwarded = "DENY", "INTERNAL_ERROR", False
            reply = self._refusal(raw, tr.env, "DENY", "INTERNAL_ERROR")
        try:
            return self._finish(reply, tr)
        except Exception as exc:  # noqa: BLE001 - audit or signing failed: still answer
            log.error("audit/sign failed: %s", type(exc).__name__)
            return self._refusal(raw, tr.env, "DENY", "INTERNAL_ERROR")

    # --- steps --------------------------------------------------------------------------

    def _run(self, raw: Any, headers: dict, tr: _Trace) -> Envelope:
        M = self.modules
        now = self._clock()

        tr.step = 1                                                     # 1 validate
        if not isinstance(raw, dict):
            return self._stop(raw, tr, "DENY", "MALFORMED_JSON")
        v = M.validate_envelope(raw)
        if not v.ok or v.env is None:
            return self._stop(raw, tr, "DENY", v.reason_code or "BAD_ENVELOPE")
        env = tr.env = v.env
        if v.reason_code:
            tr.notes.append(v.reason_code)
        if env.msg_type != "request":
            return self._stop(raw, tr, "DENY", "BAD_ENVELOPE")
        request_cue = bool(v.injection_cue)
        if request_cue:
            tr.events.append("INJECTION_CUE")

        tr.step = 2                                                     # 2 identity
        ident = M.verify_identity(headers, env)
        if not ident.ok or not ident.agent:
            return self._stop(raw, tr, "DENY", ident.reason_code or "UNKNOWN_AGENT")
        agent = tr.agent = ident.agent

        with self._lock:
            self._epochs[agent] = ident.epoch

            tr.step = 3                                                 # 3 quarantine
            if M.defence.is_blocked(agent) or M.trust.get(agent).state == "Quarantined":
                M.defence.record_decision(agent, "QUARANTINE", now)
                return self._stop(raw, tr, "QUARANTINE", "AGENT_QUARANTINED")

            for event in M.burst.observe(agent, env.trace_id):          # V4, counted per request
                if event not in tr.events:
                    tr.events.append(event)

            tr.step = 4                                                 # 4 policy
            policy = M.evaluate_policy(env, ident)
            risk = M.risk_vector(env.action)
            if policy.verdict != "ALLOW":
                return self._settle(raw, tr, "DENY", policy.reason_code, risk, request_cue, now)

            tr.step = 5                                                 # 5 request content
            content_ok, content_code = M.check_request_content(env)
            if not content_ok:
                return self._settle(raw, tr, "DENY", content_code or "CONTENT_REJECTED", risk,
                                    request_cue, now)
            if content_code:
                (tr.events if content_code in TRUST_EVENTS else tr.notes).append(content_code)

            tr.step = 6                                                 # 6 risk and trust
            needed = M.required_trust(policy.action_class, risk)
            T = M.trust.get(agent).T

            tr.step = 7                                                 # 7 decision
            if T < needed:
                return self._settle(raw, tr, "DENY", "TRUST_TOO_LOW", risk, request_cue, now)
            if policy.needs_human:
                self._settle(raw, tr, "HITL", "HITL_PENDING", risk, request_cue, now)
                self._add_pending(env, policy.reason_code, now)
                return self._refusal(raw, env, "HITL", "HITL_PENDING", PENDING_PAYLOAD)
            self._settle(raw, tr, "ALLOW", policy.reason_code, risk, request_cue, now)

        tr.step = 8                                                     # 8 forward
        try:
            reply = self._forward(env)
        except _ForwardError as exc:
            tr.notes.append("FORWARD_FAILED")
            tr.reason_code = "FORWARD_FAILED"
            return self._refusal(raw, env, "ALLOW", "FORWARD_FAILED",
                                 {"status": "error", "result": None, "error": f"broker: {exc}"})
        tr.forwarded = True

        tr.step = 9                                                     # 9 reply content
        reply, redacted, reply_cue = M.sanitize_reply(reply)
        decision, reason = "ALLOW", tr.reason_code
        if redacted:
            decision, reason = "SANITIZE", "REPLY_SANITIZED"
            tr.redacted_fields = list(redacted)
        if redacted or reply_cue:                       # affects the responder's next message (S23)
            responder_events = ["REPLY_SANITIZED"] if redacted else []
            with self._lock:
                M.trust.update(env.receiver, "SANITIZE" if redacted else "ALLOW",
                               M.risk_vector(env.action), bool(reply_cue), events=responder_events)
            if reply_cue:
                tr.notes.append("REPLY_INJECTION_CUE")
        tr.decision, tr.reason_code = decision, reason
        return reply.model_copy(update={"decision": decision, "reason_code": reason,
                                        "redacted_fields": list(redacted) or None,
                                        "broker_signature": None})

    def _stop(self, raw: Any, tr: _Trace, decision: str, reason: str) -> Envelope:
        """Hard gate before trust is involved (steps 1 to 3)."""
        tr.decision, tr.reason_code = decision, reason
        return self._refusal(raw, tr.env, decision, reason)

    def _settle(self, raw, tr: _Trace, decision: str, reason: str, risk: dict, cue: bool,
                now: float) -> Envelope:
        """Record a decision for a verified sender (trust, V1) and build a refusal if needed.

        Count once: one trust update per message, whatever the reason. A DENY that makes
        the defence manager block the agent (V1, 5 in 60 s) becomes QUARANTINE.
        """
        M = self.modules
        agent = tr.agent
        M.trust.update(agent, decision, risk, cue, events=list(tr.events))
        M.defence.record_decision(agent, decision, now)
        if decision == "DENY" and M.defence.is_blocked(agent):
            decision, reason = "QUARANTINE", "DENIAL_RATE_EXCEEDED"
        tr.decision, tr.reason_code = decision, reason
        return self._refusal(raw, tr.env, decision, reason)

    def _add_pending(self, env: Envelope, policy_reason: str, now: float) -> None:
        approval_id = str(uuid.uuid4())
        self.pending[approval_id] = {
            "approval_id": approval_id, "msg_id": env.msg_id, "trace_id": env.trace_id,
            "sender": env.sender, "receiver": env.receiver, "action": env.action,
            "resource": env.resource, "policy_reason": policy_reason, "created_at": _iso(now),
        }
        self._pending_envs[approval_id] = env

    # --- forwarding (step 8) --------------------------------------------------------------

    def _receiver_url(self, receiver: str) -> str:
        if self._agent_urls is not None:
            urls = self._agent_urls
        else:
            from wrapper.config import ConfigError, parse_agent_urls   # read-only reuse
            try:
                urls = parse_agent_urls(self._environ.get("AGENT_URLS", ""))
            except ConfigError as exc:
                raise _ForwardError("AGENT_URLS is invalid") from exc
        url = urls.get(receiver)
        if url is None:
            raise _ForwardError(f"no URL for receiver {receiver!r}")
        return url

    def _forward(self, env: Envelope) -> Envelope:
        url = f"{self._receiver_url(env.receiver)}/message"
        http = self._client or httpx.Client(timeout=self._timeout)
        try:
            # The token and proof stay with the broker: receivers get the envelope only.
            resp = http.post(url, content=env.model_dump_json(),
                             headers={"Content-Type": "application/json"})
        except httpx.HTTPError as exc:
            raise _ForwardError(f"{env.receiver!r} unreachable ({type(exc).__name__})") from None
        finally:
            if self._client is None:
                http.close()
        if resp.status_code != 200:
            raise _ForwardError(f"{env.receiver!r} answered HTTP {resp.status_code}")
        try:
            reply = Envelope.model_validate_json(resp.content)
        except ValidationError:
            raise _ForwardError(f"{env.receiver!r} did not return a valid envelope") from None
        if reply.msg_type != "response" or reply.parent_msg_id != env.msg_id or reply.sender != env.receiver:
            raise _ForwardError(f"{env.receiver!r} returned an envelope that does not answer the request")
        return reply

    # --- responses, audit, events ------------------------------------------------------------

    def _refusal(self, raw: Any, env: Envelope | None, decision: str, reason: str,
                 payload: dict | None = None) -> Envelope:
        """A response envelope the broker writes itself (refusal, HITL or forward failure)."""
        payload = dict(payload or DENIED_PAYLOAD)
        if env is not None:
            return Envelope(
                schema_version=SCHEMA_VERSION, msg_id=new_id(), trace_id=env.trace_id,
                parent_msg_id=env.msg_id, msg_type="response", sender=env.receiver,
                receiver=env.sender, action=env.action, resource=env.resource, payload=payload,
                delegation_chain=list(env.delegation_chain), timestamp=utc_now(),
                decision=decision, reason_code=reason)
        r = raw if isinstance(raw, dict) else {}
        return Envelope(
            schema_version=SCHEMA_VERSION, msg_id=new_id(), trace_id=_id_or(r.get("trace_id"), new_id()),
            parent_msg_id=_id_or(r.get("msg_id"), None), msg_type="response",
            sender=_id_or(r.get("receiver"), "broker"), receiver=_id_or(r.get("sender"), "unknown"),
            action=_id_or(r.get("action"), "unknown"), resource=_id_or(r.get("resource"), "unknown"),
            payload=payload, delegation_chain=["user"], timestamp=utc_now(),
            decision=decision, reason_code=reason)

    def _finish(self, reply: Envelope, tr: _Trace) -> Envelope:
        """Step 10: sign the reply, write the audit entry and the event record."""
        M = self.modules
        tr.decision = tr.decision or reply.decision
        tr.reason_code = reply.reason_code
        signed = reply.model_copy(update={"broker_signature": M.sign_decision(reply)})
        env = tr.env
        entry = {
            "ts": _iso(self._clock()),
            "msg_id": env.msg_id if env else tr.raw_msg_id,
            "trace_id": env.trace_id if env else None,
            "sender": env.sender if env else tr.raw_sender,
            "verified_agent": tr.agent,
            "receiver": env.receiver if env else None,
            "action": env.action if env else None,
            "step": tr.step,
            "decision": reply.decision,
            "reason_code": reply.reason_code,
            "events": list(tr.events),
            "notes": list(tr.notes),
            "redacted_fields": list(tr.redacted_fields),
            "forwarded": tr.forwarded,
            "reply_msg_id": signed.msg_id,
        }
        with self._lock:
            entry_hash = M.append(entry)
            self.events.append({**entry, "entry_hash": entry_hash})
            self.counters["messages"] += 1
            self.counters[f"decision:{reply.decision}"] += 1
            if tr.forwarded:
                self.counters["forwarded"] += 1
        return signed

    # --- views for the app ---------------------------------------------------------------------

    def health(self) -> dict:
        return {"status": "ok", "service": "broker",
                "modules": dict(self.modules.status),
                "stubbed": sorted(n for n, s in self.modules.status.items() if s == "stub"),
                "real": sorted(n for n, s in self.modules.status.items() if s == "real"),
                "ignored": dict(self.modules.ignored)}

    def state(self) -> dict:
        with self._lock:
            seen = set(self._epochs)
            names = list(get_catalog().roles) + sorted(seen - set(get_catalog().roles))
            agents = []
            for name in names:
                ts = self.modules.trust.get(name)
                agents.append({"agent": name, "T": round(float(ts.T), 4), "state": ts.state,
                               "epoch": self._epochs.get(name),
                               "blocked": bool(self.modules.defence.is_blocked(name))})
            counters = {
                "messages": self.counters["messages"],
                "forwarded": self.counters["forwarded"],
                "decisions": {d: self.counters[f"decision:{d}"] for d in DECISIONS},
                "pending_approvals": len(self.pending),
            }
            return {"counters": counters, "agents": agents, "pending_approvals": list(self.pending.values())}

    def recent_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return list(self.events)[-limit:][::-1]

    def release(self, agent: str, reviewer: str) -> dict:
        """Authorised release of a quarantined agent (trust engine; defence too if it can)."""
        with self._lock:
            state = self.modules.trust.release(agent, reviewer)
            undo = getattr(self.modules.defence, "release", None)
            if callable(undo):
                undo(agent)
            elif hasattr(self.modules.defence, "blocked"):
                self.modules.defence.blocked.discard(agent)      # the stub's block list
            entry = {"ts": _iso(self._clock()), "event": "release", "agent": agent, "reviewer": reviewer,
                     "T": float(state.T), "state": state.state}
            entry_hash = self.modules.append(entry)
            self.events.append({**entry, "entry_hash": entry_hash})
        return {"agent": agent, "T": float(state.T), "state": state.state, "released_by": reviewer}


_default: Broker | None = None
_default_lock = threading.Lock()


def default_broker() -> Broker:
    global _default
    with _default_lock:
        if _default is None:
            _default = Broker()
        return _default


def handle(raw: dict, headers: dict) -> Envelope:
    """Frozen interface: run the pipeline on one raw request with its HTTP headers."""
    return default_broker().handle(raw, headers)
