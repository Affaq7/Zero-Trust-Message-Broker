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
even one that cannot be parsed, gets one audit entry (field names of
docs/audit-log-examples.md, A4) and an event record; neither ever holds a payload
(only its hash), a header or a token. The defence manager's own events
(quarantine, release) are appended to the audit log as they happen.

Which implementation runs is decided per function in one place, Modules: all stubs
by default; BROKER_REAL="identity,policy,audit,..." switches the named groups to the
real modules, function by function, imported lazily. A function whose module or
attribute is not on this branch yet stays a stub and is listed in /health.

Direct mode is untouched: nothing here is imported by wrapper/, agents/ or runner/.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import logging
import os
import sys
import threading
import time
import uuid
from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

from broker import stubs
from contracts.catalog import get_catalog
from contracts.envelope import Envelope, new_id, utc_now
from contracts.version import SCHEMA_VERSION

log = logging.getLogger("broker")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SIGNING_KEY = REPO_ROOT / "keys" / "broker_signing.key"
SIGNING_KEY_HINT = "python -m broker.audit.signing_key create"

DECISIONS = ("ALLOW", "SANITIZE", "HITL", "DENY", "QUARANTINE")
# Event codes the trust engine accepts (docs/detection-design.md section 4).
TRUST_EVENTS = ("INJECTION_CUE", "BURST_DETECTED", "INDIVIDUAL_DATA_REQUEST", "REPLY_SANITIZED")
# A3 event kinds the audit log accepts (PR #9, broker/audit/log.py EVENT_KINDS).
AUDIT_EVENT_KINDS = ("quarantine", "release", "revoke", "restore")
DENIED_PAYLOAD = {"status": "denied"}
PENDING_PAYLOAD = {"status": "pending"}
DEFAULT_FORWARD_TIMEOUT_S = 60.0
MAX_EVENTS = 1000
# V4 (BurstDetector) counts requests per (agent, trace_id). The broker never sees a task end
# (every request has parent_msg_id = null, and the runner's /task reply does not pass through
# it), so traces are forgotten when idle, and the number tracked is capped.
TRACE_IDLE_SECONDS = 900           # the runner's task timeout; a trace this quiet is over
TRACE_SWEEP_INTERVAL_SECONDS = 60  # idle traces are looked for at most once a minute
MAX_TRACKED_TRACES = 10_000        # beyond this the least recently seen trace is forgotten


class BrokerStartupError(RuntimeError):
    """The broker cannot start with the chosen real modules (message says how to fix it)."""


class UnknownAgentError(ValueError):
    """/admin/release named an agent the broker does not know."""


# --- module registry, per function ----------------------------------------------------------

# group name (as written in BROKER_REAL) -> (real module path, functions or classes it provides).
# Paths of modules not on main yet are the documented ones: validate (Kissa K4), defence
# (PR #8), audit (PR #9), signing (A5, stretch), content (F3, placeholder path).
GROUPS: dict[str, tuple[str, tuple[str, ...]]] = {
    "validate": ("broker.intercept.validate", ("validate_envelope",)),
    "identity": ("broker.identity.verify", ("verify_identity",)),
    "defence": ("broker.defence.quarantine", ("DefenceManager",)),
    "policy": ("broker.policy.engine", ("evaluate_policy",)),
    "risk": ("broker.trust.risk", ("risk_vector", "required_trust")),
    "trust": ("broker.trust.trust", ("TrustEngine",)),
    "burst": ("broker.trust.rules", ("BurstDetector",)),
    "content": ("broker.content", ("check_request_content", "sanitize_reply")),
    "audit": ("broker.audit.log", ("append", "configure")),
    "signing": ("broker.transport.signing", ("sign_decision",)),
}
FUNCTIONS: tuple[str, ...] = tuple(f for _, fns in GROUPS.values() for f in fns)
REVOCATION_MODULE = "broker.defence.revocation"     # PR #8: set_registry(), revoke(), restore()


def _module_exists(path: str) -> bool:
    if path in sys.modules:
        return sys.modules[path] is not None
    try:
        return importlib.util.find_spec(path) is not None
    except (ModuleNotFoundError, ValueError):        # a parent package is missing
        return False


@dataclass
class Modules:
    """The one place that says which implementation each pipeline function uses.

    Classes (TrustEngine, DefenceManager, BurstDetector) are instantiated once: the
    defence manager gets the shared trust engine (PR #8: DefenceManager(trust=...)).
    Tests may pass ready instances instead.
    """

    validate_envelope: Callable = stubs.validate_envelope
    verify_identity: Callable = stubs.verify_identity
    evaluate_policy: Callable = stubs.evaluate_policy
    risk_vector: Callable = stubs.risk_vector
    required_trust: Callable = stubs.required_trust
    check_request_content: Callable = stubs.check_request_content
    sanitize_reply: Callable = stubs.sanitize_reply
    append: Callable | None = None                 # None: a fresh in-memory stub audit log
    configure: Callable | None = None              # real audit only
    sign_decision: Callable = stubs.sign_decision
    TrustEngine: type = stubs.TrustEngine
    DefenceManager: type = stubs.DefenceManager
    BurstDetector: type = stubs.BurstDetector
    trust: Any = None
    defence: Any = None
    burst: Any = None
    status: dict[str, str] = field(default_factory=lambda: {f: "stub" for f in FUNCTIONS})
    ignored: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.trust is None:
            self.trust = self.TrustEngine()
        if self.defence is None:
            self.defence = self.DefenceManager(trust=self.trust)
        if self.burst is None:
            self.burst = self.BurstDetector()
        if self.append is None:
            self.append = stubs.AuditLog().append

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "Modules":
        """All stubs, then each group named in BROKER_REAL switched to its real module."""
        names = [n.strip() for n in environ.get("BROKER_REAL", "").split(",") if n.strip()]
        return cls.with_real(names)

    @classmethod
    def with_real(cls, names: list[str]) -> "Modules":
        found: dict[str, Any] = {}
        ignored: dict[str, str] = {}
        for name in names:
            if name not in GROUPS:
                ignored[name] = "unknown module name"
                continue
            path, functions = GROUPS[name]
            if not _module_exists(path):
                ignored[name] = f"{path} does not exist on this branch yet; using the stub"
                continue
            try:
                module = importlib.import_module(path)
            except Exception as exc:  # noqa: BLE001 - a broken real module must not stop the broker
                ignored[name] = f"{path} could not be imported ({type(exc).__name__}); using the stub"
                continue
            for fn in functions:
                value = getattr(module, fn, None)
                if value is None:
                    ignored[f"{name}.{fn}"] = f"{path} has no {fn}; using the stub"
                else:
                    found[fn] = value
        mods = cls(**found)
        mods.ignored = ignored
        for fn in found:
            mods.status[fn] = "real"
        return mods

    def is_real(self, fn: str) -> bool:
        return self.status.get(fn) == "real"

    def group_status(self) -> dict[str, str]:
        out = {}
        for name, (_, functions) in GROUPS.items():
            real = [self.is_real(f) for f in functions]
            out[name] = "real" if all(real) else "stub" if not any(real) else "partial"
        return out


# --- the pipeline ---------------------------------------------------------------------------

class _ForwardError(Exception):
    pass


@dataclass
class _Trace:
    """What one message did, for the audit entry and the event record (no payloads)."""

    raw_sender: str | None = None
    raw_msg_id: str | None = None
    env: Envelope | None = None
    identity: Any = None
    agent: str | None = None
    step: int = 0
    decision: str | None = None
    reason_code: str | None = None
    risk: dict | None = None
    trust: dict | None = None
    events: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    redacted_fields: list[str] = field(default_factory=list)
    forwarded: bool = False


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


def _id_or(value: Any, default: str | None) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 128 else default


def _payload_hash(payload: Any) -> str:
    """SHA-256 of the canonical JSON payload, as A4's payload_hash()."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _trust_view(before, after) -> dict | None:
    if before is None or after is None:
        return None
    return {"T_before": float(before.T), "T_after": float(after.T),
            "state_before": before.state, "state_after": after.state}


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
        self._trace_seen: OrderedDict[str, float] = OrderedDict()   # trace_id -> last seen, oldest first
        self._last_sweep: float | None = None
        self._defence_seen = 0                   # how many DefenceManager.log() events are audited
        self.startup: dict[str, Any] = {"started": False, "audit_configured": False,
                                        "revocation_registry": False}

    # --- startup ----------------------------------------------------------------------------

    def start(self, signing_key_path: Path | None = None, audit_log_path: Path | None = None) -> None:
        """Once, before the first message: configure the real audit log and give the real
        revocation module the identity registry. Raises BrokerStartupError with a fix."""
        M = self.modules
        if M.is_real("configure"):
            key_path = Path(signing_key_path or DEFAULT_SIGNING_KEY)
            if not key_path.is_file():
                raise BrokerStartupError(
                    f"real audit is on (BROKER_REAL includes audit) but the broker signing key "
                    f"keys/{key_path.name} is missing: run {SIGNING_KEY_HINT}")
            from broker.identity.keys import private_key_from_text
            try:
                key = private_key_from_text(key_path.read_text(encoding="utf-8").strip())
            except Exception as exc:  # noqa: BLE001
                raise BrokerStartupError(f"keys/{key_path.name} is not a valid signing key "
                                         f"({type(exc).__name__})") from None
            M.configure(audit_log_path, key)
            self.startup["audit_configured"] = True
        elif M.is_real("append"):
            raise BrokerStartupError("real audit append without configure(): check broker/audit/log.py")
        if M.is_real("verify_identity") and _module_exists(REVOCATION_MODULE):
            from broker.identity import verify as identity_verify
            try:
                registry = identity_verify.default_verifier().registry
            except Exception as exc:  # noqa: BLE001
                raise BrokerStartupError(f"real identity is on but the registry could not be loaded "
                                         f"({type(exc).__name__}: {exc}); run scripts/issue_credentials.py")
            importlib.import_module(REVOCATION_MODULE).set_registry(registry)
            self.startup["revocation_registry"] = True
        self.startup["started"] = True

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
        ident = tr.identity = M.verify_identity(headers, env)
        if not ident.ok or not ident.agent:
            # Not verified: never counted against the claimed sender (V1, trust).
            return self._stop(raw, tr, "DENY", ident.reason_code or "UNKNOWN_AGENT")
        agent = tr.agent = ident.agent

        with self._lock:
            self._epochs[agent] = ident.epoch

            tr.step = 3                                                 # 3 quarantine
            if M.defence.is_blocked(agent) or M.trust.get(agent).state == "Quarantined":
                state = M.trust.get(agent)
                tr.trust = _trust_view(state, state)
                M.defence.record_decision(agent, "QUARANTINE", now)
                return self._stop(raw, tr, "QUARANTINE", "AGENT_QUARANTINED")

            self._track_trace(env.trace_id, now)                         # forget idle traces first
            for event in M.burst.observe(agent, env.trace_id):          # V4, counted per request
                if event not in tr.events:
                    tr.events.append(event)

            tr.step = 4                                                 # 4 policy
            policy = M.evaluate_policy(env, ident)
            risk = tr.risk = M.risk_vector(env.action)
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

        Count once: one trust update per message, whatever the reason. The decision is never
        changed here: the denial that trips V1 (5 in 60 s) stays a DENY with its own reason
        code; the quarantine itself is the defence manager's log event (kind quarantine,
        reason_code DENIAL_RATE_EXCEEDED, audited at step 10), and the agent's next message
        gets QUARANTINE / AGENT_QUARANTINED at step 3 (docs/scenario-control-map.md, A9).
        """
        M = self.modules
        agent = tr.agent
        before = M.trust.get(agent)
        after = M.trust.update(agent, decision, risk, cue, events=list(tr.events))
        tr.trust = _trust_view(before, after)
        M.defence.record_decision(agent, decision, now)
        tr.decision, tr.reason_code = decision, reason
        return self._refusal(raw, tr.env, decision, reason)

    def _track_trace(self, trace_id: str, now: float) -> None:
        """Record that ``trace_id`` is active now, and forget traces that are over (no timer thread).

        Called under the lock, before BurstDetector.observe(), so a trace that comes back after
        being idle starts counting again from zero.
        """
        seen = self._trace_seen
        if self._last_sweep is None or now - self._last_sweep >= TRACE_SWEEP_INTERVAL_SECONDS:
            self._last_sweep = now
            while seen:                                   # oldest first: stop at the first active one
                oldest, last = next(iter(seen.items()))
                if now - last <= TRACE_IDLE_SECONDS:
                    break
                seen.popitem(last=False)
                self._forget_trace(oldest)
        seen[trace_id] = now
        seen.move_to_end(trace_id)
        while len(seen) > MAX_TRACKED_TRACES:
            oldest, _ = seen.popitem(last=False)
            self._forget_trace(oldest)

    def _forget_trace(self, trace_id: str) -> None:
        forget = getattr(self.modules.burst, "forget", None)
        if callable(forget):
            forget(trace_id)

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

    def _audit_entry(self, reply: Envelope, tr: _Trace, ts: str) -> dict:
        """One decision line in A4's field names. For a message that could not be parsed the
        required ids come from the broker's own refusal (A4 refuses a line without them)."""
        env = tr.env
        risk = tr.risk
        return {
            "kind": "decision",
            "ts": ts,
            "trace_id": env.trace_id if env else reply.trace_id,
            "msg_id": env.msg_id if env else (tr.raw_msg_id or f"unparsed:{reply.msg_id}"),
            "parent_msg_id": env.parent_msg_id if env else None,
            "msg_type": env.msg_type if env else None,
            "sender": env.sender if env else (tr.raw_sender or "unknown"),
            "receiver": env.receiver if env else reply.sender,
            "action": env.action if env else reply.action,
            "resource": env.resource if env else None,
            "payload_hash": _payload_hash(env.payload) if env else None,
            "identity": tr.identity.model_dump(mode="json") if tr.identity is not None else None,
            "trust": tr.trust,
            "risk": dict(risk) if risk is not None else None,
            "compound_high": (sum(1 for v in risk.values() if v == "H") >= 2) if risk is not None else None,
            "decision": reply.decision,
            "reason_code": reply.reason_code,
            "events": list(tr.events),
            "redacted_fields": list(tr.redacted_fields) or None,
        }

    def _finish(self, reply: Envelope, tr: _Trace) -> Envelope:
        """Step 10: sign the reply, append the audit line, record the event, audit defence events."""
        M = self.modules
        signed = reply.model_copy(update={"broker_signature": M.sign_decision(reply)})
        ts = _iso(self._clock())
        entry = self._audit_entry(reply, tr, ts)
        with self._lock:
            entry_hash = M.append(entry)
            self.events.append({
                "kind": "decision", "ts": ts, "msg_id": entry["msg_id"], "trace_id": entry["trace_id"],
                "sender": entry["sender"], "verified_agent": tr.agent, "receiver": entry["receiver"],
                "action": entry["action"], "step": tr.step, "decision": reply.decision,
                "reason_code": reply.reason_code, "events": list(tr.events), "notes": list(tr.notes),
                "redacted_fields": list(tr.redacted_fields), "forwarded": tr.forwarded,
                "reply_msg_id": signed.msg_id, "entry_hash": entry_hash,
            })
            self.counters["messages"] += 1
            self.counters[f"decision:{reply.decision}"] += 1
            if tr.forwarded:
                self.counters["forwarded"] += 1
            self._audit_defence_events()
        return signed

    def _audit_defence_events(self) -> None:
        """Append the defence manager's new events (quarantine, release) to the audit log.

        DefenceManager.log() (broker/defence/quarantine.py) returns its whole list on every
        call, each entry already in A4's field names: kind, agent, by, reason_code, ts,
        denials. A cursor makes sure each entry is appended exactly once. Only ``ts`` is
        normalised: the broker-clock float (or None on release) becomes an ISO time, as in
        every other audit line.
        """
        get_log = getattr(self.modules.defence, "log", None)
        if not callable(get_log):
            return
        entries = get_log()
        new, self._defence_seen = entries[self._defence_seen:], len(entries)
        for e in new:
            raw_ts = e.get("ts")
            ts = _iso(raw_ts) if isinstance(raw_ts, (int, float)) else (raw_ts or _iso(self._clock()))
            entry = {"kind": e.get("kind"), "ts": ts, "agent": e.get("agent"), "by": e.get("by"),
                     "reason_code": e.get("reason_code"), "denials": e.get("denials")}
            entry_hash = self.modules.append(entry) if entry["kind"] in AUDIT_EVENT_KINDS else None
            self.events.append({**entry, "entry_hash": entry_hash})

    def refuse_unread(self, reason: str) -> Envelope:
        """A DENY for a request the app would not read (e.g. a body over the size limit).
        Audited and recorded like any step-1 refusal; never raises."""
        tr = _Trace(step=1, decision="DENY", reason_code=reason)
        reply = self._refusal(None, None, "DENY", reason)
        try:
            return self._finish(reply, tr)
        except Exception as exc:  # noqa: BLE001
            log.error("audit/sign failed: %s", type(exc).__name__)
            return reply

    def admin_event(self, kind: str, **fields: Any) -> None:
        """An admin call that changed nothing (refused): event list only, never secrets."""
        with self._lock:
            self.events.append({"kind": kind, "ts": _iso(self._clock()), **fields})

    # --- views and admin ---------------------------------------------------------------------

    def health(self) -> dict:
        functions = dict(self.modules.status)
        return {"status": "ok", "service": "broker",
                "modules": self.modules.group_status(),
                "functions": functions,
                "real": sorted(f for f, s in functions.items() if s == "real"),
                "stubbed": sorted(f for f, s in functions.items() if s == "stub"),
                "ignored": dict(self.modules.ignored),
                "startup": dict(self.startup)}

    def known_agents(self) -> list[str]:
        catalog = get_catalog()
        return list(dict.fromkeys([*catalog.roles, *catalog.agents, *sorted(self._epochs)]))

    def state(self) -> dict:
        with self._lock:
            agents = []
            for name in self.known_agents():
                ts = self.modules.trust.get(name)
                # quarantined: the step-3 answer (V1 block or trust-engine Quarantined, as
                # DefenceManager.is_blocked says); trust_state: the trust engine's own state.
                agents.append({"agent": name, "T": round(float(ts.T), 4), "trust_state": ts.state,
                               "quarantined": bool(self.modules.defence.is_blocked(name)),
                               "epoch": self._epochs.get(name)})
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
        """Authorised release through the defence manager (PR #8), which also restores trust.

        Raises UnknownAgentError, PermissionError (reviewer not allowed) or ValueError
        (agent not quarantined); the app turns them into 400 / 403 / 400.
        """
        if agent not in self.known_agents():
            raise UnknownAgentError(f"unknown agent {agent!r}")
        with self._lock:
            self.modules.defence.release(agent, reviewer, ts=self._clock())
            self._audit_defence_events()
            state = self.modules.trust.get(agent)
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
