"""F1 follow-up: real-module loading per function, /admin/release with the admin token,
the defence manager of PR #8 and the audit log of PR #9.

PR #8 and #9 are not on main yet, so their documented interfaces are replaced by small
fakes installed as modules (broker.defence.quarantine, broker.defence.revocation,
broker.audit.log). No network, no live model, no real keys: the signing key is made
here in a temporary folder."""

import sys
import types
from collections import deque

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from broker import stubs
from broker.app import create_app
from broker.identity.keys import private_key_to_text
from broker.identity.verify import IdentityResult
from broker.pipeline import Broker, BrokerStartupError, Modules
from broker.policy.engine import PolicyResult
from contracts import new_request

ADMIN = "admin-placeholder-value"
N1 = dict(sender="planner", receiver="database", action="db.query_aggregate", resource="db:project_costs",
          payload={"metric": "sum", "column": "amount", "filters": {"project": "Project X"}},
          chain_so_far=["user"])


# --- fakes of the PR #8 and PR #9 interfaces ---------------------------------------------------

class FakeDefenceManager:
    """PR #8 interface: DefenceManager(trust=None, settings=None); V1 = 5 DENY in 60 s."""

    def __init__(self, trust=None, settings=None):
        self.s = settings or {"deny_limit": 5, "window_seconds": 60, "reviewers": ["amna", "kissa", "afaq"]}
        self.trust = trust
        self.calls = []
        self._denials, self._blocked, self._log = {}, set(), []

    def record_decision(self, agent, decision, ts):
        self.calls.append((agent, decision))
        if not agent or decision != "DENY" or agent in self._blocked:
            return
        window = self._denials.setdefault(agent, deque())
        window.append(ts)
        while window and ts - window[0] > self.s["window_seconds"]:
            window.popleft()
        if len(window) >= self.s["deny_limit"]:
            self._blocked.add(agent)
            self._log.append({"event": "quarantine", "agent": agent, "reason": "DENIAL_RATE_EXCEEDED",
                              "ts": ts, "denials": list(window)})
            window.clear()

    def is_blocked(self, agent):
        if not agent:
            return False
        return agent in self._blocked or (self.trust is not None and self.trust.get(agent).state == "Quarantined")

    def release(self, agent, reviewer, ts=None):
        if reviewer not in self.s["reviewers"]:
            raise PermissionError(f"reviewer {reviewer!r} may not release agents")
        if not agent:
            raise ValueError("agent name is empty")
        if not self.is_blocked(agent):
            raise ValueError(f"{agent!r} is not quarantined")
        self._blocked.discard(agent)
        self._denials.pop(agent, None)
        if self.trust is not None:
            self.trust.release(agent, reviewer)
        self._log.append({"event": "release", "agent": agent, "reviewer": reviewer, "ts": ts})

    def log(self):
        return [dict(e) for e in self._log]


DECISION_FIELDS = ("kind", "ts", "trace_id", "msg_id", "parent_msg_id", "msg_type", "sender", "receiver",
                   "action", "resource", "payload_hash", "identity", "trust", "risk", "compound_high",
                   "decision", "reason_code", "events", "redacted_fields")
DECISION_REQUIRED = ("trace_id", "msg_id", "sender", "receiver", "action", "decision")
EVENT_FIELDS = ("kind", "ts", "agent", "by", "reason_code", "denials")
EVENT_REQUIRED = {"quarantine": ("agent", "reason_code"), "release": ("agent", "by"),
                  "revoke": ("agent", "by"), "restore": ("agent", "by")}


class FakeAudit:
    """PR #9 interface: configure(path, private_key) and append(entry) -> entry_hash, refusing
    any field outside its lists and any missing required field."""

    def __init__(self):
        self.entries, self.configured = [], []

    def configure(self, path=None, private_key=None):
        self.configured.append((path, private_key))

    def append(self, entry):
        kind = entry.get("kind", "decision")
        allowed, required = ((DECISION_FIELDS, DECISION_REQUIRED) if kind == "decision"
                             else (EVENT_FIELDS, EVENT_REQUIRED[kind]))
        extra = set(entry) - set(allowed)
        assert not extra, f"fields not allowed in the audit log: {sorted(extra)}"
        assert all(entry.get(f) not in (None, "") for f in required), f"missing fields in {entry}"
        self.entries.append(entry)
        return f"{len(self.entries):064x}"


def install(monkeypatch, name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    monkeypatch.setitem(sys.modules, name, module)
    return module


@pytest.fixture
def fake_defence(monkeypatch):
    return install(monkeypatch, "broker.defence.quarantine", DefenceManager=FakeDefenceManager)


@pytest.fixture
def fake_audit(monkeypatch):
    audit = FakeAudit()
    install(monkeypatch, "broker.audit.log", append=audit.append, configure=audit.configure)
    return audit


@pytest.fixture
def signing_key(tmp_path):
    path = tmp_path / "keys" / "broker_signing.key"
    path.parent.mkdir()
    path.write_text(private_key_to_text(Ed25519PrivateKey.generate()) + "\n", encoding="utf-8")
    return path


def receiver(request):
    from contracts import Envelope
    from contracts.envelope import make_response
    from contracts.payloads import ResponsePayload
    env = Envelope.model_validate_json(request.content)
    return httpx.Response(200, content=make_response(env, ResponsePayload(status="ok", result=1)).model_dump_json())


def make(modules, **kw):
    return Broker(modules, client=httpx.Client(transport=httpx.MockTransport(receiver)),
                  agent_urls={"database": "http://database.test"}, **kw)


def deny_policy(env, identity):
    return PolicyResult(verdict="DENY", action_class="Permitted", reason_code="ROLE_NOT_ALLOWED",
                        needs_human=False)


def raw_n1():
    return new_request(**N1).model_dump(mode="json")


def admin_client(broker, token=ADMIN, header=ADMIN):
    client = TestClient(create_app(broker, environ={"BROKER_ADMIN_TOKEN": token} if token else {}))
    if header is not None:
        client.headers["X-Admin-Token"] = header
    return client


def quarantine_planner(broker):
    """Five verified DENYs in a row: V1 quarantines the planner on the fifth."""
    policy = broker.modules.evaluate_policy
    broker.modules.evaluate_policy = deny_policy
    outs = [broker.handle(raw_n1(), {}) for _ in range(5)]
    broker.modules.evaluate_policy = policy
    return outs


# --- 1. loading per function -------------------------------------------------------------------

def test_audit_real_while_sign_decision_stays_a_stub(fake_audit, signing_key):
    mods = Modules.with_real(["audit", "signing"])
    assert mods.status["append"] == mods.status["configure"] == "real"
    assert mods.status["sign_decision"] == "stub"
    assert "broker.transport.signing" in mods.ignored["signing"]
    broker = make(mods)
    broker.start(signing_key_path=signing_key)
    health = broker.health()
    assert health["functions"]["append"] == "real" and health["functions"]["sign_decision"] == "stub"
    assert health["modules"]["audit"] == "real" and health["modules"]["signing"] == "stub"
    assert health["startup"]["audit_configured"] is True

    out = broker.handle(raw_n1(), {})
    assert out.decision == "ALLOW" and out.broker_signature.startswith("STUB-SIG-")
    [entry] = fake_audit.entries                                    # one line per decision
    assert entry["kind"] == "decision" and entry["decision"] == "ALLOW" and entry["sender"] == "planner"
    assert len(entry["payload_hash"]) == 64 and "payload" not in entry
    assert entry["identity"]["agent"] == "planner" and set(entry["trust"]) == {
        "T_before", "T_after", "state_before", "state_after"}
    assert set(entry["risk"]) == set("RTDEPAS") and entry["compound_high"] is False


def test_audit_accepts_unparseable_messages_too(fake_audit, signing_key):
    broker = make(Modules.with_real(["audit"]))
    broker.start(signing_key_path=signing_key)
    out = broker.handle(None, {})
    assert (out.decision, out.reason_code) == ("DENY", "MALFORMED_JSON")
    [entry] = fake_audit.entries
    assert entry["msg_id"].startswith("unparsed:") and entry["identity"] is None and entry["risk"] is None


# --- 4. startup -----------------------------------------------------------------------------------

def test_startup_fails_with_a_clear_message_when_the_signing_key_is_missing(fake_audit, tmp_path):
    broker = make(Modules.with_real(["audit"]))
    with pytest.raises(BrokerStartupError, match=r"broker_signing\.key is missing: run "
                                                 r"python -m broker\.audit\.signing_key create"):
        broker.start(signing_key_path=tmp_path / "keys" / "broker_signing.key")
    assert fake_audit.configured == []


def test_configure_gets_the_path_and_the_key(fake_audit, signing_key, tmp_path):
    broker = make(Modules.with_real(["audit"]))
    broker.start(signing_key_path=signing_key, audit_log_path=tmp_path / "audit.jsonl")
    [(path, key)] = fake_audit.configured
    assert path == tmp_path / "audit.jsonl" and isinstance(key, Ed25519PrivateKey)


def test_set_registry_is_called_once_when_real_identity_is_on(monkeypatch):
    calls = []
    install(monkeypatch, "broker.defence.revocation", set_registry=calls.append)
    sentinel = object()
    import broker.identity.verify as verify
    monkeypatch.setattr(verify, "default_verifier", lambda: types.SimpleNamespace(registry=sentinel))
    broker = make(Modules.with_real(["identity"]))
    broker.start()
    assert calls == [sentinel] and broker.health()["startup"]["revocation_registry"] is True

    calls.clear()
    make(Modules.with_real(["risk"])).start()                       # identity stubbed: not called
    assert calls == []


# --- 2. defence manager ------------------------------------------------------------------------------

def test_defence_manager_gets_the_shared_trust_engine(fake_defence):
    mods = Modules.with_real(["defence", "trust"])
    assert isinstance(mods.defence, FakeDefenceManager) and mods.defence.trust is mods.trust


def test_record_decision_is_not_called_for_unverified_senders(fake_defence):
    def forged(headers, env):
        return IdentityResult(ok=False, agent=None, role=None, instance_id=None, epoch=None,
                              reason_code="PROOF_KEY_MISMATCH")

    mods = Modules.with_real(["defence"])
    mods.verify_identity = forged
    broker = make(mods)
    for _ in range(10):
        assert broker.handle(raw_n1(), {}).reason_code == "PROOF_KEY_MISMATCH"
    assert mods.defence.calls == [] and not mods.defence.is_blocked("planner")


def test_release_success_restores_trust_and_is_audited(fake_defence, fake_audit, signing_key):
    mods = Modules.with_real(["defence", "trust", "audit"])
    broker = make(mods)
    broker.start(signing_key_path=signing_key)
    outs = quarantine_planner(broker)
    assert [o.decision for o in outs] == ["DENY"] * 4 + ["QUARANTINE"]
    assert outs[-1].reason_code == "DENIAL_RATE_EXCEEDED"
    assert broker.handle(raw_n1(), {}).reason_code == "AGENT_QUARANTINED"

    client = admin_client(broker)
    r = client.post("/admin/release", json={"agent": "planner", "reviewer": "kissa"})
    assert r.status_code == 200
    assert r.json() == {"agent": "planner", "T": 0.5, "state": "Restricted", "released_by": "kissa"}
    assert broker.handle(raw_n1(), {}).decision == "ALLOW"

    kinds = [(e["kind"], e.get("by"), e.get("reason_code")) for e in fake_audit.entries if e["kind"] != "decision"]
    assert kinds == [("quarantine", "broker", "DENIAL_RATE_EXCEEDED"), ("release", "kissa", None)]
    quarantine = next(e for e in fake_audit.entries if e["kind"] == "quarantine")
    assert quarantine["agent"] == "planner" and len(quarantine["denials"]) == 5
    events = client.get("/api/events").json()["events"]
    assert any(e["kind"] == "release" and e["by"] == "kissa" for e in events)


def test_release_reviewer_not_allowed_is_403(fake_defence):
    broker = make(Modules.with_real(["defence"]))
    quarantine_planner(broker)
    r = admin_client(broker).post("/admin/release", json={"agent": "planner", "reviewer": "mallory"})
    assert r.status_code == 403 and broker.modules.defence.is_blocked("planner")
    assert broker.recent_events(1)[0] == {**broker.recent_events(1)[0], "kind": "release_refused",
                                          "by": "mallory", "outcome": "403 reviewer not allowed"}


@pytest.mark.parametrize("body, message", [
    ({"agent": "planner", "reviewer": "afaq"}, "not quarantined"),
    ({"agent": "nobody", "reviewer": "afaq"}, "unknown agent"),
    ({"agent": "planner"}, "body must be"),
    ({"agent": "", "reviewer": "afaq"}, "body must be"),
])
def test_release_bad_requests_are_400(fake_defence, body, message):
    broker = make(Modules.with_real(["defence"]))
    r = admin_client(broker).post("/admin/release", json=body)
    assert r.status_code == 400 and message in r.json()["error"]


def test_release_never_500_even_if_the_defence_manager_breaks():
    class Broken(stubs.DefenceManager):
        def release(self, agent, reviewer, ts=None):
            raise RuntimeError("bug")

    broker = make(Modules(defence=Broken()))
    r = admin_client(broker).post("/admin/release", json={"agent": "planner", "reviewer": "afaq"})
    assert r.status_code == 400


# --- 3. admin token ---------------------------------------------------------------------------------

@pytest.mark.parametrize("header, status, outcome", [
    (None, 401, "401 missing admin token"),
    ("", 401, "401 missing admin token"),
    ("wrong-value", 401, "401 wrong admin token"),
])
def test_missing_or_wrong_admin_token_is_refused(fake_defence, header, status, outcome):
    broker = make(Modules.with_real(["defence"]))
    quarantine_planner(broker)
    r = admin_client(broker, header=header).post("/admin/release", json={"agent": "planner", "reviewer": "afaq"})
    assert r.status_code == status and broker.modules.defence.is_blocked("planner")
    event = broker.recent_events(1)[0]
    assert event["kind"] == "admin_refused" and event["outcome"] == outcome
    assert ADMIN not in str(broker.recent_events(50)) and "wrong-value" not in str(broker.recent_events(50))


def test_no_admin_token_configured_refuses_every_admin_call(fake_defence):
    broker = make(Modules.with_real(["defence"]))
    quarantine_planner(broker)
    client = admin_client(broker, token=None, header="anything")
    r = client.post("/admin/release", json={"agent": "planner", "reviewer": "afaq"})
    assert r.status_code == 403 and "BROKER_ADMIN_TOKEN is not set" in r.json()["error"]
    assert broker.modules.defence.is_blocked("planner")
    assert client.get("/health").json()["admin"] == "disabled"
    r = admin_client(broker, token=None, header="").post("/admin/release", json={"agent": "planner", "reviewer": "afaq"})
    assert r.status_code == 403
