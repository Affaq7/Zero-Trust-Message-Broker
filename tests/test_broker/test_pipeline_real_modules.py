"""The pipeline with REAL modules from main: V4 (BurstDetector) and its trace forgetting,
and the signed audit log (A4). Fixed clock, temp folders, a key made here; no network."""

import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import broker.pipeline as pipeline
from broker import stubs
from broker.identity.keys import private_key_to_text
from broker.pipeline import Broker, Modules
from broker.policy.engine import PolicyResult
from contracts import Envelope, make_response, new_request
from contracts.payloads import ResponsePayload


class Clock:
    """A clock the test moves by hand (seconds)."""

    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class Recorder:
    """Stands in for audit append(): keeps every entry, returns a fake entry_hash."""

    def __init__(self):
        self.entries = []

    def __call__(self, entry):
        self.entries.append(entry)
        return f"{len(self.entries):064x}"


def receiver(request):
    env = Envelope.model_validate_json(request.content)
    return httpx.Response(200, content=make_response(env, ResponsePayload(status="ok", result=1)).model_dump_json())


def make(mods, clock):
    return Broker(mods, client=httpx.Client(transport=httpx.MockTransport(receiver)),
                  agent_urls={"database": "http://database.test"}, clock=clock)


def n1(trace_id="trace-1"):
    return json.loads(new_request(sender="planner", receiver="database", action="db.query_aggregate",
                                  resource="db:project_costs", payload={"metric": "sum", "column": "amount"},
                                  chain_so_far=["user"], trace_id=trace_id).model_dump_json())


def deny_policy(env, identity):
    return PolicyResult(verdict="DENY", action_class="Permitted", reason_code="ROLE_NOT_ALLOWED",
                        needs_human=False)


def burst_broker(clock):
    from broker.trust.rules import BurstDetector as RealBurst
    mods = Modules.with_real(["burst"])
    assert isinstance(mods.burst, RealBurst) and mods.burst.limit == 10
    audit = Recorder()
    mods.append = audit
    return make(mods, clock), audit


def bursts(audit):
    """Which decision lines carried BURST_DETECTED (1-based)."""
    decisions = [e for e in audit.entries if e.get("kind") == "decision"]
    return [n for n, e in enumerate(decisions, 1) if "BURST_DETECTED" in e["events"]]


# --- V4 with the real BurstDetector ----------------------------------------------------------

def test_v4_fires_on_the_11th_request_and_the_agent_turns_suspicious():
    from broker.trust.trust import TrustEngine as RealTrust
    mods = Modules.with_real(["burst", "trust"])
    assert isinstance(mods.trust, RealTrust)
    audit = Recorder()
    mods.append = audit
    broker = make(mods, Clock())
    outs = [broker.handle(n1(), {}) for _ in range(11)]
    assert all(o.decision == "ALLOW" for o in outs)                     # an event never decides on its own
    assert bursts(audit) == [11]
    assert mods.trust.get("planner").state == "Suspicious"


# --- forgetting traces: idle (900 s) and capped (10,000) ----------------------------------------

def test_an_idle_trace_is_forgotten_and_its_counter_restarts():
    clock = Clock()
    broker, audit = burst_broker(clock)
    for _ in range(10):
        broker.handle(n1("t-idle"), {})
    clock.t += pipeline.TRACE_IDLE_SECONDS + 1                        # quiet for longer than 900 s
    for _ in range(10):
        broker.handle(n1("t-idle"), {})                                # counts from zero again
    assert bursts(audit) == []
    broker.handle(n1("t-idle"), {})                                    # the 11th since it came back
    assert bursts(audit) == [21]


def test_an_active_trace_is_kept():
    clock = Clock()
    broker, audit = burst_broker(clock)
    for _ in range(11):
        broker.handle(n1("t-active"), {})
        clock.t += 500                                                 # long gaps, but never 900 s idle
    assert bursts(audit) == [11]


def test_other_idle_traces_are_forgotten_while_an_active_one_is_kept():
    clock = Clock()
    broker, _ = burst_broker(clock)
    forgotten = []
    real_forget = broker.modules.burst.forget
    broker.modules.burst.forget = lambda t: (forgotten.append(t), real_forget(t))
    broker.handle(n1("old"), {})
    clock.t += 600
    broker.handle(n1("busy"), {})
    clock.t += 400                                                     # "old" idle 1000 s, "busy" 400 s
    broker.handle(n1("busy"), {})
    assert forgotten == ["old"] and list(broker._trace_seen) == ["busy"]


def test_the_idle_sweep_runs_at_most_once_a_minute():
    clock = Clock()
    broker, _ = burst_broker(clock)
    forgotten = []
    broker.modules.burst.forget = forgotten.append
    broker.handle(n1("a"), {})                                         # first message: sweep at t=1000
    clock.t += pipeline.TRACE_IDLE_SECONDS + 1
    broker.handle(n1("b"), {})                                         # sweep: "a" is idle
    assert forgotten == ["a"]
    broker.handle(n1("c"), {})
    clock.t += 30                                                      # "b" and "c" not idle; no sweep yet
    broker.handle(n1("d"), {})
    assert forgotten == ["a"]


def test_the_cap_drops_only_the_oldest(monkeypatch):
    monkeypatch.setattr(pipeline, "MAX_TRACKED_TRACES", 3)
    clock = Clock()
    broker, _ = burst_broker(clock)
    forgotten = []
    broker.modules.burst.forget = forgotten.append
    for trace in ("t1", "t2", "t3"):
        broker.handle(n1(trace), {})
        clock.t += 1
    broker.handle(n1("t1"), {})                                        # t1 seen again: now the newest
    broker.handle(n1("t4"), {})                                        # 4 traces: the least recent goes
    assert forgotten == ["t2"] and list(broker._trace_seen) == ["t3", "t1", "t4"]


def test_the_default_limits():
    assert (pipeline.TRACE_IDLE_SECONDS, pipeline.TRACE_SWEEP_INTERVAL_SECONDS,
            pipeline.MAX_TRACKED_TRACES) == (900, 60, 10_000)


# --- the real signed audit log (A4) --------------------------------------------------------------

@pytest.fixture
def real_audit(tmp_path):
    import broker.audit.log as real_log
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "keys" / "broker_signing.key"
    key_path.parent.mkdir()
    key_path.write_text(private_key_to_text(key) + "\n", encoding="utf-8")
    log_path = tmp_path / "logs" / "broker_audit.jsonl"
    yield key, key_path, log_path
    real_log.reset()                                                   # forget the configured log


def test_real_audit_log_verifies_and_a_one_byte_edit_fails_at_that_line(real_audit):
    from broker.audit.verify import verify_chain
    key, key_path, log_path = real_audit
    mods = Modules.with_real(["audit", "defence", "trust"])
    assert mods.status["append"] == mods.status["configure"] == "real"
    clock = Clock()
    broker = make(mods, clock)
    broker.start(signing_key_path=key_path, audit_log_path=log_path)

    assert broker.handle(n1(), {}).decision == "ALLOW"                # 1 decision
    assert broker.handle(None, {}).reason_code == "MALFORMED_JSON"     # 2 malformed message
    mods.evaluate_policy = deny_policy
    for _ in range(5):                                                 # 3-7 five denials, then the
        clock.t += 1                                                   # quarantine event (8)
        assert broker.handle(n1(), {}).decision == "DENY"
    assert broker.release("planner", "kissa")["state"] == "Restricted"  # 9 release

    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert [(r["kind"], r.get("decision")) for r in records] == (
        [("decision", "ALLOW"), ("decision", "DENY")] + [("decision", "DENY")] * 5
        + [("quarantine", None), ("release", None)])
    assert (records[7]["reason_code"], records[7]["by"], len(records[7]["denials"])) == (
        "DENIAL_RATE_EXCEEDED", "broker", 5)
    assert (records[8]["agent"], records[8]["by"]) == ("planner", "kissa")
    assert verify_chain(log_path, key.public_key()).ok

    data = bytearray(log_path.read_bytes())                            # bytes: no newline translation
    lines = data.split(b"\n")
    i = lines[2].index(b'"DENY"') + 4                                  # line 3: DENY -> DENX, one byte
    start = sum(len(line) + 1 for line in lines[:2])
    data[start + i] = ord("X")
    log_path.write_bytes(bytes(data))
    r = verify_chain(log_path, key.public_key())
    assert (r.ok, r.bad_line) == (False, 3)


# --- /admin/revoke and /admin/restore with the real revocation, registry, verifier and audit -------

def test_revoke_then_restore_leaves_old_tokens_stale_and_both_are_audited(real_audit, tmp_path):
    import importlib.util
    from pathlib import Path

    from fastapi.testclient import TestClient

    import broker.defence.revocation as revocation
    from broker.app import create_app
    from broker.audit.verify import verify_chain
    from broker.identity.client import make_proof
    from wrapper.credentials import FileCredentials

    key, key_path, log_path = real_audit
    script = Path(__file__).resolve().parents[2] / "scripts" / "issue_credentials.py"
    spec = importlib.util.spec_from_file_location("issue_credentials_for_revoke", script)
    issue = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(issue)
    keys = tmp_path / "run-keys"
    issue.write_set(keys, issue.credential_set(), force=False)
    planner = FileCredentials(keys / "planner.json")                    # its token has epoch 0

    mods = Modules.with_real(["identity", "policy", "defence", "audit"])
    assert all(mods.status[f] == "real" for f in ("verify_identity", "revoke", "restore", "append"))
    broker = Broker(mods, client=httpx.Client(transport=httpx.MockTransport(receiver)),
                    agent_urls={"database": "http://database.test"},
                    environ={"BROKER_KEYS_DIR": str(keys)})
    try:
        broker.start(signing_key_path=key_path, audit_log_path=log_path)
        client = TestClient(create_app(broker, environ={"BROKER_ADMIN_TOKEN": "admin-placeholder"}, start=False))
        client.headers["X-Admin-Token"] = "admin-placeholder"

        def send():
            env = new_request(sender="planner", receiver="database", action="db.query_aggregate",
                              resource="db:project_costs", payload={"metric": "sum", "column": "amount"},
                              chain_so_far=["user"])
            headers = {"Authorization": f"Bearer {planner.token}",
                       "X-Agent-Proof": make_proof(env, planner.token, planner.private_key)}
            return broker.handle(json.loads(env.model_dump_json()), headers)

        assert (send().decision, broker.recent_events(1)[0]["reason_code"]) == ("ALLOW", "POLICY_ALLOW")
        r = client.post("/admin/revoke", json={"agent": "planner", "by": "amna"})
        assert r.status_code == 200 and (r.json()["status"], r.json()["epoch"]) == ("revoked", 1)
        assert (send().decision, broker.recent_events(1)[0]["reason_code"]) == ("DENY", "STALE_EPOCH")
        r = client.post("/admin/restore", json={"agent": "planner", "by": "amna"})
        assert r.status_code == 200 and (r.json()["status"], r.json()["epoch"]) == ("active", 1)
        assert (send().decision, broker.recent_events(1)[0]["reason_code"]) == ("DENY", "STALE_EPOCH")

        lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        events = [(r["kind"], r.get("agent"), r.get("by")) for r in lines if r["kind"] != "decision"]
        assert events == [("revoke", "planner", "amna"), ("restore", "planner", "amna")]
        assert verify_chain(log_path, key.public_key()).ok
        api = client.get("/api/events").json()["events"]
        assert [e["kind"] for e in api if e["kind"] in ("revoke", "restore")] == ["restore", "revoke"]
    finally:
        revocation.set_registry(None)                                  # the module keeps one global registry
