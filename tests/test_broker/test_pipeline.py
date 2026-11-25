"""F1: broker app and the ten-step pipeline, with stubs. No live model, no network:
receivers are httpx.MockTransport handlers and the app runs in a TestClient."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from broker import stubs
from broker.app import create_app
from broker.identity.verify import IdentityResult
from broker.pipeline import REAL_MODULES, Broker, Modules
from broker.policy.engine import PolicyResult
from broker.trust.trust import TrustState
from contracts import Envelope, new_request
from contracts.envelope import make_response
from contracts.payloads import ResponsePayload

N1_PAYLOAD = {"metric": "sum", "column": "amount", "filters": {"project": "Project X"}}
HEADERS = {"Authorization": "Bearer stub-token-for-tests", "X-Agent-Proof": "PROOF-STUB-NOT-IMPLEMENTED"}


def n1_request(**kw) -> Envelope:
    args = dict(sender="planner", receiver="database", action="db.query_aggregate",
                resource="db:project_costs", payload=N1_PAYLOAD, chain_so_far=["user"])
    args.update(kw)
    return new_request(**args)


def raw(env: Envelope) -> dict:
    return json.loads(env.model_dump_json())


class Receiver:
    """A fake receiving wrapper: answers every request with an ok response envelope."""

    def __init__(self, result=None, status_code=200, body=None, fail=False):
        self.calls: list[httpx.Request] = []
        self.result = {"rows": [{"value": 184250}]} if result is None else result
        self.status_code, self.body, self.fail = status_code, body, fail

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.fail:
            raise httpx.ConnectError("refused", request=request)
        if self.body is not None:
            return httpx.Response(self.status_code, content=self.body)
        env = Envelope.model_validate_json(request.content)
        reply = make_response(env, ResponsePayload(status="ok", result=self.result))
        return httpx.Response(self.status_code, content=reply.model_dump_json())

    @property
    def forwarded(self) -> list[Envelope]:
        return [Envelope.model_validate_json(c.content) for c in self.calls]


def make_broker(modules: Modules | None = None, receiver: Receiver | None = None):
    receiver = receiver or Receiver()
    broker = Broker(modules or Modules(), client=httpx.Client(transport=httpx.MockTransport(receiver)),
                    agent_urls={"database": "http://database.test", "mailer": "http://mailer.test",
                                "tool": "http://tool.test"})
    return broker, receiver


def last_event(broker: Broker) -> dict:
    return broker.recent_events(1)[0]


# --- the normal path -------------------------------------------------------------------------

def test_n1_passes_all_ten_steps_and_is_forwarded_once():
    broker, receiver = make_broker()
    req = n1_request()
    out = broker.handle(raw(req), HEADERS)

    assert len(receiver.calls) == 1
    [fwd] = receiver.forwarded
    assert fwd == req                                     # forwarded unchanged, no broker fields
    assert "authorization" not in {k.lower() for k in receiver.calls[0].headers}   # token stays at the broker
    assert out.msg_type == "response" and out.parent_msg_id == req.msg_id
    assert (out.sender, out.receiver) == ("database", "planner")
    assert out.payload["status"] == "ok" and out.payload["result"] == {"rows": [{"value": 184250}]}
    assert (out.decision, out.reason_code, out.redacted_fields) == ("ALLOW", "POLICY_ALLOW", None)
    assert out.broker_signature and out.broker_signature.startswith("STUB-SIG-")
    ev = last_event(broker)
    assert ev["step"] == 9 and ev["forwarded"] is True and ev["decision"] == "ALLOW" and ev["entry_hash"]
    assert "payload" not in ev                             # never payloads in events or audit
    assert broker.modules.trust.updates == [{"agent": "planner", "decision": "ALLOW",
                                             "injection_cue": False, "events": []}]
    assert [d[:2] for d in broker.modules.defence.decisions] == [("planner", "ALLOW")]


def test_reply_is_accepted_by_the_agent_side_send_message():
    """End to end through the app: wrapper.send.send_message() accepts the broker's reply."""
    from wrapper.send import send_message
    broker, receiver = make_broker()
    client = TestClient(create_app(broker))
    environ = {"MODE": "direct", "AGENT_NAME": "planner", "AGENT_URLS": "database=http://testserver"}
    reply = send_message(receiver="database", action="db.query_aggregate", resource="db:project_costs",
                         payload=N1_PAYLOAD, chain_so_far=["user"], token="stub-token-for-tests",
                         environ=environ, client=client)
    assert reply.decision == "ALLOW" and reply.payload["status"] == "ok" and len(receiver.calls) == 1


# --- hard gates (steps 1 to 4) ---------------------------------------------------------------

def _fail_validate(raw_):
    return stubs.ValidationResult(ok=False, reason_code="STALE_MESSAGE", env=None, injection_cue=False)


def _fail_identity(headers, env):
    return IdentityResult(ok=False, agent=None, role=None, instance_id=None, epoch=None,
                          reason_code="TOKEN_EXPIRED")


def _deny_policy(env, identity):
    return PolicyResult(verdict="DENY", action_class="Permitted", reason_code="ROLE_NOT_ALLOWED",
                        needs_human=False)


def _blocked_defence():
    d = stubs.DefenceManager()
    d.revoke("planner")
    return d


@pytest.mark.parametrize("step, override, decision, reason, trust_updates", [
    (1, {"validate_envelope": _fail_validate}, "DENY", "STALE_MESSAGE", 0),
    (2, {"verify_identity": _fail_identity}, "DENY", "TOKEN_EXPIRED", 0),
    (3, {"defence": _blocked_defence()}, "QUARANTINE", "AGENT_QUARANTINED", 0),
    (4, {"evaluate_policy": _deny_policy}, "DENY", "ROLE_NOT_ALLOWED", 1),
])
def test_each_hard_gate_stops_the_message_before_forwarding(step, override, decision, reason, trust_updates):
    broker, receiver = make_broker(Modules(**override))
    req = n1_request()
    out = broker.handle(raw(req), HEADERS)
    assert receiver.calls == []
    assert (out.decision, out.reason_code, out.payload) == (decision, reason, {"status": "denied"})
    assert out.msg_type == "response" and out.parent_msg_id == req.msg_id and out.receiver == "planner"
    assert out.broker_signature
    ev = last_event(broker)
    assert (ev["step"], ev["decision"], ev["reason_code"], ev["forwarded"]) == (step, decision, reason, False)
    assert len(broker.modules.trust.updates) == trust_updates   # unverified senders never touch trust


def test_trust_lowers_allow_to_deny_but_never_raises_a_deny():
    class LowTrust(stubs.TrustEngine):
        def get(self, agent):
            return TrustState(agent=agent, T=0.3, state="Restricted")

    broker, receiver = make_broker(Modules(trust=LowTrust(), required_trust=lambda c, r: 0.8))
    out = broker.handle(raw(n1_request()), HEADERS)
    assert (out.decision, out.reason_code) == ("DENY", "TRUST_TOO_LOW") and receiver.calls == []

    broker, receiver = make_broker(Modules(evaluate_policy=_deny_policy))   # T = 1.0, policy DENY
    out = broker.handle(raw(n1_request()), HEADERS)
    assert (out.decision, out.reason_code) == ("DENY", "ROLE_NOT_ALLOWED") and receiver.calls == []


def test_request_content_check_can_deny_and_can_add_a_trust_event():
    broker, receiver = make_broker(Modules(check_request_content=lambda env: (False, "RECIPIENT_NOT_APPROVED")))
    out = broker.handle(raw(n1_request()), HEADERS)
    assert (out.decision, out.reason_code) == ("DENY", "RECIPIENT_NOT_APPROVED") and receiver.calls == []

    broker, receiver = make_broker(Modules(check_request_content=lambda env: (True, "INDIVIDUAL_DATA_REQUEST")))
    out = broker.handle(raw(n1_request()), HEADERS)
    assert out.decision == "ALLOW" and len(receiver.calls) == 1
    assert broker.modules.trust.updates[-1]["events"] == ["INDIVIDUAL_DATA_REQUEST"]


def test_request_cue_and_burst_events_reach_the_trust_engine():
    def cue_validate(raw_):
        v = stubs.validate_envelope(raw_)
        return v.model_copy(update={"injection_cue": True})

    class Burst:
        def observe(self, sender, trace_id):
            return ("BURST_DETECTED",)

    broker, _ = make_broker(Modules(validate_envelope=cue_validate, burst=Burst()))
    out = broker.handle(raw(n1_request()), HEADERS)
    assert out.decision == "ALLOW"                              # events never decide on their own
    [update] = broker.modules.trust.updates
    assert update["injection_cue"] is True and update["events"] == ["INJECTION_CUE", "BURST_DETECTED"]


# --- quarantine ---------------------------------------------------------------------------------

def test_quarantine_path_and_release():
    broker, receiver = make_broker()
    client = TestClient(create_app(broker))
    broker.modules.defence.revoke("planner")
    r = client.post("/message", json=raw(n1_request()))
    assert r.status_code == 200 and r.json()["decision"] == "QUARANTINE"
    assert r.json()["reason_code"] == "AGENT_QUARANTINED" and receiver.calls == []
    assert {a["agent"]: a["blocked"] for a in client.get("/api/state").json()["agents"]}["planner"] is True

    r = client.post("/admin/release", json={"agent": "planner", "reviewer": "afaq"})
    assert r.status_code == 200 and r.json()["released_by"] == "afaq"
    assert broker.modules.trust.releases == [("planner", "afaq")]
    r = client.post("/message", json=raw(n1_request()))
    assert r.json()["decision"] == "ALLOW" and len(receiver.calls) == 1
    assert client.post("/admin/release", json={"agent": "planner", "reviewer": ""}).status_code == 422


def test_a_denial_that_trips_the_denial_rate_becomes_quarantine():
    class V1(stubs.DefenceManager):              # blocks on the second DENY
        def record_decision(self, agent, decision, ts):
            super().record_decision(agent, decision, ts)
            if sum(1 for a, d, _ in self.decisions if a == agent and d == "DENY") >= 2:
                self.blocked.add(agent)

    broker, receiver = make_broker(Modules(defence=V1(), evaluate_policy=_deny_policy))
    first = broker.handle(raw(n1_request()), HEADERS)
    second = broker.handle(raw(n1_request()), HEADERS)
    third = broker.handle(raw(n1_request()), HEADERS)
    assert (first.decision, first.reason_code) == ("DENY", "ROLE_NOT_ALLOWED")
    assert (second.decision, second.reason_code) == ("QUARANTINE", "DENIAL_RATE_EXCEEDED")
    assert (third.decision, third.reason_code) == ("QUARANTINE", "AGENT_QUARANTINED")
    assert receiver.calls == []


def test_a_trust_quarantined_agent_is_stopped_at_step_3():
    class Quarantined(stubs.TrustEngine):
        def get(self, agent):
            return TrustState(agent=agent, T=0.2, state="Quarantined")

    broker, receiver = make_broker(Modules(trust=Quarantined()))
    out = broker.handle(raw(n1_request()), HEADERS)
    assert (out.decision, out.reason_code) == ("QUARANTINE", "AGENT_QUARANTINED") and receiver.calls == []


# --- HITL -----------------------------------------------------------------------------------------

def test_needs_human_gives_hitl_and_a_pending_approval():
    def needs_human(env, identity):
        return PolicyResult(verdict="ALLOW", action_class="Conditional", reason_code="NEEDS_APPROVAL",
                            needs_human=True)

    broker, receiver = make_broker(Modules(evaluate_policy=needs_human))
    req = n1_request(receiver="tool", action="tool.send_email_external", resource="email:external",
                     payload={"to": ["x@example.test"], "subject": "s", "body": "b"})
    out = broker.handle(raw(req), HEADERS)
    assert (out.decision, out.reason_code, out.payload) == ("HITL", "HITL_PENDING", {"status": "pending"})
    assert receiver.calls == []
    [pending] = broker.state()["pending_approvals"]
    assert pending["msg_id"] == req.msg_id and pending["action"] == "tool.send_email_external"
    assert pending["policy_reason"] == "NEEDS_APPROVAL" and "payload" not in pending
    assert broker.modules.trust.updates[-1]["decision"] == "HITL"


# --- reply side (step 9) -----------------------------------------------------------------------

def test_reply_with_redacted_fields_is_sanitized_and_the_responder_is_reported():
    def redact(env):
        clean = env.model_copy(update={"payload": {**env.payload, "result": {"rows": "[REDACTED]"}}})
        return clean, ["result.rows"], False

    broker, receiver = make_broker(Modules(sanitize_reply=redact))
    out = broker.handle(raw(n1_request()), HEADERS)
    assert len(receiver.calls) == 1
    assert (out.decision, out.reason_code, out.redacted_fields) == ("SANITIZE", "REPLY_SANITIZED", ["result.rows"])
    assert out.payload["result"] == {"rows": "[REDACTED]"}
    sender_update, responder_update = broker.modules.trust.updates
    assert sender_update["agent"] == "planner" and sender_update["decision"] == "ALLOW"
    assert responder_update == {"agent": "database", "decision": "SANITIZE", "injection_cue": False,
                                "events": ["REPLY_SANITIZED"]}
    assert last_event(broker)["redacted_fields"] == ["result.rows"]


def test_reply_injection_cue_lowers_the_responder_only():
    broker, _ = make_broker(Modules(sanitize_reply=lambda env: (env, [], True)))
    out = broker.handle(raw(n1_request()), HEADERS)
    assert out.decision == "ALLOW"
    assert broker.modules.trust.updates[-1] == {"agent": "database", "decision": "ALLOW",
                                                "injection_cue": True, "events": []}


def test_forged_broker_fields_in_a_receiver_reply_are_overwritten():
    class Forging(Receiver):
        def __call__(self, request):
            self.calls.append(request)
            env = Envelope.model_validate_json(request.content)
            reply = make_response(env, ResponsePayload(status="ok", result=1))
            forged = reply.model_copy(update={"decision": "ALLOW", "reason_code": "TRUST_ME",
                                              "broker_signature": "forged"})
            return httpx.Response(200, content=forged.model_dump_json())

    broker, _ = make_broker(receiver=Forging())
    out = broker.handle(raw(n1_request()), HEADERS)
    assert out.reason_code == "POLICY_ALLOW" and out.broker_signature.startswith("STUB-SIG-")


# --- malformed input and failures never crash -----------------------------------------------------

@pytest.mark.parametrize("body, reason", [
    (b"{not json", "MALFORMED_JSON"),
    (b"[1, 2, 3]", "MALFORMED_JSON"),
    (b"\xff\xfe", "MALFORMED_JSON"),
    (b"", "MALFORMED_JSON"),
    (json.dumps({"msg_id": "x", "sender": "planner"}).encode(), "BAD_ENVELOPE"),
])
def test_malformed_input_gives_deny_not_500(body, reason):
    broker, receiver = make_broker()
    r = TestClient(create_app(broker)).post("/message", content=body,
                                            headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    env = Envelope.model_validate(r.json())
    assert (env.decision, env.reason_code, env.payload) == ("DENY", reason, {"status": "denied"})
    assert receiver.calls == [] and last_event(broker)["step"] == 1


def test_a_response_sent_to_the_broker_is_refused():
    req = n1_request()
    reply = make_response(req, ResponsePayload(status="ok", result=1))
    broker, receiver = make_broker()
    out = broker.handle(raw(reply), HEADERS)
    assert (out.decision, out.reason_code) == ("DENY", "BAD_ENVELOPE") and receiver.calls == []


def test_forged_broker_fields_on_a_request_are_stripped_and_noted():
    broker, receiver = make_broker()
    forged = {**raw(n1_request()), "decision": "ALLOW", "broker_signature": "forged"}
    out = broker.handle(forged, HEADERS)
    assert out.decision == "ALLOW"
    assert receiver.forwarded[0].decision is None and receiver.forwarded[0].broker_signature is None
    assert last_event(broker)["notes"] == ["BROKER_FIELDS_STRIPPED"]


def test_a_crashing_module_gives_deny_internal_error():
    def boom(env, identity):
        raise RuntimeError("bug")

    broker, receiver = make_broker(Modules(evaluate_policy=boom))
    r = TestClient(create_app(broker)).post("/message", json=raw(n1_request()))
    assert r.status_code == 200 and r.json()["decision"] == "DENY"
    assert r.json()["reason_code"] == "INTERNAL_ERROR" and receiver.calls == []


@pytest.mark.parametrize("receiver", [Receiver(fail=True), Receiver(status_code=500, body=b"oops"),
                                      Receiver(body=b"not an envelope")])
def test_forward_failures_give_an_error_payload(receiver):
    broker, _ = make_broker(receiver=receiver)
    req = n1_request()
    out = broker.handle(raw(req), HEADERS)
    assert out.reason_code == "FORWARD_FAILED" and out.parent_msg_id == req.msg_id
    assert out.payload["status"] == "error" and "denied" not in out.payload["status"]
    assert last_event(broker)["forwarded"] is False


def test_unknown_receiver_url_is_a_forward_failure():
    broker = Broker(Modules(), client=httpx.Client(transport=httpx.MockTransport(Receiver())), agent_urls={})
    assert broker.handle(raw(n1_request()), HEADERS).reason_code == "FORWARD_FAILED"


# --- module registry --------------------------------------------------------------------------------

def test_default_modules_are_all_stubs_and_broker_real_switches_and_ignores():
    assert set(Modules().status.values()) == {"stub"} and set(Modules().status) == set(REAL_MODULES)
    mods = Modules.from_env({"BROKER_REAL": "risk, trust, burst, validate, nonsense"})
    assert {n for n, s in mods.status.items() if s == "real"} == {"risk", "trust", "burst"}
    assert set(mods.ignored) == {"validate", "nonsense"}
    assert "does not exist" in mods.ignored["validate"]


def test_n1_passes_with_the_real_risk_and_trust_modules():
    broker, receiver = make_broker(Modules.with_real(["risk", "trust", "burst"]))
    out = broker.handle(raw(n1_request()), HEADERS)
    assert out.decision == "ALLOW" and len(receiver.calls) == 1
    assert broker.modules.trust.get("planner").state == "Active"


# --- read-only API shapes ------------------------------------------------------------------------------

def test_health_state_and_events_shapes():
    broker, _ = make_broker(Modules.with_real(["risk", "validate"]))
    client = TestClient(create_app(broker))
    client.post("/message", json=raw(n1_request()))
    client.post("/message", content=b"{bad")

    health = client.get("/health").json()
    assert health["status"] == "ok" and health["service"] == "broker"
    assert health["real"] == ["risk"] and "identity" in health["stubbed"] and "validate" in health["ignored"]
    assert set(health["modules"]) == set(REAL_MODULES)

    state = client.get("/api/state").json()
    assert set(state) == {"counters", "agents", "pending_approvals"}
    c = state["counters"]
    assert c["messages"] == 2 and c["forwarded"] == 1 and c["pending_approvals"] == 0
    assert c["decisions"] == {"ALLOW": 1, "SANITIZE": 0, "HITL": 0, "DENY": 1, "QUARANTINE": 0}
    planner = next(a for a in state["agents"] if a["agent"] == "planner")
    assert set(planner) == {"agent", "T", "state", "epoch", "blocked"}
    assert (planner["T"], planner["state"], planner["epoch"], planner["blocked"]) == (1.0, "Active", 0, False)

    events = client.get("/api/events").json()["events"]
    assert [e["reason_code"] for e in events] == ["MALFORMED_JSON", "POLICY_ALLOW"]   # newest first
    keys = {"ts", "msg_id", "trace_id", "sender", "receiver", "action", "step", "decision", "reason_code",
            "events", "notes", "redacted_fields", "forwarded", "entry_hash"}
    assert keys <= set(events[0]) and "payload" not in events[0]
    assert client.get("/api/events?limit=1").json()["events"][0]["reason_code"] == "MALFORMED_JSON"
