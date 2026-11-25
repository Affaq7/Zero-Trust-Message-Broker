"""F2-A: the wrapper in MODE=broker (send path, broker refusals, /message, settings).

No network: the broker is an httpx.MockTransport. Credentials are issued into a temp
folder by scripts/issue_credentials.py; the real keys/ folder is never used."""

import importlib.util
import json
import sys
import types
from pathlib import Path

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from broker.identity.client import PROOF_TYP, envelope_hash, token_hash
from broker.identity.registry import AgentRegistry
from broker.identity.verify import IdentityVerifier
from contracts import Envelope, make_response, new_request
from contracts.payloads import ResponsePayload
from contracts.tokens import PROOF_HEADER, PROOF_STUB_VALUE
from wrapper.app import create_app
from wrapper.config import ConfigError, Settings, load_settings
from wrapper.credentials import FileCredentials
from wrapper.send import BrokerDecisionError, BrokerNotConfiguredError, send_message

REPO = Path(__file__).resolve().parents[2]
N1 = dict(receiver="database", action="db.query_aggregate", resource="db:project_costs",
          payload={"metric": "sum", "column": "amount", "filters": {"project": "Project X"}},
          chain_so_far=["user"])


@pytest.fixture
def keys(tmp_path):
    spec = importlib.util.spec_from_file_location("issue_credentials_t", REPO / "scripts" / "issue_credentials.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path / "run-keys"
    module.write_set(out, module.credential_set(), force=False)
    return out


def broker_env(keys, **over):
    env = {"MODE": "broker", "AGENT_NAME": "planner", "BROKER_URL": "http://broker.test",
           "AGENT_CREDENTIALS": "planner", "AGENT_KEYS_DIR": str(keys),
           "AGENT_URLS": "database=http://database.test"}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


class FakeBroker:
    """Records what reached it and answers like the broker: the receiver's reply with a decision."""

    def __init__(self, decision="ALLOW", reason="POLICY_ALLOW", payload=None, redacted=None):
        self.requests: list[httpx.Request] = []
        self.decision, self.reason, self.payload, self.redacted = decision, reason, payload, redacted

    def __call__(self, request):
        self.requests.append(request)
        env = Envelope.model_validate_json(request.content)
        reply = make_response(env, ResponsePayload(status="ok", result=1)).model_copy(update={
            "decision": self.decision, "reason_code": self.reason, "redacted_fields": self.redacted,
            **({"payload": self.payload} if self.payload is not None else {})})
        return httpx.Response(200, content=reply.model_dump_json())


def send(broker, environ, **kw):
    return send_message(token="stub-token-ignored-in-broker-mode", environ=environ,
                        client=httpx.Client(transport=httpx.MockTransport(broker)), **{**N1, **kw})


# --- send path --------------------------------------------------------------------------------

def test_broker_mode_sends_to_the_broker_with_token_and_a_real_proof(keys):
    broker = FakeBroker()
    reply = send(broker, broker_env(keys))
    assert reply.decision == "ALLOW"
    [req] = broker.requests
    assert str(req.url) == "http://broker.test/message"              # never the receiver's own URL
    env = Envelope.model_validate_json(req.content)
    creds = FileCredentials(keys / "planner.json")
    assert req.headers["authorization"] == f"Bearer {creds.token}"
    proof = req.headers[PROOF_HEADER]
    assert proof != PROOF_STUB_VALUE
    assert jwt.get_unverified_header(proof)["typ"] == PROOF_TYP
    claims = jwt.decode(proof, options={"verify_signature": False})
    assert claims["msg_hash"] == envelope_hash(env) and claims["ath"] == token_hash(creds.token)
    # Kissa's real verifier accepts exactly what the wrapper sent (token, proof, registry)
    result = IdentityVerifier(AgentRegistry.from_credentials_dir(keys)).verify(dict(req.headers), env)
    assert result.ok and result.agent == "planner" and result.instance_id == "planner-1"


@pytest.mark.parametrize("over, message", [
    ({"AGENT_CREDENTIALS": None}, "AGENT_CREDENTIALS"),               # stub credentials: never sent
    ({"AGENT_CREDENTIALS": "tool"}, "cannot load issued credentials"),  # someone else's file
    ({"AGENT_CREDENTIALS": "nobody"}, "cannot load issued credentials"),
    ({"BROKER_URL": None}, "BROKER_URL"),
])
def test_nothing_is_sent_without_credentials_or_broker_url(keys, over, message):
    broker = FakeBroker()
    with pytest.raises(BrokerNotConfiguredError, match=message):
        send(broker, broker_env(keys, **over))
    assert broker.requests == []


@pytest.mark.parametrize("decision, reason", [("DENY", "ROLE_NOT_ALLOWED"),
                                              ("QUARANTINE", "AGENT_QUARANTINED"),
                                              ("HITL", "HITL_PENDING")])
def test_broker_refusals_raise_a_send_error_with_the_decision(keys, decision, reason):
    broker = FakeBroker(decision, reason, payload={"status": "denied"})
    with pytest.raises(BrokerDecisionError) as info:
        send(broker, broker_env(keys))
    assert (info.value.decision, info.value.reason_code) == (decision, reason)
    assert str(info.value) == f"broker {decision}: {reason}"


def test_a_sanitized_reply_is_returned_normally(keys):
    reply = send(FakeBroker("SANITIZE", "REPLY_SANITIZED", redacted=["result.rows"]), broker_env(keys))
    assert reply.decision == "SANITIZE" and reply.redacted_fields == ["result.rows"]


def test_direct_mode_ignores_broker_settings(keys):
    """BROKER_URL and credentials set, MODE=direct: the request still goes straight to the receiver."""
    seen = []

    def receiver(request):
        seen.append(request)
        env = Envelope.model_validate_json(request.content)
        return httpx.Response(200, content=make_response(env, ResponsePayload(status="ok")).model_dump_json())

    send(receiver, broker_env(keys, MODE="direct"))
    [req] = seen
    assert str(req.url) == "http://database.test/message"
    assert req.headers[PROOF_HEADER] == PROOF_STUB_VALUE
    assert req.headers["authorization"] == "Bearer stub-token-ignored-in-broker-mode"


# --- settings ---------------------------------------------------------------------------------

def test_settings_read_broker_url_and_signature_flag():
    s = load_settings({"MODE": "broker", "AGENT_NAME": "planner", "BROKER_URL": "http://127.0.0.1:8100/",
                       "REQUIRE_BROKER_SIGNATURE": "1"})
    assert s.broker_url == "http://127.0.0.1:8100" and s.require_broker_signature is True
    assert load_settings({"MODE": "direct", "AGENT_NAME": "x"}).require_broker_signature is False
    with pytest.raises(ConfigError):
        load_settings({"MODE": "broker", "AGENT_NAME": "x", "BROKER_URL": "broker:8100"})
    with pytest.raises(ConfigError):
        load_settings({"MODE": "broker", "AGENT_NAME": "x", "REQUIRE_BROKER_SIGNATURE": "maybe"})


# --- /message in broker mode --------------------------------------------------------------------

def request_body():
    return new_request(sender="planner", receiver="dummy", action="db.query_aggregate",
                       resource="db:employees", payload={"metric": "count"},
                       chain_so_far=["user"]).model_dump_json()


FORWARD = "forward-placeholder-secret"     # the per-run broker forwarding secret (X-Broker-Token), a test value


def app_client(tmp_path, **settings):
    """A broker-mode agent, called as the broker calls it (with the forwarding token)."""
    c = TestClient(create_app(Settings(mode="broker", agent_name="dummy", log_dir=tmp_path,
                                       broker_forward_token=FORWARD, **settings)))
    c.headers["X-Broker-Token"] = FORWARD
    return c


def test_signature_check_off_by_default(tmp_path):
    r = app_client(tmp_path).post("/message", content=request_body())
    assert r.status_code == 200 and r.json()["msg_type"] == "response"


def test_signature_required_but_missing_or_unverifiable_is_refused(tmp_path, monkeypatch):
    monkeypatch.delitem(sys.modules, "broker.transport.signing", raising=False)
    client = app_client(tmp_path, require_broker_signature=True)
    assert client.post("/message", content=request_body()).status_code == 403
    r = client.post("/message", content=request_body(), headers={"X-Broker-Signature": "sig"})
    assert r.status_code == 403 and "not available" in r.json()["error"]     # A5 not on main: fail closed


@pytest.mark.parametrize("valid, status", [(True, 200), (False, 403)])
def test_signature_required_uses_the_a5_check_when_present(tmp_path, monkeypatch, valid, status):
    module = types.ModuleType("broker.transport.signing")
    module.verify_request_signature = lambda signature: valid and signature == "good"
    monkeypatch.setitem(sys.modules, "broker.transport.signing", module)
    client = app_client(tmp_path, require_broker_signature=True)
    r = client.post("/message", content=request_body(), headers={"X-Broker-Signature": "good"})
    assert r.status_code == status


def test_signature_flag_has_no_effect_in_direct_mode(tmp_path):
    client = TestClient(create_app(Settings(mode="direct", agent_name="dummy", log_dir=tmp_path,
                                            require_broker_signature=True)))
    assert client.post("/message", content=request_body()).status_code == 200


# --- the broker forwarding token (X-Broker-Token, A12) ---------------------------------------------

def test_a_request_that_did_not_come_through_the_broker_is_refused(tmp_path):
    agent = TestClient(create_app(Settings(mode="broker", agent_name="dummy", log_dir=tmp_path,
                                           broker_forward_token=FORWARD)))
    r = agent.post("/message", content=request_body())                      # straight to the agent port
    assert r.status_code == 401 and FORWARD not in r.text
    r = agent.post("/message", content=request_body(), headers={"X-Broker-Token": "wrong-placeholder"})
    assert r.status_code == 403 and FORWARD not in r.text
    assert not list(tmp_path.glob("*.jsonl"))                                  # nothing reached the agent
    assert agent.get("/health").status_code == 200                            # health stays open


def test_broker_mode_without_a_forwarding_token_refuses_everything(tmp_path):
    agent = TestClient(create_app(Settings(mode="broker", agent_name="dummy", log_dir=tmp_path)))
    r = agent.post("/message", content=request_body(), headers={"X-Broker-Token": "anything-placeholder"})
    assert r.status_code == 403 and "BROKER_FORWARD_TOKEN" in r.json()["error"]


def test_direct_mode_ignores_the_forwarding_token(tmp_path):
    agent = TestClient(create_app(Settings(mode="direct", agent_name="dummy", log_dir=tmp_path,
                                           broker_forward_token=FORWARD)))
    assert agent.post("/message", content=request_body()).status_code == 200


def test_forwarding_token_is_read_from_the_environment_and_not_shown():
    s = load_settings({"MODE": "broker", "AGENT_NAME": "x", "BROKER_FORWARD_TOKEN": FORWARD})
    assert s.broker_forward_token == FORWARD and FORWARD not in repr(s)


def test_the_same_request_forwarded_by_the_broker_succeeds(tmp_path):
    """A real Broker (stub modules) forwards to a real broker-mode wrapper and is accepted;
    the identical request sent straight to the wrapper is refused."""
    from broker.pipeline import Broker, Modules

    agent = TestClient(create_app(Settings(mode="broker", agent_name="dummy", log_dir=tmp_path,
                                           broker_forward_token=FORWARD)))

    def to_agent(request):
        r = agent.post("/message", content=request.content, headers=dict(request.headers))
        return httpx.Response(r.status_code, content=r.content)

    broker = Broker(Modules(), client=httpx.Client(transport=httpx.MockTransport(to_agent)),
                    agent_urls={"dummy": "http://dummy.test"}, environ={"BROKER_FORWARD_TOKEN": FORWARD})
    body = request_body()
    out = broker.handle(json.loads(body), {})
    assert (out.decision, out.payload["status"]) == ("ALLOW", "ok")
    assert agent.post("/message", content=body).status_code == 401           # around the broker: refused
