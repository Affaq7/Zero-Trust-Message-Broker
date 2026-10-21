"""Step 9: send_message() between wrapper apps, using in-process transports."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from agents.dummy import FIXED_TEXT
from contracts import Envelope, EnvelopeRuleError, make_response, new_request
from contracts.payloads import ResponsePayload
from contracts.tokens import PROOF_HEADER, PROOF_STUB_VALUE
from wrapper import registry
from wrapper.app import create_app
from wrapper.config import ConfigError, Settings, parse_agent_urls
from wrapper.send import (
    BadResponseError,
    BrokerModeNotImplementedError,
    ReceiverUnreachableError,
    UnknownReceiverError,
    send_message,
)

TOKEN = "STUB-TOKEN-MARKER-789"
URLS = "dummy=http://dummy.test,planner=http://planner.test,database=http://dummy.test"


def planner_env(**overrides):
    env = {"MODE": "direct", "AGENT_NAME": "planner", "AGENT_URLS": URLS}
    env.update(overrides)
    return env


class AppRouter(httpx.BaseTransport):
    """Routes each request to an in-process app by host, and records it."""

    def __init__(self, apps):
        self.clients = {host: TestClient(app) for host, app in apps.items()}
        self.requests: list[httpx.Request] = []

    def handle_request(self, request):
        self.requests.append(request)
        c = self.clients.get(request.url.host)
        if c is None:
            raise httpx.ConnectError("no such host", request=request)
        r = c.request(request.method, request.url.path,
                      content=request.read(), headers=dict(request.headers))
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)


def app(name, log_dir):
    return create_app(Settings(mode="direct", agent_name=name, log_dir=log_dir))


def read_log(log_dir, agent):
    path = log_dir / f"{agent}.jsonl"
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]


def send(client, **overrides):
    args = dict(receiver="dummy", action="db.query_aggregate", resource="db:sales",
                payload={"metric": "count"}, chain_so_far=["user"], token=TOKEN,
                environ=planner_env(), client=client)
    args.update(overrides)
    return send_message(**args)


def mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


# --- happy paths -------------------------------------------------------------

def test_planner_to_dummy(tmp_path):
    router = AppRouter({"dummy.test": app("dummy", tmp_path)})
    resp = send(httpx.Client(transport=router))

    assert resp.msg_type == "response"
    assert (resp.sender, resp.receiver) == ("dummy", "planner")
    assert resp.payload["result"] == {"text": FIXED_TEXT}

    sent = router.requests[0]
    assert str(sent.url) == "http://dummy.test/message"
    assert sent.headers["Authorization"] == f"Bearer {TOKEN}"
    assert sent.headers[PROOF_HEADER] == PROOF_STUB_VALUE

    request = Envelope.model_validate_json(sent.content)
    assert request.sender == "planner"                    # from AGENT_NAME
    assert request.delegation_chain == ["user", "planner"]
    assert resp.parent_msg_id == request.msg_id


def test_two_wrappers_chain_a_request(tmp_path, monkeypatch):
    # user -> planner wrapper; the planner agent forwards to the dummy wrapper.
    router = AppRouter({"dummy.test": app("dummy", tmp_path),
                        "planner.test": None})

    def planner_agent(env):
        reply = send_message(
            receiver="dummy", action="db.query_aggregate", resource="db:sales",
            payload={"metric": "count"}, chain_so_far=env.delegation_chain,
            trace_id=env.trace_id, token=TOKEN, environ=planner_env(),
            client=httpx.Client(transport=router),
        )
        return ResponsePayload(status="ok", result=reply.payload["result"])

    monkeypatch.setitem(registry.AGENTS, "planner", planner_agent)
    router.clients["planner.test"] = TestClient(app("planner", tmp_path))

    first = new_request(sender="user", receiver="planner", action="db.query_aggregate",
                        resource="db:sales", payload={"metric": "count"}, chain_so_far=[])
    r = httpx.Client(transport=router).post(
        "http://planner.test/message", content=first.model_dump_json(),
        headers={"Content-Type": "application/json"})

    final = Envelope.model_validate(r.json())
    assert final.payload["result"] == {"text": FIXED_TEXT}
    assert final.parent_msg_id == first.msg_id

    hop = read_log(tmp_path, "dummy")[0]["envelope"]
    assert hop["sender"] == "planner"
    assert hop["trace_id"] == first.trace_id               # one trace end to end
    assert hop["delegation_chain"] == ["user", "planner"]
    assert [rec["direction"] for rec in read_log(tmp_path, "planner")] == ["in", "out"]


def test_token_never_reaches_any_log(tmp_path):
    send(httpx.Client(transport=AppRouter({"dummy.test": app("dummy", tmp_path)})))
    for path in tmp_path.glob("*.jsonl"):
        assert TOKEN not in path.read_text(encoding="utf-8")


def test_mode_cannot_be_set_through_the_message(tmp_path):
    router = AppRouter({"dummy.test": app("dummy", tmp_path)})
    resp = send(httpx.Client(transport=router), payload={"MODE": "broker", "mode": "broker"})
    assert resp.payload["status"] == "ok"                   # still direct


# --- failures ------------------------------------------------------------------

def _never_called(request):
    raise AssertionError("no HTTP request expected")


def test_unknown_receiver():
    with pytest.raises(UnknownReceiverError):
        send(mock_client(_never_called), receiver="research")


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout])
def test_receiver_unreachable(error):
    def handler(request):
        raise error("down", request=request)
    with pytest.raises(ReceiverUnreachableError):
        send(mock_client(handler))


def test_unreachable_real_socket():
    # Nothing listens on port 1; real httpx client, short timeout.
    env = planner_env(AGENT_URLS="dummy=http://127.0.0.1:1")
    with pytest.raises(ReceiverUnreachableError):
        send(None, environ=env, timeout=2.0)


def _respond(status=200, body=b"", json_body=None):
    def handler(request):
        if json_body is not None:
            return httpx.Response(status, json=json_body(request))
        return httpx.Response(status, content=body)
    return handler


def _answer(request, **changes):
    env = Envelope.model_validate_json(request.content)
    data = make_response(env, ResponsePayload(status="ok")).model_dump(mode="json")
    data.update(changes)
    return data


@pytest.mark.parametrize("handler, status", [
    (_respond(500, b"Internal Server Error"), 500),
    (_respond(200, b"not json"), 200),
    (_respond(json_body=lambda r: {"hello": "world"}), 200),
    (_respond(json_body=lambda r: Envelope.model_validate_json(r.content).model_dump(mode="json")), 200),  # echoed request
    (_respond(json_body=lambda r: _answer(r, parent_msg_id="someone-else")), 200),
])
def test_bad_response(handler, status):
    with pytest.raises(BadResponseError) as info:
        send(mock_client(handler))
    assert info.value.status_code == status
    assert TOKEN not in str(info.value)


def test_wrapper_rejection_is_a_bad_response(tmp_path):
    # AGENT_URLS sends "database" to the dummy wrapper, which answers 400.
    router = AppRouter({"dummy.test": app("dummy", tmp_path)})
    with pytest.raises(BadResponseError) as info:
        send(httpx.Client(transport=router), receiver="database")
    assert info.value.status_code == 400


def test_broker_mode_not_implemented():
    with pytest.raises(BrokerModeNotImplementedError, match="not implemented"):
        send(mock_client(_never_called), environ=planner_env(MODE="broker"))


@pytest.mark.parametrize("env", [planner_env(MODE="bogus"), planner_env(AGENT_NAME="")])
def test_bad_environment_rejected(env):
    with pytest.raises(ConfigError):
        send(mock_client(_never_called), environ=env)


def test_rule_breaking_request_not_sent():
    with pytest.raises(EnvelopeRuleError):
        send(mock_client(_never_called), receiver="planner")   # planner -> planner


# --- AGENT_URLS ------------------------------------------------------------------

def test_parse_agent_urls():
    assert parse_agent_urls("") == {}
    assert parse_agent_urls(" dummy = http://127.0.0.1:8001/ , tool=https://tool:8443 ") == {
        "dummy": "http://127.0.0.1:8001", "tool": "https://tool:8443"}


@pytest.mark.parametrize("value", [
    "dummy", "=http://x", "dummy=", "dummy=ftp://x", "dummy=127.0.0.1:8001",
    "dummy=http://a,dummy=http://b",
])
def test_bad_agent_urls_rejected(value):
    with pytest.raises(ConfigError):
        parse_agent_urls(value)
