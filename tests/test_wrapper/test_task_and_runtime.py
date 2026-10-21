"""M2 step 7: POST /task, AGENT_IMPL and per-agent stub tokens."""

import json
from uuid import UUID

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from agents.base import TaskResult
from agents.dummy import FIXED_TEXT
from contracts.tokens import BROKER_ISSUER, TokenClaims, algorithm_allowed
from wrapper import registry
from wrapper.app import create_app
from wrapper.config import ConfigError, Settings, load_settings
from wrapper.credentials import LIFETIME_SECONDS, REFRESH_MARGIN_SECONDS, StubCredentials
from wrapper.runtime import NoRoleError, current_runtime
from wrapper.send import send_message


def client(tmp_path, name="dummy", **kw):
    return TestClient(create_app(Settings(mode="direct", agent_name=name, log_dir=tmp_path, **kw)))


def claims(token):
    return TokenClaims.model_validate(jwt.decode(token, options={"verify_signature": False}))


# --- /task -------------------------------------------------------------------------

def test_task_returns_answer_and_new_trace_id(tmp_path):
    r = client(tmp_path).post("/task", json={"task": "say hello"})
    assert r.status_code == 200
    body = r.json()
    assert body == {"trace_id": body["trace_id"], "status": "ok", "answer": FIXED_TEXT, "error": None}
    assert UUID(body["trace_id"]).version == 4


def test_task_passes_trace_id_and_chain_through(tmp_path, monkeypatch):
    seen = {}

    def handler(ctx):
        seen.update(ctx.model_dump())
        return TaskResult(status="ok", answer="done")

    monkeypatch.setitem(registry.TASKS, "dummy", handler)
    r = client(tmp_path).post("/task", json={"task": "total cost of Project X", "trace_id": "trace-7"})
    assert r.json()["trace_id"] == "trace-7"
    assert seen == {"task": "total cost of Project X", "trace_id": "trace-7", "chain_so_far": ["user"]}


@pytest.mark.parametrize("body", [
    {"task": "x", "scenario_label": "A3"},
    {"task": "x", "expected_decision": "DENY"},
    {"task": "x", "trust_score": 0.2},
    {"task": "x", "mode": "broker"},
    {"task": ""},
    {"task": "x" * 4001},
    {"task": "x", "trace_id": "t" * 129},
    {},
])
def test_task_rejects_labels_and_bad_input(tmp_path, body):
    r = client(tmp_path).post("/task", json=body)
    assert r.status_code == 422
    assert "A3" not in r.text and "DENY" not in r.text       # input not echoed


def test_task_rejects_non_json(tmp_path):
    assert client(tmp_path).post("/task", content=b"not json").status_code == 422


def test_agent_without_task_handler(tmp_path, monkeypatch):
    monkeypatch.delitem(registry.TASKS, "dummy")
    assert client(tmp_path).post("/task", json={"task": "x"}).status_code == 404


def test_task_crash_becomes_error(tmp_path, monkeypatch):
    def boom(ctx):
        raise ValueError("crash")
    monkeypatch.setitem(registry.TASKS, "dummy", boom)
    body = client(tmp_path).post("/task", json={"task": "x"}).json()
    assert body["status"] == "error" and body["error"] == "agent failed: ValueError"


def test_task_writes_nothing_to_the_message_log(tmp_path):
    client(tmp_path).post("/task", json={"task": "x"})
    assert not (tmp_path / "dummy.jsonl").exists()


# --- AGENT_IMPL -------------------------------------------------------------------------

def test_impl_defaults_to_name():
    s = load_settings({"MODE": "direct", "AGENT_NAME": "dummy"})
    assert s.impl == "dummy" and s.agent_impl is None


def test_impostor_runs_under_victim_name(tmp_path):
    # AGENT_NAME=research with the dummy code standing in for the malicious impl.
    s = load_settings({"MODE": "direct", "AGENT_NAME": "research", "AGENT_IMPL": "dummy",
                       "LOG_DIR": str(tmp_path)})
    c = TestClient(create_app(s))
    env = {"schema_version": "0.2", "msg_id": "m-1", "trace_id": "t-1", "parent_msg_id": None,
           "msg_type": "request", "sender": "planner", "receiver": "research",
           "action": "web.fetch_page", "resource": "https://x", "payload": {},
           "delegation_chain": ["user", "planner"], "timestamp": "2026-10-21T10:00:00Z"}
    r = c.post("/message", content=json.dumps(env), headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert r.json()["sender"] == "research"
    assert (tmp_path / "research.jsonl").exists()           # logs under the victim's name
    assert c.get("/health").json()["agent"] == "research"


def test_unknown_impl_fails_at_startup(tmp_path):
    with pytest.raises(ConfigError):
        create_app(Settings(mode="direct", agent_name="research", agent_impl="nobody", log_dir=tmp_path))


# --- roles and stub tokens --------------------------------------------------------------

def _runtime_inside_task(tmp_path, monkeypatch, **settings):
    seen = {}

    def handler(ctx):
        rt = current_runtime()
        seen["rt"] = rt
        seen["tokens"] = (rt.token_for("database"), rt.token_for("database"), rt.token_for("tool"))
        return TaskResult(status="ok", answer="x")

    monkeypatch.setitem(registry.TASKS, settings.get("agent_impl") or settings["name"], handler)
    name = settings.pop("name")
    body = client(tmp_path, name=name, **settings).post("/task", json={"task": "x"}).json()
    assert body["status"] == "ok", body
    return seen


def test_runtime_tokens_per_receiver(tmp_path, monkeypatch):
    monkeypatch.setitem(registry.AGENTS, "planner", lambda env: None)
    seen = _runtime_inside_task(tmp_path, monkeypatch, name="planner")
    rt, (db1, db2, tool) = seen["rt"], seen["tokens"]
    assert (rt.agent_name, rt.role) == ("planner", "planner")
    assert db1 == db2                                        # cached
    assert db1 != tool
    c_db, c_tool = claims(db1), claims(tool)
    assert (c_db.sub, c_db.role, c_db.aud) == ("planner", "planner", "database")
    assert c_tool.aud == "tool"
    assert c_db.cnf.jkt == c_tool.cnf.jkt                   # one key per process
    assert c_db.iss == c_tool.iss == BROKER_ISSUER          # agreed issuer (S9)
    assert algorithm_allowed(db1)


def test_impostor_gets_victims_identity(tmp_path, monkeypatch):
    seen = _runtime_inside_task(tmp_path, monkeypatch, name="research", agent_impl="dummy")
    assert claims(seen["tokens"][0]).sub == "research"
    assert claims(seen["tokens"][0]).role == "research"


def test_malicious_needs_explicit_role(tmp_path, monkeypatch):
    monkeypatch.setitem(registry.AGENTS, "malicious", lambda env: None)
    seen = _runtime_inside_task(tmp_path, monkeypatch, name="malicious", agent_role="research")
    assert (claims(seen["tokens"][0]).sub, claims(seen["tokens"][0]).role) == ("malicious", "research")


def test_no_role_means_no_token(tmp_path, monkeypatch):
    def handler(ctx):
        current_runtime().token_for("tool")
    monkeypatch.setitem(registry.TASKS, "dummy", handler)
    body = client(tmp_path).post("/task", json={"task": "x"}).json()
    assert body == {"trace_id": body["trace_id"], "status": "error", "answer": None,
                    "error": "agent failed: NoRoleError"}


def test_runtime_not_available_outside_agent_calls():
    with pytest.raises(RuntimeError):
        current_runtime()


def test_token_refreshed_before_expiry():
    creds = StubCredentials("planner", "planner")
    first = creds.token_for("tool", now=1_000_000)
    assert creds.token_for("tool", now=1_000_000 + LIFETIME_SECONDS - REFRESH_MARGIN_SECONDS - 1) == first
    later = creds.token_for("tool", now=1_000_000 + LIFETIME_SECONDS - REFRESH_MARGIN_SECONDS)
    assert later != first and claims(later).iat == 1_000_000 + LIFETIME_SECONDS - REFRESH_MARGIN_SECONDS


def test_bad_role_rejected_when_minting():
    with pytest.raises(Exception):
        StubCredentials("x", "admin").token_for("tool")


# --- end to end: task -> send_message with the runtime token --------------------------

def test_task_sends_with_runtime_token(tmp_path, monkeypatch):
    dummy_app = create_app(Settings(mode="direct", agent_name="dummy", log_dir=tmp_path))
    dummy = TestClient(dummy_app)
    sent = []

    def route(request):
        sent.append(request)
        r = dummy.request(request.method, request.url.path, content=request.read(),
                          headers=dict(request.headers))
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)

    def planner_task(ctx):
        rt = current_runtime()
        reply = send_message(
            receiver="dummy", action="db.query_aggregate", resource="db:payroll",
            payload={"metric": "count"}, chain_so_far=ctx.chain_so_far, trace_id=ctx.trace_id,
            token=rt.token_for("dummy"),
            environ={"MODE": "direct", "AGENT_NAME": rt.agent_name, "AGENT_URLS": "dummy=http://dummy.test"},
            client=httpx.Client(transport=httpx.MockTransport(route)))
        return TaskResult(status="ok", answer=reply.payload["result"]["text"])

    monkeypatch.setitem(registry.AGENTS, "planner", lambda env: None)
    monkeypatch.setitem(registry.TASKS, "planner", planner_task)
    body = client(tmp_path, name="planner").post("/task", json={"task": "x", "trace_id": "tr-1"}).json()
    assert body["answer"] == FIXED_TEXT
    token = sent[0].headers["Authorization"].removeprefix("Bearer ")
    assert (claims(token).sub, claims(token).aud) == ("planner", "dummy")
    assert token not in (tmp_path / "dummy.jsonl").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "dummy.jsonl").read_text(encoding="utf-8").splitlines()[0])["envelope"]["trace_id"] == "tr-1"
