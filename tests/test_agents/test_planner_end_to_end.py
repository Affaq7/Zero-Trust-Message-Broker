"""M2 step 11: planner -> database and planner -> tool through real wrappers."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import agents.database as database_module
import agents.planner as planner_module
import agents.tool as tool_module
from agents.database import DatabaseAgent
from agents.planner import PlannerAgent
from agents.tool import ToolAgent
from mocks.seed import NAMES
from wrapper.app import create_app
from wrapper.config import Settings
from wrapper.runtime import current_runtime
from wrapper.send import send_message

URLS = "database=http://database.test,tool=http://tool.test"


def router(apps):
    clients = {host: TestClient(app) for host, app in apps.items()}

    def route(request):
        c = clients[request.url.host]
        r = c.request(request.method, request.url.path, content=request.read(),
                      headers=dict(request.headers))
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)
    return httpx.Client(transport=httpx.MockTransport(route))


@pytest.fixture
def testbed(tmp_path, fake_llm, mocks_client, monkeypatch):
    """Planner, database and tool wrappers wired together in-process."""
    def _build(planner_replies, database_replies=(), tool_replies=()):
        monkeypatch.setattr(database_module, "_default",
                            DatabaseAgent(fake_llm("database", {"database.summarise": list(database_replies)}), mocks_client))
        monkeypatch.setattr(tool_module, "_default",
                            ToolAgent(fake_llm("tool", {"tool.compose_email": list(tool_replies)}), mocks_client))
        apps = {f"{name}.test": create_app(Settings(mode="direct", agent_name=name, log_dir=tmp_path))
                for name in ("database", "tool")}
        http = router(apps)
        env = {"MODE": "direct", "AGENT_NAME": "planner", "AGENT_URLS": URLS}

        def send(**kwargs):
            token = current_runtime().token_for(kwargs["receiver"])
            return send_message(token=token, environ=env, client=http, **kwargs)

        monkeypatch.setattr(planner_module, "_default",
                            PlannerAgent(fake_llm("planner", {"planner.decide": list(planner_replies)}), send))
        return TestClient(create_app(Settings(mode="direct", agent_name="planner", log_dir=tmp_path)))
    return _build


def log(tmp_path, agent):
    return [json.loads(l) for l in (tmp_path / f"{agent}.jsonl").read_text(encoding="utf-8").splitlines()]


COUNT = {"done": False, "action": "db.query_aggregate", "resource": "db:employees",
         "payload": {"metric": "count"}, "reason": "count people"}
SUMMARY = {"summary": "There are 20 employees."}


def test_planner_to_database(testbed, tmp_path, truth):
    planner = testbed([COUNT, {"done": True, "answer": "20 employees."}], database_replies=[SUMMARY])
    body = planner.post("/task", json={"task": "How many employees?", "trace_id": "trace-e2e-db"}).json()
    assert body == {"trace_id": "trace-e2e-db", "status": "ok", "answer": "20 employees.", "error": None}

    records = log(tmp_path, "database")
    assert [r["direction"] for r in records] == ["in", "out"]
    request, response = records[0]["envelope"], records[1]["envelope"]
    assert (request["sender"], request["action"], request["trace_id"]) == ("planner", "db.query_aggregate", "trace-e2e-db")
    assert request["delegation_chain"] == ["user", "planner"]
    assert response["payload"]["result"]["rows"] == [{"value": len(NAMES)}]
    assert truth(trace_id="trace-e2e-db", kind="db.query")[0]["details"]["action"] == "db.query_aggregate"


def test_planner_to_tool(testbed, tmp_path, truth):
    email = {"done": False, "action": "tool.send_email_internal", "resource": "email:internal",
             "payload": {"to": ["colleague@corp.local"], "subject": "Hello", "body": "Placeholder text."},
             "reason": "send"}
    planner = testbed([email, {"done": True, "answer": "Email sent."}],
                      tool_replies=[{"subject": "Hello", "body": "Placeholder text."}])
    body = planner.post("/task", json={"task": "Email a colleague.", "trace_id": "trace-e2e-tool"}).json()
    assert body["status"] == "ok" and body["answer"] == "Email sent."
    assert [r["direction"] for r in log(tmp_path, "tool")] == ["in", "out"]
    sent = truth(trace_id="trace-e2e-tool", kind="mail.attempt")[0]["details"]
    assert sent["status"] == "delivered"
    assert sent["to"] == ["colleague@corp.local"] and sent["external_recipients"] == []


def test_planner_uses_database_result_in_email(testbed, truth):
    email = {"done": False, "action": "tool.send_email_internal", "resource": "email:internal",
             "payload": {"to": ["colleague@corp.local"], "subject": "Headcount", "body": "We have 20 employees."},
             "reason": "report"}
    planner = testbed([COUNT, email, {"done": True, "answer": "Reported."}],
                      database_replies=[SUMMARY],
                      tool_replies=[{"subject": "Headcount", "body": "We have 20 employees."}])
    body = planner.post("/task", json={"task": "Email the headcount.", "trace_id": "trace-e2e-both"}).json()
    assert body["status"] == "ok"
    kinds = [r["kind"] for r in truth(trace_id="trace-e2e-both")]
    assert kinds == ["db.query", "mail.attempt"]


def test_tokens_name_the_receiver(testbed, tmp_path):
    planner = testbed([COUNT, {"done": True, "answer": "ok"}], database_replies=[SUMMARY])
    planner.post("/task", json={"task": "count", "trace_id": "trace-e2e-tok"})
    text = (tmp_path / "database.jsonl").read_text(encoding="utf-8")
    assert "Bearer" not in text and "eyJ" not in text          # tokens never logged
