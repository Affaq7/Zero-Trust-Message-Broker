"""M2 step 9: database agent against the mock database, with the fake LLM."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import agents.database as database_module
from agents.database import DatabaseAgent
from agents.mocks_client import MocksClient
from contracts import new_request
from mocks.seed import DEPTS, NAMES
from wrapper.app import create_app
from wrapper.config import Settings

SUMMARY = {"summary": "Placeholder summary of the result."}


def req(action, resource, payload, trace_id="trace-db"):
    return new_request(sender="planner", receiver="database", action=action, resource=resource,
                       payload=payload, chain_so_far=["user"], trace_id=trace_id)


@pytest.fixture
def make_agent(fake_llm, mocks_client):
    def _make(script=None):
        return DatabaseAgent(fake_llm("database", script or {}), mocks_client)
    return _make


# --- reads -------------------------------------------------------------------------

def test_aggregate_returns_rows_and_summary(make_agent, truth, llm_calls):
    agent = make_agent({"database.summarise": [SUMMARY]})
    out = agent.handle(req("db.query_aggregate", "db:employees", {"metric": "count", "group_by": ["dept"]}))
    assert out.status == "ok"
    assert out.result["rows"] == [{"dept": d, "value": len(NAMES) // len(DEPTS)} for d in sorted(DEPTS)]
    assert out.result["summary"] == SUMMARY["summary"]
    assert truth(trace_id="trace-db", kind="db.query")[0]["details"]["action"] == "db.query_aggregate"
    calls = llm_calls("database")
    assert len(calls) == 1 and calls[0]["purpose"] == "database.summarise" and calls[0]["ok"]


def test_query_rows_returns_requested_columns(make_agent):
    agent = make_agent({"database.summarise": [SUMMARY]})
    out = agent.handle(req("db.query_rows", "db:employees", {"columns": ["id", "name"], "limit": 2}))
    assert out.status == "ok"
    assert out.result["rows"] == [{"id": 1, "name": NAMES[0]}, {"id": 2, "name": NAMES[1]}]


def test_full_table_stays_inside_the_context_window(make_agent, llm_calls):
    agent = make_agent({"database.summarise": [SUMMARY]})
    out = agent.handle(req("db.query_rows", "db:employees",
                           {"columns": ["id", "name", "dept", "email", "phone"]}))
    assert out.status == "ok" and len(out.result["rows"]) == len(NAMES)
    call = llm_calls("database")[0]
    assert call["ok"] and call["est_prompt_tokens"] + call["num_predict"] <= call["num_ctx"]


# --- writes ------------------------------------------------------------------------

def test_update_needs_no_llm(make_agent, truth, llm_calls):
    out = make_agent().handle(req("db.update_records", "db:employees",
                                  {"filters": {"id": 1}, "updates": {"dept": "Sales"}}))
    assert out.status == "ok"
    assert out.result == {"rows_affected": 1, "summary": "Updated 1 row(s)."}
    assert truth(trace_id="trace-db", kind="db.write")[0]["details"]["rows_affected"] == 1
    assert llm_calls("database") == []


# --- errors ------------------------------------------------------------------------

@pytest.mark.parametrize("action, resource, payload, text", [
    ("db.query_rows", "db:employees", {"columns": ["nope"]}, "unknown column"),
    ("db.query_rows", "db:unknown_table", {"columns": ["id"]}, "unknown table"),
    ("db.query_rows", "db:employees", {"columns": []}, "invalid payload: columns:"),
])
def test_database_errors_become_error_replies(make_agent, action, resource, payload, text):
    out = make_agent().handle(req(action, resource, payload))
    assert out.status == "error" and text in out.error


# The payloads the planner actually sent in the live N1/N3 runs (2026-10-21).
LIVE_FAILURES = [
    ("db.query_rows", {"columns": ["project_id", "amount"], "filters": {"project": "Project X"}, "limit": 0},
     ["limit"]),
    ("db.query_rows", {"columns": ["id", "project", "amount"],
                       "filters": [{"column": "project", "value": "X"}], "limit": 1000},
     ["filters"]),
    ("db.query_aggregate", {"metric": "SUM(amount)", "column": "project", "group_by": "project",
                            "filters": [{"column": "project", "value": "X", "operator": "EQ"}]},
     ["metric", "group_by", "filters"]),
    ("db.query_aggregate", {"metric": "sum", "column": "amount", "group_by": "project",
                            "filters": [{"column": "project", "value": "Project X"}]},
     ["group_by", "filters"]),
]


@pytest.mark.parametrize("action, payload, fields", LIVE_FAILURES)
def test_invalid_payload_error_names_fields_not_values(make_agent, action, payload, fields):
    out = make_agent().handle(req(action, "db:project_costs", payload))
    assert out.status == "error" and out.error.startswith("invalid payload: ")
    for field in fields:
        assert f"{field}:" in out.error or f"{field}." in out.error, out.error
    for value in ("Project X", "SUM(amount)", "EQ", '"X"'):
        assert value not in out.error, out.error


def test_cross_field_error_does_not_quote_the_value(make_agent):
    out = make_agent().handle(req("db.query_aggregate", "db:project_costs", {"metric": "sum"}))
    assert "needs a column" in out.error and "'sum'" not in out.error


def test_extra_field_is_named(make_agent):
    out = make_agent().handle(req("db.query_rows", "db:projects", {"columns": ["name"], "operator": "EQ"}))
    assert "operator: Extra inputs are not permitted" in out.error and "EQ" not in out.error


def test_unsupported_action(make_agent):
    out = make_agent().handle(req("web.fetch_page", "https://news.example.com/q3-market", {}))
    assert out.status == "error" and "cannot perform" in out.error


def test_llm_failure_is_an_error_reply(make_agent):
    agent = make_agent({"database.summarise": ["not json", "still not json"]})
    out = agent.handle(req("db.query_aggregate", "db:employees", {"metric": "count"}))
    assert out.status == "error" and "invalid reply" in out.error


def test_mock_services_unreachable(fake_llm):
    def down(request):
        raise httpx.ConnectError("down", request=request)
    agent = DatabaseAgent(fake_llm("database", {}),
                          MocksClient("http://mocks.test", client=httpx.Client(transport=httpx.MockTransport(down))))
    out = agent.handle(req("db.query_aggregate", "db:employees", {"metric": "count"}))
    assert out.status == "error" and "unreachable" in out.error


# --- through the wrapper -------------------------------------------------------------

def test_through_wrapper_with_environment_settings(tmp_path, mocks_client, monkeypatch):
    script = tmp_path / "script.json"
    script.write_text(json.dumps({"database.summarise": [SUMMARY]}), encoding="utf-8")
    monkeypatch.setenv("LLM_BACKEND", "fake")
    monkeypatch.setenv("LLM_FAKE_SCRIPT", str(script))
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    monkeypatch.setattr(database_module, "_default", None)
    monkeypatch.setattr(database_module, "MocksClient", lambda: mocks_client)

    wrapper = TestClient(create_app(Settings(mode="direct", agent_name="database", log_dir=tmp_path)))
    env = req("db.query_aggregate", "db:employees", {"metric": "count"}, trace_id="trace-wrap")
    r = wrapper.post("/message", content=env.model_dump_json(), headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    body = r.json()
    assert (body["sender"], body["receiver"]) == ("database", "planner")
    assert body["payload"]["result"]["rows"] == [{"value": len(NAMES)}]
    assert (tmp_path / "llm" / "database.jsonl").exists()
