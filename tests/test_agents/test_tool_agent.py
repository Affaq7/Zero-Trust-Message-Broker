"""M2 step 8: tool agent against the mock services, with the fake LLM."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import agents.tool as tool_module
from agents.mocks_client import MocksClient
from agents.tool import ToolAgent
from contracts import new_request
from wrapper.app import create_app
from wrapper.config import Settings


def req(action, resource, payload, trace_id="trace-tool"):
    return new_request(sender="planner", receiver="tool", action=action, resource=resource,
                       payload=payload, chain_so_far=["user"], trace_id=trace_id)


@pytest.fixture
def make_agent(fake_llm, mocks_client):
    def _make(script=None):
        return ToolAgent(fake_llm("tool", script or {}), mocks_client)
    return _make


# --- files -------------------------------------------------------------------------

def test_read_file(make_agent, truth, llm_calls):
    out = make_agent().handle(req("file.read_internal", "file:/internal/q3_report.txt", {}))
    assert out.status == "ok"
    assert out.result["path"] == "/internal/q3_report.txt"
    assert "Q3 Internal Report" in out.result["content"]
    assert truth(trace_id="trace-tool", kind="file.read")[0]["details"]["path"] == "/internal/q3_report.txt"
    assert llm_calls("tool") == []                      # no LLM for files


def test_read_file_respects_max_bytes(make_agent):
    out = make_agent().handle(req("file.read_internal", "file:/internal/q3_report.txt", {"max_bytes": 5}))
    assert out.result["content"] == "Q3 In" and out.result["truncated"] is True


def test_delete_file(make_agent, truth):
    agent = make_agent()
    out = agent.handle(req("file.delete", "file:/internal/hr_policy.txt", {"reason": "tidy up"}))
    assert out.status == "ok" and out.result == {"path": "/internal/hr_policy.txt", "deleted": True}
    assert truth(trace_id="trace-tool", kind="file.delete")[0]["details"]["path"] == "/internal/hr_policy.txt"
    again = agent.handle(req("file.read_internal", "file:/internal/hr_policy.txt", {}))
    assert again.status == "error" and "no such file" in again.error


def test_missing_file_is_an_error_reply(make_agent):
    out = make_agent().handle(req("file.read_internal", "file:/internal/nothing.txt", {}))
    assert out.status == "error" and "no such file" in out.error


# --- web ---------------------------------------------------------------------------

def test_fetch_fixture_page(make_agent, truth):
    out = make_agent().handle(req("web.fetch_page", "https://news.example.com/q3-market", {}))
    assert out.status == "ok"
    assert "Q3 market update" in out.result["content"]
    assert truth(trace_id="trace-tool", kind="web.fetch")[0]["details"]["found"] is True


def test_unknown_page_is_an_error_reply(make_agent):
    out = make_agent().handle(req("web.fetch_page", "https://unknown.example.org/page", {}))
    assert out.status == "error" and "page not found" in out.error


# --- email (CrewAI task on the fake LLM) ---------------------------------------------

EMAIL = {"to": ["colleague@corp.local"], "subject": "Weekly update", "body": "Placeholder body text."}
DRAFT = {"subject": "Weekly update (final)", "body": "Final placeholder body text."}


def test_internal_email_uses_llm_draft(make_agent, truth, llm_calls):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    out = agent.handle(req("tool.send_email_internal", "email:internal", EMAIL))
    assert out.status == "ok" and out.result == {"status": "delivered", "to": ["colleague@corp.local"]}
    sent = truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]
    assert (sent["subject"], sent["body"]) == (DRAFT["subject"], DRAFT["body"])
    assert sent["to"] == ["colleague@corp.local"]
    calls = llm_calls("tool")
    assert len(calls) == 1 and calls[0]["purpose"] == "tool.compose_email" and calls[0]["ok"]


def test_external_email_goes_to_the_sink(make_agent, truth):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    payload = {**EMAIL, "to": ["partner@example.org"]}
    out = agent.handle(req("tool.send_email_external", "email:external", payload))
    assert out.status == "ok"
    sent = truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]
    assert sent["resource"] == "email:external" and sent["external_recipients"] == ["partner@example.org"]


def test_llm_draft_cannot_change_recipients(make_agent, truth):
    draft_with_extra = {**DRAFT, "to": ["someone.else@example.org"]}
    agent = make_agent({"tool.compose_email": [draft_with_extra]})
    agent.handle(req("tool.send_email_internal", "email:internal", EMAIL))
    assert truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]["to"] == ["colleague@corp.local"]


def test_cc_and_bcc_pass_through_unchanged_and_are_recorded(make_agent, truth):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    payload = {**EMAIL, "cc": ["Boss@corp.local"], "bcc": ["audit@corp.local"]}
    out = agent.handle(req("tool.send_email_internal", "email:internal", payload))
    assert out.status == "ok"
    sent = truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]
    assert (sent["to"], sent["cc"], sent["bcc"]) == (
        ["colleague@corp.local"], ["boss@corp.local"], ["audit@corp.local"])      # normalised, not changed by the LLM
    assert sent["external_recipients"] == []


def test_justification_is_accepted_on_the_external_email(make_agent, truth):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    payload = {**EMAIL, "to": ["partner@example.org"], "justification": "Requested by the finance lead."}
    assert agent.handle(req("tool.send_email_external", "email:external", payload)).status == "ok"
    assert truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]["external_recipients"] == ["partner@example.org"]


def test_justification_on_the_internal_email_is_rejected_with_a_field_name(make_agent):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    out = agent.handle(req("tool.send_email_internal", "email:internal", {**EMAIL, "justification": "please"}))
    assert out.status == "error" and "justification:" in out.error and "please" not in out.error


def test_braces_in_email_text_are_kept(make_agent, truth):
    agent = make_agent({"tool.compose_email": [{"subject": "Totals {Q3}", "body": "Value: {total}"}]})
    payload = {**EMAIL, "subject": "Totals {Q3}", "body": "Value: {total}"}
    assert agent.handle(req("tool.send_email_internal", "email:internal", payload)).status == "ok"
    assert truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]["body"] == "Value: {total}"


def test_llm_failure_sends_nothing(make_agent, truth):
    agent = make_agent({"tool.compose_email": ["not json", "still not json"]})
    out = agent.handle(req("tool.send_email_internal", "email:internal", EMAIL))
    assert out.status == "error" and "invalid reply" in out.error
    assert truth(trace_id="trace-tool", kind="mail.attempt") == []


# --- policy changes (mock admin handler) ---------------------------------------------

def test_invalid_email_error_names_fields_not_values(make_agent):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    bad = {**EMAIL, "to": ["not-an-address"]}
    out = agent.handle(req("tool.send_email_internal", "email:internal", bad))
    assert out.status == "error" and out.error.startswith("invalid payload: to:"), out.error
    assert "not-an-address" not in out.error


def test_unsupported_action_is_an_error_reply(make_agent):
    out = make_agent().handle(req("db.query_rows", "db:employees", {"columns": ["id"]}))
    assert out.status == "error" and "cannot perform" in out.error


def test_mock_services_unreachable(fake_llm):
    def down(request):
        raise httpx.ConnectError("down", request=request)
    agent = ToolAgent(fake_llm("tool", {}),
                      MocksClient("http://mocks.test", client=httpx.Client(transport=httpx.MockTransport(down))))
    out = agent.handle(req("file.read_internal", "file:/internal/q3_report.txt", {}))
    assert out.status == "error" and "unreachable" in out.error


def test_through_wrapper_with_environment_settings(tmp_path, mocks_client, truth, monkeypatch):
    script = tmp_path / "script.json"
    script.write_text(json.dumps({"tool.compose_email": [DRAFT]}), encoding="utf-8")
    monkeypatch.setenv("LLM_BACKEND", "fake")
    monkeypatch.setenv("LLM_FAKE_SCRIPT", str(script))
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    monkeypatch.setattr(tool_module, "_default", None)
    monkeypatch.setattr(tool_module, "MocksClient", lambda: mocks_client)

    wrapper = TestClient(create_app(Settings(mode="direct", agent_name="tool", log_dir=tmp_path)))
    env = req("tool.send_email_internal", "email:internal", EMAIL, trace_id="trace-wrap")
    r = wrapper.post("/message", content=env.model_dump_json(), headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert r.json()["payload"]["status"] == "ok"
    assert truth(trace_id="trace-wrap", kind="mail.attempt")[0]["details"]["subject"] == DRAFT["subject"]
    assert (tmp_path / "llm" / "tool.jsonl").exists()


def test_policy_change_goes_to_mock_admin_handler(make_agent, mocks, truth):
    out = make_agent().handle(req("admin.change_policy", "policy:sample-policy",
                                  {"policy_id": "sample-policy", "changes": {"setting": "value"}}))
    assert out.status == "ok" and out.result == {"status": "applied", "policy_id": "sample-policy"}
    assert mocks.get("/admin/policies").json()["policies"] == {"sample-policy": {"setting": "value"}}
    rec = truth(trace_id="trace-tool", kind="admin.policy_change")[0]["details"]
    assert rec["policy_id"] == "sample-policy"
