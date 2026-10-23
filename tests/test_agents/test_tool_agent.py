"""M2 step 8: tool agent against the mock services, with the fake LLM.

Files, web pages and policy changes go to the mock services; email goes to the
mailer as a mail.deliver message (the ``mail_path`` fixture is a real mailer
wrapper, in-process, in front of the mock sink).
"""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import agents.tool as tool_module
from agents.mocks_client import MocksClient
from agents.tool import ToolAgent
from contracts import Envelope, new_request
from wrapper.app import create_app
from wrapper.config import Settings
from wrapper.send import ReceiverUnreachableError, UnknownReceiverError
from wrapper.send import send_message as real_send_message


def req(action, resource, payload, trace_id="trace-tool"):
    return new_request(sender="planner", receiver="tool", action=action, resource=resource,
                       payload=payload, chain_so_far=["user"], trace_id=trace_id)


@pytest.fixture
def make_agent(fake_llm, mocks_client, mail_path):
    def _make(script=None):
        return ToolAgent(fake_llm("tool", script or {}), mocks_client, sender=mail_path.send)
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


def test_external_email_is_delivered_through_the_mailer(make_agent, truth):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    payload = {**EMAIL, "to": ["partner@example.org"]}
    out = agent.handle(req("tool.send_email_external", "email:external", payload))
    assert out.status == "ok"
    sent = truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]
    assert sent["resource"] == "mail:outbound" and sent["external_recipients"] == ["partner@example.org"]


def test_email_is_a_mail_deliver_message_to_the_mailer(make_agent, mail_path, truth):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    agent.handle(req("tool.send_email_internal", "email:internal", EMAIL))
    [request] = mail_path.requests
    assert str(request.url) == "http://mailer.test/message"
    sent = Envelope.model_validate_json(request.content)
    assert (sent.sender, sent.receiver, sent.action, sent.resource) == (
        "tool", "mailer", "mail.deliver", "mail:outbound")
    assert sent.trace_id == "trace-tool"                                      # same trace as the task
    assert sent.delegation_chain == ["user", "planner", "tool"]               # the tool appended itself
    assert set(sent.payload) == {"to", "cc", "bcc", "subject", "body"}
    assert sent.payload["cc"] == [] and sent.payload["bcc"] == []             # stated explicitly, even when empty
    assert (sent.payload["subject"], sent.payload["body"]) == (DRAFT["subject"], DRAFT["body"])
    # N3's case: no cc/bcc requested, so the delivery record shows them empty.
    d = truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]
    assert d["cc"] == [] and d["bcc"] == []


def test_recipients_in_the_mail_deliver_message_are_normalised(make_agent, mail_path):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    agent.handle(req("tool.send_email_internal", "email:internal",
                     {**EMAIL, "to": [" Colleague@Corp.Local "], "cc": ["Boss@Corp.Local"],
                      "bcc": ["\tAudit@corp.local"]}))
    sent = Envelope.model_validate_json(mail_path.requests[0].content)
    assert (sent.payload["to"], sent.payload["cc"], sent.payload["bcc"]) == (
        ["colleague@corp.local"], ["boss@corp.local"], ["audit@corp.local"])     # normalised on the wire


def test_malformed_recipients_are_passed_on_for_the_receiver_to_refuse(make_agent, truth):
    agent = make_agent({"tool.compose_email": [DRAFT]})
    out = agent.handle(req("tool.send_email_internal", "email:internal", {**EMAIL, "cc": "boss@corp.local"}))
    assert out.status == "error" and out.error.startswith("invalid payload: cc:")
    assert truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]["status"] == "failed"


def test_the_tool_never_calls_the_mail_sink_itself(fake_llm, recording_mocks, mail_path, truth):
    agent = ToolAgent(fake_llm("tool", {"tool.compose_email": [DRAFT]}), recording_mocks.client,
                      sender=mail_path.send)
    assert agent.handle(req("tool.send_email_internal", "email:internal", EMAIL)).status == "ok"
    assert recording_mocks.paths == []                                        # the tool made no mock-service call
    assert len(truth(trace_id="trace-tool", kind="mail.attempt")) == 1        # yet the mail was delivered (by the mailer)
    agent.handle(req("file.read_internal", "file:/internal/q3_report.txt", {}))
    assert recording_mocks.paths == ["/files/read"]                           # files still go to the mocks


def test_request_only_fields_are_not_forwarded_to_the_mailer(make_agent, mail_path, truth):
    # justification belongs to the request, not to mail.deliver.
    agent = make_agent({"tool.compose_email": [DRAFT, DRAFT]})
    agent.handle(req("tool.send_email_external", "email:external",
                     {**EMAIL, "to": ["partner@example.org"], "justification": "Approved by finance."}))
    agent.handle(req("tool.send_email_internal", "email:internal", {**EMAIL, "justification": "please"}))
    for request in mail_path.requests:
        assert "justification" not in Envelope.model_validate_json(request.content).payload
    assert [r["details"]["status"] for r in truth(kind="mail.attempt")] == ["delivered", "delivered"]


def test_mailer_not_in_the_scenario_is_a_clear_error(fake_llm, mocks_client):
    def no_mailer(**kwargs):
        raise UnknownReceiverError("no URL for receiver 'mailer' in AGENT_URLS")
    agent = ToolAgent(fake_llm("tool", {"tool.compose_email": [DRAFT]}), mocks_client, sender=no_mailer)
    out = agent.handle(req("tool.send_email_internal", "email:internal", EMAIL))
    assert out.status == "error" and out.error.startswith("mailer: no URL for receiver 'mailer'")


def test_mailer_unreachable_sends_nothing(fake_llm, mocks_client, truth):
    def down(**kwargs):
        raise ReceiverUnreachableError("'mailer' at http://mailer.test/message unreachable: ConnectError")
    agent = ToolAgent(fake_llm("tool", {"tool.compose_email": [DRAFT]}), mocks_client, sender=down)
    out = agent.handle(req("tool.send_email_internal", "email:internal", EMAIL))
    assert out.status == "error" and "unreachable" in out.error
    assert truth(kind="mail.attempt") == []


def test_incoming_chain_that_breaks_a_rule_is_an_error_not_a_crash(make_agent, mail_path):
    bad = Envelope.model_validate({**req("tool.send_email_internal", "email:internal", EMAIL).model_dump(mode="json"),
                                   "delegation_chain": ["planner"]})
    out = make_agent({"tool.compose_email": [DRAFT]}).handle(bad)
    assert out.status == "error" and out.error.startswith("cannot send mail.deliver:")
    assert mail_path.requests == []


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


def test_braces_in_email_text_are_kept(make_agent, truth):
    agent = make_agent({"tool.compose_email": [{"subject": "Totals {Q3}", "body": "Value: {total}"}]})
    payload = {**EMAIL, "subject": "Totals {Q3}", "body": "Value: {total}"}
    assert agent.handle(req("tool.send_email_internal", "email:internal", payload)).status == "ok"
    assert truth(trace_id="trace-tool", kind="mail.attempt")[0]["details"]["body"] == "Value: {total}"


def test_llm_failure_sends_nothing(make_agent, truth, mail_path):
    agent = make_agent({"tool.compose_email": ["not json", "still not json"]})
    out = agent.handle(req("tool.send_email_internal", "email:internal", EMAIL))
    assert out.status == "error" and "invalid reply" in out.error
    assert truth(trace_id="trace-tool", kind="mail.attempt") == []
    assert mail_path.requests == []                                           # the mailer was never asked


# --- policy changes (mock admin handler) ---------------------------------------------

def test_invalid_email_error_names_fields_not_values(make_agent, truth):
    # The mailer passes the message to the sink, which refuses it and records a failed attempt.
    agent = make_agent({"tool.compose_email": [DRAFT]})
    bad = {**EMAIL, "to": ["not-an-address"]}
    out = agent.handle(req("tool.send_email_internal", "email:internal", bad))
    assert out.status == "error" and out.error.startswith("invalid payload: to:"), out.error
    assert "not-an-address" not in out.error
    [attempt] = truth(trace_id="trace-tool", kind="mail.attempt")
    assert attempt["details"]["status"] == "failed"


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


def test_through_wrapper_with_environment_settings(tmp_path, mocks_client, mail_path, truth, monkeypatch):
    script = tmp_path / "script.json"
    script.write_text(json.dumps({"tool.compose_email": [DRAFT]}), encoding="utf-8")
    monkeypatch.setenv("LLM_BACKEND", "fake")
    monkeypatch.setenv("LLM_FAKE_SCRIPT", str(script))
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    monkeypatch.setattr(tool_module, "_default", None)
    monkeypatch.setattr(tool_module, "MocksClient", lambda: mocks_client)
    # The default sender (runtime token + send_message) reaches the in-process mailer.
    monkeypatch.setattr(tool_module, "send_message",
                        lambda **kw: real_send_message(client=mail_path.client, environ=mail_path.environ, **kw))

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
