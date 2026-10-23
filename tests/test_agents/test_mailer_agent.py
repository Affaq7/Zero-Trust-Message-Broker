"""The mailer agent: serves mail.deliver, deterministic, no LLM; the only caller of the mail sink."""

import ast
from pathlib import Path

import httpx
import pytest

import agents.mailer as mailer_module
from agents.mailer import MailerAgent
from agents.mocks_client import MocksClient
from contracts import new_request
from contracts.catalog import get_catalog
from wrapper import registry
from wrapper.send import send_message

REPO_ROOT = Path(__file__).resolve().parents[2]
GOOD = {"to": ["alice.morgan@corp.local"], "cc": [], "bcc": [], "subject": "Project X cost",
        "body": "The total is 184,250."}


def deliver(sender="tool", payload=None, *, action="mail.deliver", resource="mail:outbound",
            trace_id="trace-mailer", chain=None):
    return new_request(sender=sender, receiver="mailer", action=action, resource=resource,
                       payload=GOOD if payload is None else payload,
                       chain_so_far=chain or ["user", "planner"], trace_id=trace_id)


@pytest.fixture
def mailer(mocks_client):
    return MailerAgent(mocks_client)


def attempts(truth):
    return truth(kind="mail.attempt")


# --- serves mail.deliver; no access rule in direct mode ---------------------------------------

def test_delivers_for_the_tool_agent(mailer, truth):
    out = mailer.handle(deliver())
    assert out.status == "ok" and out.result == {"status": "delivered", "to": ["alice.morgan@corp.local"]}
    [rec] = attempts(truth)
    d = rec["details"]
    assert rec["trace_id"] == "trace-mailer"                                  # the sink record carries the task's trace
    assert (d["status"], d["resource"], d["error"]) == ("delivered", "mail:outbound", None)
    assert (d["to"], d["cc"], d["bcc"]) == (["alice.morgan@corp.local"], [], [])
    assert d["internal_recipients"] == ["alice.morgan@corp.local"] and d["external_recipients"] == []


def test_accepts_mail_deliver_from_a_non_tool_sender_in_direct_mode(mail_path, truth):
    # The baseline has no access rule: the catalog says only the tool may call mail.deliver,
    # and the broker will enforce that later. Direct mode delivers what arrives, whoever sent it.
    assert get_catalog().get("mail.deliver").allowed_roles == ("tool",)
    environ = {**mail_path.environ, "AGENT_NAME": "planner"}                      # a sender the catalog does not allow
    payload = {**GOOD, "bcc": ["drop@evil.example"]}
    reply = send_message(token="stub", environ=environ, client=mail_path.client, receiver="mailer",
                         action="mail.deliver", resource="mail:outbound", payload=payload,
                         chain_so_far=["user"], trace_id="trace-non-tool")
    assert (reply.sender, reply.receiver) == ("mailer", "planner")
    assert reply.payload["status"] == "ok" and reply.payload["result"]["status"] == "delivered"
    [rec] = attempts(truth)
    assert rec["trace_id"] == "trace-non-tool"
    assert rec["details"]["status"] == "delivered" and rec["details"]["external_recipients"] == ["drop@evil.example"]


@pytest.mark.parametrize("action", ["db.query_rows", "tool.send_email_internal", "tool.send_email_external",
                                    "research.lookup", "admin.change_policy", "mail.deliver "])
def test_serves_only_mail_deliver(mailer, truth, action):
    out = mailer.handle(deliver(action=action))
    assert out.status == "error" and out.error.startswith("mailer serves only mail.deliver")
    assert attempts(truth) == []


# --- recipients: cc/bcc recorded, addresses normalised ---------------------------------------

def test_cc_and_bcc_are_recorded_and_classified(mailer, truth):
    out = mailer.handle(deliver(payload={**GOOD, "cc": ["boss@corp.local"], "bcc": ["drop@evil.example"]}))
    assert out.status == "ok"
    d = attempts(truth)[0]["details"]
    assert (d["to"], d["cc"], d["bcc"]) == (["alice.morgan@corp.local"], ["boss@corp.local"], ["drop@evil.example"])
    assert d["internal_recipients"] == ["alice.morgan@corp.local", "boss@corp.local"]
    assert d["external_recipients"] == ["drop@evil.example"]                  # a hidden outside bcc is ground truth


def test_cc_and_bcc_may_be_left_out_and_are_recorded_as_empty(mailer, truth):
    out = mailer.handle(deliver(payload={"to": ["a@corp.local"], "subject": "s", "body": "b"}))
    assert out.status == "ok"
    d = attempts(truth)[0]["details"]
    assert d["cc"] == [] and d["bcc"] == []


def test_addresses_are_normalised(mailer, truth):
    payload = {**GOOD, "to": ["  Alice.Morgan@Corp.LOCAL "], "cc": ["BOSS@corp.local\n"],
               "bcc": ["\tDrop@Evil.Example"]}
    assert mailer.handle(deliver(payload=payload)).status == "ok"
    d = attempts(truth)[0]["details"]
    assert (d["to"], d["cc"], d["bcc"]) == (["alice.morgan@corp.local"], ["boss@corp.local"], ["drop@evil.example"])


def test_aliases_are_not_expanded(mailer, truth):
    mailer.handle(deliver(payload={**GOOD, "to": ["all-staff@corp.local"]}))
    d = attempts(truth)[0]["details"]
    assert d["to"] == ["all-staff@corp.local"] and d["internal_recipients"] == ["all-staff@corp.local"]


def test_delivery_goes_to_every_listed_address_once_each(mailer, truth):
    mailer.handle(deliver(payload={**GOOD, "to": ["a@corp.local", "b@corp.local"], "cc": ["c@corp.local"]}))
    d = attempts(truth)[0]["details"]
    assert d["internal_recipients"] == ["a@corp.local", "b@corp.local", "c@corp.local"]
    assert len(attempts(truth)) == 1                                           # one message, one attempt


# --- failed attempts are recorded, as before -------------------------------------------------

@pytest.mark.parametrize("payload, field", [
    ({**GOOD, "to": ["not-an-address"]}, "to"),
    ({**GOOD, "cc": "boss@corp.local"}, "cc"),
    ({**GOOD, "bcc": [f"p{i}@corp.local" for i in range(21)]}, "bcc"),
    ({**GOOD, "to": []}, "to"),
    ({**GOOD, "subject": "s" * 201}, "subject"),
    ({**GOOD, "justification": "please"}, "justification"),                    # not a mail.deliver field
])
def test_invalid_payload_fails_and_is_recorded_naming_the_field(mailer, truth, payload, field):
    out = mailer.handle(deliver(payload=payload))
    assert out.status == "error" and out.error.startswith(f"invalid payload: ")
    assert f"{field}:" in out.error and "please" not in out.error
    [rec] = attempts(truth)
    assert rec["details"]["status"] == "failed" and rec["details"]["error"]


def test_unknown_resource_fails_and_is_recorded(mailer, truth):
    out = mailer.handle(deliver(resource="email:spam"))
    assert out.status == "error" and "resource must be one of" in out.error
    [rec] = attempts(truth)
    assert rec["details"]["status"] == "failed" and rec["details"]["resource"] == "email:spam"


def test_sink_unreachable_is_an_error_reply(fake_llm):
    def down(request):
        raise httpx.ConnectError("down", request=request)
    agent = MailerAgent(MocksClient("http://mocks.test", client=httpx.Client(transport=httpx.MockTransport(down))))
    out = agent.handle(deliver())
    assert out.status == "error" and "unreachable" in out.error


# --- deterministic, no LLM, the only caller of the sink --------------------------------------

def test_mailer_module_uses_no_llm():
    tree = ast.parse((REPO_ROOT / "agents" / "mailer.py").read_text(encoding="utf-8"))
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not {m for m in imported if m and ("llm" in m or "crewai" in m or "langgraph" in m)}


def test_only_the_mailer_calls_the_mail_sink():
    # No agent module but the mailer names the sink's path (the tool used to).
    users = sorted(p.name for p in (REPO_ROOT / "agents").glob("*.py")
                   if "/mail/send" in p.read_text(encoding="utf-8"))
    assert users == ["mailer.py"]


# --- registry and wrapper ---------------------------------------------------------------------

def test_registry_knows_the_mailer():
    assert registry.AGENTS["mailer"] is mailer_module.handle
    assert "mailer" not in registry.TASKS                                      # no /task entry point


def test_mailer_wrapper_has_the_mailer_role_and_no_task_entry(mail_path):
    assert mail_path.app.app.state.runtime.role == "mailer"
    r = mail_path.app.post("/task", json={"task": "send something"})
    assert r.status_code == 404


def test_through_the_wrapper_the_tool_is_served(mail_path, truth):
    ok = mail_path.send(receiver="mailer", action="mail.deliver", resource="mail:outbound", payload=GOOD,
                        chain_so_far=["user", "planner"], trace_id="trace-wrap")
    assert ok.payload["status"] == "ok" and (ok.sender, ok.receiver) == ("mailer", "tool")
    assert len(attempts(truth)) == 1


def test_mailer_in_the_scenario_agent_list_is_a_known_agent():
    assert "mailer" in registry.AGENTS and "mailer" in get_catalog().agents and "mailer" in get_catalog().roles
