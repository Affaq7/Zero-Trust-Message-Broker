"""F2-A: agents finish cleanly when the broker refuses a step (DENY, QUARANTINE, HITL).

send_message() raises BrokerDecisionError (a SendError) for a refusal; the planner and
research agents already treat any SendError as a failed step, so the task ends with a
clear status instead of an exception. Fake LLM, recording senders, no network."""

from types import SimpleNamespace

import pytest

from agents.base import TaskContext
from agents.planner import PlannerAgent
from agents.research import ResearchAgent
from contracts import make_response, new_request
from contracts.payloads import ResponsePayload
from wrapper.send import BrokerDecisionError


def refusal(decision, reason, receiver="database", action="db.query_aggregate"):
    req = new_request(sender="planner", receiver=receiver, action=action, resource="db:employees",
                      payload={}, chain_so_far=["user"])
    reply = make_response(req, ResponsePayload(status="ok")).model_copy(
        update={"decision": decision, "reason_code": reason, "payload": {"status": "denied"}})
    return BrokerDecisionError(reply)


class RefusingSender:
    def __init__(self, decision="DENY", reason="ROLE_NOT_ALLOWED"):
        self.decision, self.reason, self.calls = decision, reason, []

    def __call__(self, *, receiver, action, resource, payload, chain_so_far, trace_id):
        self.calls.append(action)
        raise refusal(self.decision, self.reason, receiver, action)


def step(action, resource, payload):
    return {"done": False, "action": action, "resource": resource, "payload": payload, "reason": "next"}


@pytest.mark.parametrize("decision, reason", [("DENY", "ROLE_NOT_ALLOWED"), ("QUARANTINE", "AGENT_QUARANTINED"),
                                              ("HITL", "HITL_PENDING")])
def test_planner_records_the_refusal_and_finishes(fake_llm, decision, reason):
    replies = [step("db.query_aggregate", "db:employees", {"metric": "count"}),
               {"done": True, "answer": "The broker refused the database query."}]
    sender = RefusingSender(decision, reason)
    planner = PlannerAgent(fake_llm("planner", {"planner.decide": replies}), sender)
    result = planner.run_task(TaskContext(task="How many employees are there?", trace_id="t-deny"))
    assert result.status == "ok" and result.answer == "The broker refused the database query."
    assert sender.calls == ["db.query_aggregate"]

    # The step record the model sees next says why the step failed.
    state = {"decision": SimpleNamespace(action="db.query_aggregate", resource="db:employees",
                                         payload={"metric": "count"}),
             "chain": ["user"], "trace_id": "t-deny", "history": [], "steps": 0}
    [record] = planner._act(state)["history"]
    assert record["outcome"] == f"ERROR: broker {decision}: {reason}"


def test_research_reports_a_refused_read_as_a_failed_step(fake_llm):
    agent = ResearchAgent(fake_llm("research", {}), RefusingSender("DENY", "DELEGATION_EXCEEDS_DELEGATOR"))
    ok, text = agent._send_step({"chain": ["user", "planner"], "trace_id": "t-r"}, "web.fetch_page",
                                "https://news.example.com/q3-market", {"url": "https://news.example.com/q3-market"})
    assert ok is False and text == "broker DENY: DELEGATION_EXCEEDS_DELEGATOR"
