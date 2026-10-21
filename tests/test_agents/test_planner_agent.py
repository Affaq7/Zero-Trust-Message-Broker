"""M2 step 11: planner agent (LangGraph) with the fake LLM and a recording sender."""

import pytest

from agents.base import TaskContext
from agents.planner import PlannerAgent, planner_actions
from contracts import make_response, new_request
from contracts.payloads import ResponsePayload
from wrapper.send import UnknownReceiverError


class RecordingSender:
    """Stands in for send_message(); answers every request with a fixed result."""

    def __init__(self, result=None, fail_for=()):
        self.calls = []
        self.result = result if result is not None else {"rows": [{"value": 20}]}
        self.fail_for = set(fail_for)

    def __call__(self, *, receiver, action, resource, payload, chain_so_far, trace_id):
        self.calls.append(dict(receiver=receiver, action=action, resource=resource,
                               payload=payload, chain_so_far=chain_so_far, trace_id=trace_id))
        if action in self.fail_for:
            raise UnknownReceiverError(f"no URL for receiver {receiver!r}")
        req = new_request(sender="planner", receiver=receiver, action=action, resource=resource,
                          payload=payload, chain_so_far=chain_so_far, trace_id=trace_id)
        return make_response(req, ResponsePayload(status="ok", result=self.result))


def step(action, resource, payload):
    return {"done": False, "action": action, "resource": resource, "payload": payload, "reason": "next"}


def finish(answer):
    return {"done": True, "answer": answer}


COUNT = step("db.query_aggregate", "db:employees", {"metric": "count"})
CTX = TaskContext(task="How many employees are there?", trace_id="trace-plan")


@pytest.fixture
def make_planner(fake_llm):
    def _make(replies, sender=None, max_steps=4):
        sender = sender or RecordingSender()
        planner = PlannerAgent(fake_llm("planner", {"planner.decide": replies}), sender, max_steps)
        return planner, sender
    return _make


def test_available_actions_come_from_the_catalog():
    actions = planner_actions()
    assert actions["db.query_aggregate"] == "database"
    assert actions["tool.send_email_internal"] == "tool"
    assert "web.fetch_page" not in actions            # planner may not call it
    assert "admin.change_policy" not in actions       # nobody may call it


def test_one_step_then_answer(make_planner, llm_calls):
    planner, sender = make_planner([COUNT, finish("There are 20 employees.")])
    result = planner.run_task(CTX)
    assert (result.status, result.answer) == ("ok", "There are 20 employees.")
    assert sender.calls == [dict(receiver="database", action="db.query_aggregate", resource="db:employees",
                                 payload={"metric": "count"}, chain_so_far=["user"], trace_id="trace-plan")]
    assert [c["purpose"] for c in llm_calls("planner")] == ["planner.decide", "planner.decide"]


def test_answer_without_actions(make_planner):
    planner, sender = make_planner([finish("Nothing to do.")])
    assert planner.run_task(CTX).answer == "Nothing to do."
    assert sender.calls == []


def test_two_steps_route_to_their_servers(make_planner):
    email = step("tool.send_email_internal", "email:internal",
                 {"to": ["colleague@corp.local"], "subject": "Count", "body": "20 employees"})
    planner, sender = make_planner([COUNT, email, finish("Sent.")])
    assert planner.run_task(CTX).status == "ok"
    assert [c["receiver"] for c in sender.calls] == ["database", "tool"]


def test_unavailable_action_is_reported_back_not_sent(make_planner):
    planner, sender = make_planner([step("web.fetch_page", "https://news.example.com/q3-market", {}),
                                    COUNT, finish("20")])
    assert planner.run_task(CTX).answer == "20"
    assert [c["action"] for c in sender.calls] == ["db.query_aggregate"]


def test_send_failure_is_reported_back(make_planner):
    planner, sender = make_planner([COUNT, finish("Could not reach the database.")],
                                   sender=RecordingSender(fail_for={"db.query_aggregate"}))
    result = planner.run_task(CTX)
    assert result.status == "ok" and "Could not reach" in result.answer
    assert len(sender.calls) == 1


def test_step_limit_forces_an_answer(make_planner):
    planner, sender = make_planner([COUNT, COUNT, finish("20 after two looks.")], max_steps=2)
    assert planner.run_task(CTX).answer == "20 after two looks."
    assert len(sender.calls) == 2


def test_never_finishing_is_an_error(make_planner):
    planner, sender = make_planner([COUNT, COUNT, COUNT], max_steps=2)
    result = planner.run_task(CTX)
    assert result.status == "error" and "step limit" in result.error
    assert len(sender.calls) == 2


def test_llm_failure_is_a_task_error(make_planner):
    planner, _ = make_planner(["not json", "still not json"])
    result = planner.run_task(CTX)
    assert result.status == "error" and "planner LLM failed" in result.error


def test_long_results_are_cut_before_the_next_prompt(make_planner, llm_calls):
    big = RecordingSender(result={"content": "x" * 50000})
    planner, _ = make_planner([COUNT, finish("done")], sender=big)
    assert planner.run_task(CTX).status == "ok"
    second = llm_calls("planner")[1]
    assert second["ok"] and second["est_prompt_tokens"] + second["num_predict"] <= second["num_ctx"]


def test_planner_accepts_no_messages_yet():
    from agents.planner import handle
    env = new_request(sender="research", receiver="planner", action="db.query_rows",
                      resource="db:employees", payload={}, chain_so_far=["user"])
    out = handle(env)
    assert out.status == "error" and "accepts no messages" in out.error
