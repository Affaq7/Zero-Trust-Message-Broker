"""Research agent (LangGraph) with the fake LLM: reads through the real tool agent
and the in-process mock services; no live model."""

import json

import pytest

from agents.base import TaskContext  # noqa: F401  (kept for parity with the other agent tests)
from agents.research import (
    MAX_ANSWER_CHARS,
    MAX_OBSERVATION_CHARS,
    ResearchAgent,
    read_request,
    research_actions,
)
from agents.tool import ToolAgent
from contracts import make_response, new_request
from contracts.payloads import ResponsePayload
from wrapper.send import UnknownReceiverError

HR = "file:/internal/hr_policy.txt"
Q3 = "file:/internal/q3_report.txt"
MARKET = "https://news.example.com/q3-market"
TRACE = "trace-research"


def lookup(sources, query="What does the policy say?", max_sources=3, trace_id=TRACE):
    payload = {"query": query, "sources": sources, "max_sources": max_sources}
    return new_request(sender="planner", receiver="research", action="research.lookup",
                       resource="research:query", payload=payload, chain_so_far=["user"],
                       trace_id=trace_id)


def answer(text):
    return {"done": True, "answer": text}


class ToolSender:
    """send_message() stand-in that hands each request to a real ToolAgent."""

    def __init__(self, tool, fail_for=()):
        self.tool, self.fail_for, self.calls = tool, set(fail_for), []

    def __call__(self, *, receiver, action, resource, payload, chain_so_far, trace_id):
        self.calls.append(dict(receiver=receiver, action=action, resource=resource, payload=payload,
                               chain_so_far=chain_so_far, trace_id=trace_id))
        if resource in self.fail_for:
            raise UnknownReceiverError(f"no URL for receiver {receiver!r}")
        req = new_request(sender="research", receiver=receiver, action=action, resource=resource,
                          payload=payload, chain_so_far=chain_so_far, trace_id=trace_id)
        return make_response(req, self.tool.handle(req))


@pytest.fixture
def make_research(fake_llm, mocks_client):
    def _make(script, max_steps=4, fail_for=()):
        llm = fake_llm("research", {"research.decide": script})
        sender = ToolSender(ToolAgent(fake_llm("tool", {}), mocks_client), fail_for)
        return ResearchAgent(llm, sender, max_steps), sender, llm
    return _make


def test_available_actions_come_from_the_catalog():
    actions = research_actions()
    assert actions == {"db.query_aggregate": "database", "file.read_internal": "tool",
                       "web.fetch_page": "tool"}


@pytest.mark.parametrize("source, expected", [
    (HR, ("file.read_internal", HR)),
    (MARKET, ("web.fetch_page", MARKET)),
    ("HTTP://news.example.com/x", ("web.fetch_page", "HTTP://news.example.com/x")),
])
def test_read_request_picks_the_action_from_the_source(source, expected):
    action, resource, payload = read_request(source)
    assert (action, resource) == expected and payload


@pytest.mark.parametrize("source", ["hr_policy.txt", "ftp://host/x", "db:employees", "mailto:a@b.c"])
def test_unsupported_sources_are_not_read(source):
    assert read_request(source) is None


def test_reads_every_source_then_makes_one_llm_call(make_research, truth, llm_calls):
    agent, sender, _ = make_research([answer("Payroll exports must not be emailed outside corp.local; Q3 was 5.2%.")])
    reply = agent.handle(lookup([HR, MARKET]))
    assert reply.status == "ok"
    assert reply.result == {"answer": "Payroll exports must not be emailed outside corp.local; Q3 was 5.2%.",
                            "sources_read": [HR, MARKET], "sources_failed": []}
    assert [c["action"] for c in sender.calls] == ["file.read_internal", "web.fetch_page"]
    assert {c["receiver"] for c in sender.calls} == {"tool"}
    assert [c["chain_so_far"] for c in sender.calls] == [["user", "planner"]] * 2
    assert len(llm_calls("research")) == 1
    assert [r["details"]["path"] for r in truth(kind="file.read")] == ["/internal/hr_policy.txt"]
    assert [r["details"]["url"] for r in truth(kind="web.fetch")] == [MARKET]


def test_the_model_sees_what_was_read_raw(make_research):
    agent, _, _ = make_research([answer("ok")])
    seen = {}
    real = agent.llm.decide

    def spy(**kw):
        seen.update(kw)
        return real(**kw)
    agent.llm.decide = spy
    agent.handle(lookup([HR, MARKET], query="Which rule applies?"))
    prompt = seen["prompt"]
    assert prompt.startswith("Question: Which rule applies?")
    assert f"Source 1 ({HR}):" in prompt and f"Source 2 ({MARKET}):" in prompt
    assert "<html" in prompt.lower() or "<p>" in prompt.lower()          # fetched HTML stays raw
    assert seen["purpose"] == "research.decide"


def test_only_max_sources_are_read(make_research):
    agent, sender, _ = make_research([answer("done")])
    reply = agent.handle(lookup([HR, Q3, MARKET], max_sources=2))
    assert reply.result["sources_read"] == [HR, Q3]
    assert len(sender.calls) == 2


def test_a_source_that_fails_is_listed_and_the_rest_answer(make_research, llm_calls):
    agent, _, _ = make_research([answer("from the report only")])
    reply = agent.handle(lookup(["file:/internal/missing.txt", Q3]))
    assert reply.status == "ok"
    assert reply.result["sources_read"] == [Q3]
    assert reply.result["sources_failed"] == ["file:/internal/missing.txt"]
    assert len(llm_calls("research")) == 1


def test_a_send_failure_counts_as_a_failed_source(make_research):
    agent, _, _ = make_research([answer("partial")], fail_for={HR})
    reply = agent.handle(lookup([HR, Q3]))
    assert reply.result["sources_failed"] == [HR] and reply.result["sources_read"] == [Q3]


def test_unsupported_source_is_failed_without_a_send(make_research):
    agent, sender, _ = make_research([answer("partial")])
    reply = agent.handle(lookup(["notes.txt", Q3]))
    assert reply.result["sources_failed"] == ["notes.txt"]
    assert len(sender.calls) == 1


def test_nothing_readable_is_an_error_without_the_llm(make_research, llm_calls):
    agent, _, _ = make_research([answer("never used")])
    reply = agent.handle(lookup(["file:/internal/missing.txt", "https://nowhere.example/x"]))
    assert reply.status == "error"
    assert reply.error.startswith("no source could be read")
    assert "missing.txt" in reply.error
    assert llm_calls("research") == []


def test_no_sources_is_an_error_without_the_llm(make_research, llm_calls):
    agent, sender, _ = make_research([answer("never used")])
    reply = agent.handle(lookup([]))
    assert reply.status == "error" and "at least one source" in reply.error
    assert sender.calls == [] and llm_calls("research") == []


def test_a_bad_payload_is_an_error_naming_the_field(make_research):
    agent, sender, _ = make_research([answer("x")])
    env = new_request(sender="planner", receiver="research", action="research.lookup",
                      resource="research:query", payload={"query": "q", "sources": [HR]},
                      chain_so_far=["user"], trace_id=TRACE)
    reply = agent.handle(env)
    assert reply.status == "error" and "max_sources" in reply.error and sender.calls == []


def test_other_actions_are_refused(make_research):
    agent, _, _ = make_research([])
    env = new_request(sender="planner", receiver="research", action="db.query_aggregate",
                      resource="db:employees", payload={"metric": "count"},
                      chain_so_far=["user"], trace_id=TRACE)
    reply = agent.handle(env)
    assert reply.status == "error" and "cannot perform" in reply.error


def test_observations_and_answer_are_cut(make_research, fake_llm, mocks_client):
    long_text = "x" * 3000
    agent, _, _ = make_research([answer("y" * 900)])
    assert len(agent.handle(lookup([HR])).result["answer"]) == MAX_ANSWER_CHARS

    class BigSender:
        def __call__(self, *, receiver, action, resource, payload, chain_so_far, trace_id):
            req = new_request(sender="research", receiver=receiver, action=action, resource=resource,
                              payload=payload, chain_so_far=chain_so_far, trace_id=trace_id)
            return make_response(req, ResponsePayload(status="ok", result={"content": long_text}))
    big = ResearchAgent(fake_llm("research", {"research.decide": [answer("ok")]}), BigSender())
    state = big.graph.invoke({"query": "q", "trace_id": TRACE, "chain": ["user"], "sources": [HR],
                              "reads": [], "extra": [], "decision": None, "answer": None, "error": None})
    assert len(state["reads"][0]["text"]) == MAX_OBSERVATION_CHARS


def test_one_extra_action_then_the_answer(make_research, truth, llm_calls):
    extra = {"done": False, "action": "file.read_internal", "resource": Q3,
             "payload": {"max_bytes": 4000}, "reason": "need the report"}
    agent, sender, _ = make_research([extra, answer("combined")])
    reply = agent.handle(lookup([HR]))
    assert reply.status == "ok" and reply.result["answer"] == "combined"
    assert [c["resource"] for c in sender.calls] == [HR, Q3]
    assert len(llm_calls("research")) == 2
    assert [r["details"]["path"] for r in truth(kind="file.read")] == ["/internal/hr_policy.txt",
                                                                       "/internal/q3_report.txt"]


def test_a_second_extra_action_is_an_error(make_research):
    extra = {"done": False, "action": "file.read_internal", "resource": Q3, "payload": {}, "reason": "more"}
    agent, sender, _ = make_research([extra, extra, answer("never")])
    reply = agent.handle(lookup([HR]))
    assert reply.status == "error" and reply.error == "no answer within the step limit"
    assert len(sender.calls) == 2


def test_the_step_limit_counts_reads_and_extra_actions(make_research):
    extra = {"done": False, "action": "file.read_internal", "resource": Q3, "payload": {}, "reason": "more"}
    agent, sender, _ = make_research([extra, answer("never")], max_steps=3)
    reply = agent.handle(lookup([HR, Q3, MARKET]))          # three reads use all three steps
    assert reply.status == "error" and len(sender.calls) == 3


def test_a_failing_extra_action_is_shown_to_the_model(make_research):
    extra = {"done": False, "action": "file.read_internal", "resource": "file:/internal/none.txt",
             "payload": {}, "reason": "try"}
    agent, _, llm = make_research([extra, answer("could not get it")])
    seen = []
    real = llm.decide

    def spy(**kw):
        seen.append(kw["prompt"])
        return real(**kw)
    llm.decide = spy
    assert agent.handle(lookup([HR])).status == "ok"
    assert "Extra step: file.read_internal on file:/internal/none.txt -> ERROR:" in seen[1]


def test_an_action_the_role_cannot_call_is_not_sent(make_research):
    bad = {"done": False, "action": "file.delete", "resource": "file:/internal/hr_policy.txt",
           "payload": {}, "reason": "no"}
    agent, sender, llm = make_research([bad, answer("fine")])
    seen = []
    real = llm.decide
    llm.decide = lambda **kw: (seen.append(kw["prompt"]), real(**kw))[1]
    assert agent.handle(lookup([HR])).status == "ok"
    assert [c["action"] for c in sender.calls] == ["file.read_internal"]       # only the seeded read
    assert "'file.delete' is not an available action" in seen[1]


def test_llm_failure_is_an_error_reply(make_research):
    agent, _, _ = make_research([])                     # script exhausted: the fake raises
    reply = agent.handle(lookup([HR]))
    assert reply.status == "error" and reply.error.startswith("research LLM failed")


def test_no_trust_scores_or_labels_in_the_reply(make_research):
    agent, _, _ = make_research([answer("fine")])
    text = json.dumps(agent.handle(lookup([HR])).model_dump())
    assert "trust" not in text.lower() and "scenario" not in text.lower()


# --- registry and wrapper ----------------------------------------------------------------------

def test_registry_knows_research_and_it_has_no_task_entry():
    import agents.research as research_module
    from wrapper import registry
    assert registry.AGENTS["research"] is research_module.handle
    assert "research" not in registry.TASKS


def test_through_the_wrapper_the_planner_is_served(tmp_path, make_research, monkeypatch):
    import httpx
    from fastapi.testclient import TestClient

    import agents.research as research_module
    from wrapper.app import create_app
    from wrapper.config import Settings
    from wrapper.send import send_message

    agent, _, _ = make_research([answer("Payroll exports stay inside corp.local.")])
    monkeypatch.setattr(research_module, "_default", agent)
    app = TestClient(create_app(Settings(mode="direct", agent_name="research", log_dir=tmp_path)))

    def route(request):
        r = app.request(request.method, request.url.path, content=request.read(), headers=dict(request.headers))
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)
    reply = send_message(
        receiver="research", action="research.lookup", resource="research:query",
        payload={"query": "May payroll be emailed?", "sources": [HR], "max_sources": 1},
        chain_so_far=["user"], trace_id="trace-wrap", token="stub-token-for-tests",
        environ={"MODE": "direct", "AGENT_NAME": "planner", "AGENT_URLS": "research=http://research.test"},
        client=httpx.Client(transport=httpx.MockTransport(route)))
    assert app.app.state.runtime.role == "research"
    assert (reply.sender, reply.receiver) == ("research", "planner")
    assert reply.payload["status"] == "ok"
    assert reply.payload["result"]["sources_read"] == [HR]
    assert app.post("/task", json={"task": "x"}).status_code == 404
