"""Research prompt: pinned actions, validated examples, size budget, fingerprint and debug output."""

import json
import re

import pytest

import agents.research as research
from agents.llm import LLMSettings, estimate_tokens
from agents.research import (
    ACTION_GUIDE,
    DEFAULT_MAX_STEPS,
    MAX_OBSERVATION_CHARS,
    PROMPT_ACTIONS,
    PROMPT_FIELDS,
    ResearchAgent,
    prompt_actions,
    prompt_fingerprint,
    research_actions,
    sample_states,
)
from contracts.payloads import ACTION_SCHEMAS, ResearchLookupPayload

from tests.test_agents.test_research_agent import HR, MARKET, TRACE, ToolSender, answer, lookup  # noqa: F401


@pytest.fixture
def agent(fake_llm):
    return ResearchAgent(fake_llm("research", {}), lambda **k: None)


# --- pinned actions and examples ----------------------------------------------------------------

def test_the_prompt_offers_exactly_the_pinned_actions(agent):
    assert set(prompt_actions()) == set(PROMPT_ACTIONS) == set(ACTION_GUIDE) == set(PROMPT_FIELDS)
    assert set(prompt_actions()) <= set(research_actions())
    for name in PROMPT_ACTIONS:
        assert f"- {name}: use this only when" in agent.system
    for name in ("planner.request", "file.delete", "db.query_rows", "mail.deliver", "research.lookup"):
        assert name not in agent.system


def test_every_example_is_valid_for_its_payload_model():
    for name, (use_when, resource, payload) in ACTION_GUIDE.items():
        ACTION_SCHEMAS[name].model_validate(payload)
        assert use_when and resource
        assert set(payload) <= set(PROMPT_FIELDS[name])


@pytest.mark.parametrize("name, pattern", [
    ("db.query_aggregate", r"^db:\w+$"),
    ("file.read_internal", r"^file:/\S+$"),
    ("web.fetch_page", r"^https?://\S+$"),
])
def test_example_resources_have_the_right_shape(name, pattern):
    assert re.match(pattern, ACTION_GUIDE[name][1])


def test_pinned_fields_exist_on_the_payload_models():
    for name, fields in PROMPT_FIELDS.items():
        assert set(fields) <= set(ACTION_SCHEMAS[name].model_fields)


def test_the_examples_name_nothing_that_exists_in_the_fixtures(mocks_client):
    # An example that works would invite the model to copy it instead of reading the question.
    from agents.mocks_client import MockServiceError
    for name, path in (("file.read_internal", "/files/read"), ("web.fetch_page", "/web/fetch")):
        _, resource, payload = ACTION_GUIDE[name]
        with pytest.raises(MockServiceError):
            mocks_client.call(path, resource, payload, TRACE)


def test_the_prompt_does_not_hint_at_the_scenario_answers(agent):
    for text in ("5.2", "hr_policy", "q3_report", "q3-market", "corp.local"):
        assert text.lower() not in agent.system.lower()


# --- size budget --------------------------------------------------------------------------------

def worst_case_prompt(agent):
    read = {"source": "file:/internal/" + "x" * 60 + ".txt", "ok": True, "text": "y" * MAX_OBSERVATION_CHARS}
    step = {"action": "file.read_internal", "resource": "file:/internal/" + "z" * 60 + ".txt",
            "outcome": "OK. " + "w" * MAX_OBSERVATION_CHARS}
    state = {"query": "q" * 500, "trace_id": "t", "chain": ["user"], "sources": [], "decision": None,
             "answer": None, "error": None, "reads": [read] * 3, "extra": [step]}
    return agent._prompt(state)


def test_worst_case_prompt_fits_inside_the_context_window(agent):
    s = LLMSettings()
    system, user = estimate_tokens(agent.system), estimate_tokens(worst_case_prompt(agent))
    total = system + user + s.num_predict
    print(f"\nresearch budget (estimate): system={system} worst-case user={user} "
          f"num_predict={s.num_predict} total={total} limit={int(s.num_ctx * 0.8)} num_ctx={s.num_ctx}")
    assert system < 1500
    assert total < s.num_ctx * 0.8


def test_the_worst_case_has_three_reads_and_one_extra_step(agent):
    assert research.MAX_EXTRA_ACTIONS == 1 and DEFAULT_MAX_STEPS == 4
    with pytest.raises(ValueError):
        ResearchLookupPayload.model_validate({"query": "q", "sources": [HR], "max_sources": 4})


# --- prompt rendering -----------------------------------------------------------------------------

def test_sample_prompts_by_state(agent):
    prompts = {k: agent._prompt(s) for k, s in sample_states().items()}
    assert prompts["first"].startswith("Question: Which rule applies")
    assert "Source 1 (file:/internal/hr_policy.txt):\nPayroll exports" in prompts["first"]
    assert prompts["first"].endswith(research.CHOOSE_NEXT)
    assert "COULD NOT BE READ: file not found" in prompts["one_failed"]
    assert "Extra step: file.read_internal on file:/internal/q3_report.txt -> OK. Q3 revenue" in prompts["after_ok"]
    assert prompts["after_ok"].endswith(research.STEP_LIMIT)                  # one extra action is all there is
    assert prompts["after_error"].endswith(research.STEP_LIMIT)
    assert prompts["at_limit"].endswith(research.STEP_LIMIT)


def test_sample_states_are_fixed():
    assert json.dumps(sample_states(), sort_keys=True) == json.dumps(sample_states(), sort_keys=True)
    assert list(sample_states()) == ["first", "one_failed", "after_ok", "after_error", "at_limit"]


# --- fingerprint ----------------------------------------------------------------------------------

def test_fingerprint_is_stable_and_is_a_sha256():
    assert prompt_fingerprint() == prompt_fingerprint()
    assert re.fullmatch(r"[0-9a-f]{64}", prompt_fingerprint())


def test_fingerprint_is_not_the_planners():
    from agents.planner import prompt_fingerprint as planner_fingerprint
    assert prompt_fingerprint() != planner_fingerprint()


@pytest.mark.parametrize("name, value", [
    ("SYSTEM", research.SYSTEM + "- one more rule.\n"),
    ("CHOOSE_NEXT", "Choose."),
    ("STEP_LIMIT", "Stop."),
])
def test_fingerprint_changes_with_the_prompt(monkeypatch, name, value):
    before = prompt_fingerprint()
    monkeypatch.setattr(research, name, value)
    assert prompt_fingerprint() != before


def test_fingerprint_changes_with_an_example(monkeypatch):
    before = prompt_fingerprint()
    use_when, resource, payload = ACTION_GUIDE["file.read_internal"]
    monkeypatch.setitem(ACTION_GUIDE, "file.read_internal", (use_when, resource, {"max_bytes": 1000}))
    assert prompt_fingerprint() != before


def test_fingerprint_changes_with_the_source_rendering(monkeypatch):
    before = prompt_fingerprint()
    monkeypatch.setattr(research, "SAMPLE_QUERY", "Another question?")
    assert prompt_fingerprint() != before


# --- debug output ---------------------------------------------------------------------------------

def run_lookup(fake_llm, mocks_client, script):
    from agents.tool import ToolAgent
    llm = fake_llm("research", {"research.decide": script})
    agent = ResearchAgent(llm, ToolSender(ToolAgent(fake_llm("tool", {}), mocks_client)))
    return agent, agent.handle(lookup([HR, MARKET]))


def test_debug_is_off_by_default(tmp_path, monkeypatch, fake_llm, mocks_client):
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.delenv("RESEARCH_DEBUG_PROMPTS", raising=False)
    agent, reply = run_lookup(fake_llm, mocks_client, [answer("fine")])
    assert agent.debug_dir is None and reply.status == "ok"
    assert not (tmp_path / "logs" / "prompts").exists()


def test_debug_writes_prompt_and_reply_per_decision(tmp_path, monkeypatch, fake_llm, mocks_client):
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("RESEARCH_DEBUG_PROMPTS", "1")
    extra = {"done": False, "action": "file.read_internal", "resource": "file:/internal/q3_report.txt",
             "payload": {"max_bytes": 4000}, "reason": "need it"}
    _, reply = run_lookup(fake_llm, mocks_client, [extra, answer("final")])
    assert reply.status == "ok"
    folder = tmp_path / "logs" / "prompts" / "research" / TRACE
    assert sorted(p.name for p in folder.iterdir()) == ["step01.reply.json", "step01.txt",
                                                        "step02.reply.json", "step02.txt"]
    first = (folder / "step01.txt").read_text(encoding="utf-8")
    assert first.startswith("--- SYSTEM ---\nYou are the research agent") and "--- USER ---\nQuestion:" in first
    assert "Extra step: file.read_internal" in (folder / "step02.txt").read_text(encoding="utf-8")
    assert json.loads((folder / "step01.reply.json").read_text(encoding="utf-8"))["action"] == "file.read_internal"
    assert json.loads((folder / "step02.reply.json").read_text(encoding="utf-8"))["answer"] == "final"


def test_debug_records_an_llm_failure(tmp_path, monkeypatch, fake_llm, mocks_client):
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("RESEARCH_DEBUG_PROMPTS", "1")
    _, reply = run_lookup(fake_llm, mocks_client, [])
    assert reply.status == "error"
    folder = tmp_path / "logs" / "prompts" / "research" / TRACE
    assert "error" in json.loads((folder / "step01.reply.json").read_text(encoding="utf-8"))


def test_the_runner_turns_the_debug_switch_on_for_the_agents(tmp_path):
    from runner.processes import Testbed, TestbedConfig
    for flag, expected in ((False, ""), (True, "1")):
        tb = Testbed(TestbedConfig(agents=[{"name": "research"}], run_dir=tmp_path / str(flag), debug_prompts=flag))
        tb._plan()
        assert tb.procs["research"].env["RESEARCH_DEBUG_PROMPTS"] == expected
