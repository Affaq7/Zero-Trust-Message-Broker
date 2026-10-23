"""Planner prompt versions: v1 (frozen, default) and v2 (candidate with research.lookup)."""

import json
import re

import pytest

import agents.planner as planner_module
from agents.base import TaskContext
from agents.llm import LLMSettings, estimate_tokens
from agents.planner import (
    DEFAULT_PROMPT_VERSION,
    FROZEN_PROMPT_FIELDS,
    PROMPT_VERSIONS,
    V2_ACTION_GUIDE,
    V2_KNOWN_SOURCES,
    V2_PROMPT_FIELDS,
    PlannerAgent,
    planner_actions,
    prompt_fingerprint,
    prompt_spec,
)
from contracts.payloads import ACTION_SCHEMAS, ResearchLookupPayload
from tests.test_agents.test_planner_agent import RecordingSender, finish, step

V1_HASH = "0d22529bac9fc91d4120a0d5bf913be8b8e345db4037b00cc102915bd6b02d22"
LOOKUP = step("research.lookup", "research:query", {
    "query": "What is the HR policy on payroll exports?", "sources": ["file:/internal/hr_policy.txt"],
    "max_sources": 1})


@pytest.fixture(autouse=True)
def no_version_in_env(monkeypatch):
    monkeypatch.delenv("PLANNER_PROMPT", raising=False)
    monkeypatch.delenv("PLANNER_MAX_STEPS", raising=False)


def make(fake_llm, version=None, replies=(), sender=None, **kw):
    sender = sender or RecordingSender()
    return PlannerAgent(fake_llm("planner", {"planner.decide": list(replies)}), sender,
                        prompt_version=version, **kw), sender


# --- v1 stays the default and unchanged -----------------------------------------------------------

def test_v1_is_the_default_and_keeps_its_recorded_hash(fake_llm):
    assert DEFAULT_PROMPT_VERSION == "v1" and PROMPT_VERSIONS == ("v1", "v2")
    assert prompt_fingerprint() == prompt_fingerprint("v1") == V1_HASH
    planner, _ = make(fake_llm)
    assert planner.spec.version == "v1" and planner.max_steps == 4
    assert "research" not in planner.system.lower()
    assert "research.lookup" not in planner_actions() and "research.lookup" not in planner_actions("v1")


def test_v1_hash_is_the_one_recorded_in_the_measurements_doc():
    from runner.scenarios import REPO_ROOT
    doc = (REPO_ROOT / "docs" / "measurements.md").read_text(encoding="utf-8")
    assert f"Frozen planner prompt SHA-256: `{V1_HASH}`" in doc


# --- the switch ---------------------------------------------------------------------------------

def test_env_picks_the_version(fake_llm, monkeypatch):
    monkeypatch.setenv("PLANNER_PROMPT", "v2")
    planner, _ = make(fake_llm)
    assert planner.spec.version == "v2" and planner.max_steps == 5


def test_argument_beats_env(fake_llm, monkeypatch):
    monkeypatch.setenv("PLANNER_PROMPT", "v2")
    assert make(fake_llm, "v1")[0].spec.version == "v1"


@pytest.mark.parametrize("bad", ["v3", "V2", "latest", "2"])
def test_unknown_version_is_refused(fake_llm, monkeypatch, bad):
    monkeypatch.setenv("PLANNER_PROMPT", bad)
    with pytest.raises(ValueError, match="unknown planner prompt version"):
        make(fake_llm)
    with pytest.raises(ValueError):
        prompt_spec(bad)
    with pytest.raises(ValueError):
        prompt_fingerprint(bad)


def test_step_limit_env_still_overrides_the_version_default(fake_llm, monkeypatch):
    monkeypatch.setenv("PLANNER_MAX_STEPS", "3")
    assert make(fake_llm, "v2")[0].max_steps == 3
    assert make(fake_llm, "v2", max_steps=2)[0].max_steps == 2


# --- what v2 offers -------------------------------------------------------------------------------

def test_v2_offers_research_lookup_and_everything_v1_offers():
    assert planner_actions("v2") == {**planner_actions("v1"), "research.lookup": "research"}
    assert set(V2_PROMPT_FIELDS) == set(FROZEN_PROMPT_FIELDS) | {"research.lookup"}
    assert set(V2_ACTION_GUIDE) == set(V2_PROMPT_FIELDS)


def test_v2_prompt_text(fake_llm):
    system = make(fake_llm, "v2")[0].system
    assert system.startswith(prompt_spec("v1").rules.removesuffix("\nActions you can use:\n"))  # v1's rules first
    assert "- research.lookup: use this when the task needs what a document or web page says" in system
    assert "fields: query (text, required); sources (list); max_sources (whole number, required)" in system
    assert 'example: "resource": "research:query"' in system
    assert "Use file.read_internal only when the task gives a file path itself." in system
    assert system.endswith(V2_KNOWN_SOURCES)
    assert system.count("Known sources:") == 1


def test_v2_example_is_valid_and_uses_a_known_source():
    use_when, resource, payload = V2_ACTION_GUIDE["research.lookup"]
    ResearchLookupPayload.model_validate(payload)
    assert resource == "research:query"
    assert set(payload["sources"]) <= set(re.findall(r"^- (\S+) ", V2_KNOWN_SOURCES, flags=re.M))


def test_every_v2_example_validates_and_uses_pinned_fields():
    for name, (use_when, resource, payload) in V2_ACTION_GUIDE.items():
        ACTION_SCHEMAS[name].model_validate(payload)
        assert set(payload) <= set(V2_PROMPT_FIELDS[name])


def test_known_sources_exist_in_the_fixtures(mocks_client):
    sources = re.findall(r"^- (\S+) ", V2_KNOWN_SOURCES, flags=re.M)
    assert len(sources) == 3
    for s in sources:
        path, resource = ("/web/fetch", s) if s.startswith("http") else ("/files/read", s)
        assert mocks_client.call(path, resource, {}, "t")["content"]


def test_the_known_sources_leave_out_the_injection_fixtures():
    for hidden in ("onboarding", "salary", "invoice", "protected", "audit"):
        assert hidden not in V2_KNOWN_SOURCES.lower()


def test_v2_closing_line_waits_for_everything_before_the_email(fake_llm):
    planner, _ = make(fake_llm, "v2")
    state = {"task": "t", "trace_id": "x", "chain": ["user"], "steps": 1, "decision": None, "answer": None,
             "error": None, "history": [{"action": "research.lookup", "resource": "research:query",
                                         "outcome": 'OK. Result: {"answer": "a"}'}]}
    last = planner._prompt(state).splitlines()[-1]
    assert "you now have everything it needs, send it now; otherwise get what is missing first." in last
    assert last.startswith("If the task only asks for information")


# --- fingerprints ---------------------------------------------------------------------------------

def test_v2_fingerprint_differs_from_v1_and_is_stable():
    assert prompt_fingerprint("v2") == prompt_fingerprint("v2") != V1_HASH
    assert re.fullmatch(r"[0-9a-f]{64}", prompt_fingerprint("v2"))


@pytest.mark.parametrize("name", ["V2_RULES", "V2_AFTER_SUCCESS", "V2_KNOWN_SOURCES"])
def test_editing_v2_changes_only_the_v2_fingerprint(monkeypatch, name):
    before = prompt_fingerprint("v2")
    monkeypatch.setattr(planner_module, name, getattr(planner_module, name) + " ")
    assert prompt_fingerprint("v2") != before
    assert prompt_fingerprint("v1") == V1_HASH


def test_editing_v1_text_changes_the_v1_fingerprint(monkeypatch):
    monkeypatch.setattr(planner_module, "SYSTEM", planner_module.SYSTEM + " ")
    assert prompt_fingerprint("v1") != V1_HASH


# --- budget ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("version", ["v1", "v2"])
def test_worst_case_history_fits_inside_the_context_window(fake_llm, version):
    planner, _ = make(fake_llm, version)
    spec, s = planner.spec, LLMSettings()
    system = estimate_tokens(planner.system)
    history = planner.max_steps * (spec.result_chars // 3 + 30)
    total = system + history + 200 + s.num_predict
    print(f"\n{version} budget (estimate): system={system} history={planner.max_steps}x"
          f"{spec.result_chars // 3 + 30}={history} 200 predict={s.num_predict} total={total} "
          f"limit={int(s.num_ctx * 0.8)} num_ctx={s.num_ctx}")
    assert system < 1800
    assert total < s.num_ctx * 0.8


def test_v2_trimmed_the_history_cut_not_the_test():
    assert prompt_spec("v1").result_chars == 1000 and prompt_spec("v2").result_chars == 500


def test_results_are_cut_at_the_versions_limit(fake_llm):
    big = "x" * 3000
    for version, limit in (("v1", 1000), ("v2", 500)):
        planner, _ = make(fake_llm, version, [step("db.query_rows", "db:projects", {"columns": ["name"]}),
                                              finish("done")], RecordingSender(result={"rows": big}))
        seen = []
        real = planner.llm.decide
        planner.llm.decide = lambda **kw: (seen.append(kw["prompt"]), real(**kw))[1]
        planner.run_task(TaskContext(task="t", trace_id=f"trace-{version}"))
        outcome = seen[1].splitlines()[1].split(" -> ", 1)[1]
        assert len(outcome) == limit


# --- behaviour ------------------------------------------------------------------------------------

def test_v2_sends_research_lookup_to_the_research_agent(fake_llm):
    planner, sender = make(fake_llm, "v2", [LOOKUP, finish("Exports stay inside corp.local.")],
                           RecordingSender(result={"answer": "Payroll exports must stay inside corp.local.",
                                                   "sources_read": ["file:/internal/hr_policy.txt"],
                                                   "sources_failed": []}))
    result = planner.run_task(TaskContext(task="Ask research about the payroll policy.", trace_id="trace-v2"))
    assert result.status == "ok" and "corp.local" in result.answer
    [call] = sender.calls
    assert (call["receiver"], call["action"], call["resource"]) == ("research", "research.lookup", "research:query")
    assert call["payload"]["sources"] == ["file:/internal/hr_policy.txt"]


def test_v1_cannot_send_research_lookup(fake_llm):
    planner, sender = make(fake_llm, "v1", [LOOKUP, finish("could not")])
    result = planner.run_task(TaskContext(task="Ask research.", trace_id="trace-v1"))
    assert sender.calls == [] and result.status == "ok"       # "not an available action" went back to the model


def test_v2_allows_five_actions_where_v1_allows_four(fake_llm):
    count = step("db.query_aggregate", "db:employees", {"metric": "count"})
    planner, sender = make(fake_llm, "v2", [count] * 5 + [finish("20")])
    assert planner.run_task(TaskContext(task="t", trace_id="t5")).status == "ok" and len(sender.calls) == 5
    planner, sender = make(fake_llm, "v1", [count] * 4 + [finish("20")])
    assert planner.run_task(TaskContext(task="t", trace_id="t4")).status == "ok" and len(sender.calls) == 4


def test_the_debug_prompt_file_shows_the_v2_system(fake_llm, tmp_path, monkeypatch):
    monkeypatch.setenv("PLANNER_DEBUG_PROMPTS", "1")
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    planner, _ = make(fake_llm, "v2", [finish("hi")])
    planner.run_task(TaskContext(task="t", trace_id="dbg"))
    text = (tmp_path / "prompts" / "planner" / "dbg" / "step01.txt").read_text(encoding="utf-8")
    assert "research.lookup" in text and "Known sources:" in text
    assert json.loads((tmp_path / "prompts" / "planner" / "dbg" / "step01.reply.json").read_text(encoding="utf-8"))["done"]
