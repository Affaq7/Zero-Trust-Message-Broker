"""M2 step 14: runner process start/stop and one repetition (fake LLM).

These tests start real uvicorn processes on free local ports.
"""

import os

import httpx
import pytest

from runner.processes import Testbed, TestbedConfig, clean_base_env, port_is_free
from runner.run import run_repetition
from runner.scenarios import Scenario


def all_stopped(tb: Testbed) -> bool:
    started = [p for p in tb.procs.values() if p.popen]
    return bool(started) and tb.leftover_ports == [] and \
        all(p.popen.poll() is not None for p in started) and \
        all(port_is_free(p.port) for p in started)


def dummy_config(tmp_path, **kw):
    return TestbedConfig(agents=[{"name": "dummy", "impl": None, "role": None}], run_dir=tmp_path / "run", **kw)


# --- process lifecycle ------------------------------------------------------------

def test_start_health_and_stop(tmp_path):
    with Testbed(dummy_config(tmp_path)) as tb:
        assert httpx.get(f"{tb.url('mocks')}/health").json()["service"] == "mocks"
        assert httpx.get(f"{tb.url('dummy')}/health").json() == {"status": "ok", "agent": "dummy", "mode": "direct"}
    assert all_stopped(tb)


def test_nothing_left_after_an_exception(tmp_path):
    tb = Testbed(dummy_config(tmp_path))
    with pytest.raises(RuntimeError, match="boom"):
        with tb:
            raise RuntimeError("boom")
    assert all_stopped(tb)


def test_nothing_left_after_ctrl_c(tmp_path):
    tb = Testbed(dummy_config(tmp_path))
    with pytest.raises(KeyboardInterrupt):
        with tb:
            raise KeyboardInterrupt
    assert all_stopped(tb)


def test_nothing_left_when_a_process_fails_to_start(tmp_path):
    cfg = TestbedConfig(agents=[{"name": "dummy", "impl": "no-such-impl", "role": None}], run_dir=tmp_path / "run")
    tb = Testbed(cfg)
    with pytest.raises(RuntimeError, match="exited during startup"):
        tb.start()
    assert all_stopped(tb)
    assert "unknown agent implementation" in (tmp_path / "run" / "processes" / "dummy.log").read_text(encoding="utf-8")


def test_controlled_variables_are_not_inherited(monkeypatch):
    monkeypatch.setenv("MODE", "broker")
    monkeypatch.setenv("AGENT_IMPL", "something")
    monkeypatch.setenv("LLM_SEED", "999")
    monkeypatch.setenv("RESEARCH_MAX_STEPS", "9")
    env = clean_base_env()
    assert not any(k in env for k in ("MODE", "AGENT_IMPL", "LLM_SEED", "RESEARCH_MAX_STEPS"))
    assert env["CREWAI_DISABLE_TELEMETRY"] == "true"


def test_processes_get_runner_settings(tmp_path):
    tb = Testbed(dummy_config(tmp_path, seed=7))
    tb._plan()
    env = tb.procs["dummy"].env
    assert (env["MODE"], env["AGENT_NAME"], env["LLM_SEED"], env["AGENT_IMPL"]) == ("direct", "dummy", "7", "")
    assert env["MOCKS_URL"] == tb.procs["mocks"].url
    assert env["PLANNER_DEBUG_PROMPTS"] == ""                      # off by default
    on = Testbed(dummy_config(tmp_path, debug_prompts=True))
    on._plan()
    assert on.procs["dummy"].env["PLANNER_DEBUG_PROMPTS"] == "1"
    assert env["AGENT_URLS"] == f"dummy=http://127.0.0.1:{tb.procs['dummy'].port}"


# --- one repetition -------------------------------------------------------------------

EXAMPLE = Scenario.model_validate({
    "id": "X1", "title": "Example: count employees", "category": "normal",
    "agents": [{"name": "planner"}, {"name": "database"}],
    "entry": {"agent": "planner", "task": "How many employees are there?"},
    "fake_llm": {
        "planner": {"planner.decide": [
            {"done": False, "action": "db.query_aggregate", "resource": "db:employees",
             "payload": {"metric": "count"}, "reason": "count"},
            {"done": True, "answer": "There are 20 employees."}]},
        "database": {"database.summarise": [{"summary": "20 employees."}]},
    },
})


def test_one_repetition_end_to_end(tmp_path):
    [o] = run_repetition(EXAMPLE, rep=1, run_dir=tmp_path / "results")
    assert o.status == "completed" and o.task_status == "ok"
    assert o.answer == "There are 20 employees."
    assert [(e["logged_by"], e["direction"]) for e in o.envelopes] == [("database", "in"), ("database", "out")]
    assert [g["kind"] for g in o.ground_truth] == ["db.query"]
    assert [c["purpose"] for c in o.llm_calls] == ["planner.decide", "database.summarise", "planner.decide"]
    assert {c["seed"] for c in o.llm_calls} == {1}                 # seed = repetition number
    assert o.latency_ms > 0


def test_concurrent_tasks_get_separate_traces(tmp_path):
    scenario = EXAMPLE.model_copy(update={"fake_llm": {
        "planner": {"planner.decide": [{"done": True, "answer": "ok"}] * 3}}})
    outcomes = run_repetition(scenario, rep=2, run_dir=tmp_path / "results", concurrency=3)
    assert [o.slot for o in outcomes] == [0, 1, 2]
    assert len({o.trace_id for o in outcomes}) == 3
    assert all(o.status == "completed" and o.answer == "ok" for o in outcomes)
