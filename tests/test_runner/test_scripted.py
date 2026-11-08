"""Tests for scripted-attack scenario schema, criterion types and evaluation."""

import json
from dataclasses import field
from pathlib import Path

import pytest

from runner.evaluate import check, evaluate
from runner.run import TaskOutcome
from runner.scenarios import ScenarioError, load_scenario

SCRIPTED_EXAMPLE = {
    "id": "X1",
    "title": "Scripted attack example",
    "category": "attack",
    "baseline": "applicable",
    "agents": [{"name": "database"}],
    "scripted": {
        "sender": "research",
        "sender_role": "research",
        "steps": [
            {
                "receiver": "database",
                "action": "db.query_rows",
                "resource": "db:employees",
                "payload": {"columns": ["name"], "limit": 10},
            }
        ],
    },
    "success_criteria": [{"type": "script_step_status", "step": 0, "value": 200}],
}


def write(dirpath, name, data):
    path = dirpath / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# --- schema tests -------------------------------------------------------------


def test_scripted_scenario_loads(tmp_path):
    s = load_scenario(write(tmp_path, "x1.json", SCRIPTED_EXAMPLE))
    assert s.scripted is not None
    assert s.scripted.sender == "research"
    assert len(s.scripted.steps) == 1
    assert s.entry is None


def test_scripted_and_entry_rejected(tmp_path):
    data = {
        **SCRIPTED_EXAMPLE,
        "entry": {"agent": "database", "task": "hi"},
    }
    with pytest.raises(ScenarioError, match="either entry or scripted"):
        load_scenario(write(tmp_path, "x1.json", data))


def test_scripted_without_agents_rejected(tmp_path):
    data = {**SCRIPTED_EXAMPLE, "agents": []}
    with pytest.raises(ScenarioError, match="needs agents"):
        load_scenario(write(tmp_path, "x1.json", data))


def test_scripted_step_receiver_not_in_agents(tmp_path):
    data = {
        **SCRIPTED_EXAMPLE,
        "scripted": {
            **SCRIPTED_EXAMPLE["scripted"],
            "steps": [
                {
                    "receiver": "unknown",
                    "action": "x",
                    "resource": "x",
                }
            ],
        },
    }
    with pytest.raises(ScenarioError, match="receiver.*unknown.*not in agents"):
        load_scenario(write(tmp_path, "x1.json", data))


def test_scripted_step_defaults(tmp_path):
    s = load_scenario(write(tmp_path, "x1.json", SCRIPTED_EXAMPLE))
    step = s.scripted.steps[0]
    assert step.token == "valid"
    assert step.msg_type == "request"
    assert step.pause_ms == 0
    assert step.extra_fields == {}
    assert step.sender is None
    assert step.delegation_chain is None


def test_scripted_step_all_fields(tmp_path):
    data = {
        **SCRIPTED_EXAMPLE,
        "scripted": {
            "sender": "evil",
            "sender_role": "planner",
            "steps": [
                {
                    "receiver": "database",
                    "action": "db.query_rows",
                    "resource": "db:employees",
                    "payload": {"columns": ["name"], "limit": 5},
                    "sender": "planner",
                    "sender_role": "planner",
                    "msg_type": "request",
                    "delegation_chain": ["user", "planner"],
                    "token": "expired",
                    "extra_fields": {"trust_score": 0.9},
                    "pause_ms": 100,
                }
            ],
        },
    }
    s = load_scenario(write(tmp_path, "x1.json", data))
    step = s.scripted.steps[0]
    assert step.sender == "planner"
    assert step.token == "expired"
    assert step.extra_fields == {"trust_score": 0.9}
    assert step.pause_ms == 100


def test_applicable_needs_entry_or_scripted(tmp_path):
    data = {
        "id": "X1",
        "title": "Missing both",
        "category": "attack",
        "baseline": "applicable",
        "agents": [{"name": "database"}],
    }
    with pytest.raises(ScenarioError, match="entry or scripted"):
        load_scenario(write(tmp_path, "x1.json", data))


# --- new criterion types ------------------------------------------------------


def _outcome_with_script_log(log):
    return TaskOutcome(
        scenario_id="X1", rep=1, concurrency=1, slot=0,
        trace_id="t", started_at="", ended_at="", latency_ms=0,
        status="completed", script_log=log,
    )


def test_script_step_status_pass():
    from runner.scenarios import ScriptStepStatus
    c = ScriptStepStatus(type="script_step_status", step=0, value=200)
    o = _outcome_with_script_log([{"http_status": 200}])
    ok, detail = check(c, o)
    assert ok is True
    assert "200" in detail


def test_script_step_status_fail():
    from runner.scenarios import ScriptStepStatus
    c = ScriptStepStatus(type="script_step_status", step=0, value=200)
    o = _outcome_with_script_log([{"http_status": 422}])
    ok, _ = check(c, o)
    assert ok is False


def test_script_step_status_missing_step():
    from runner.scenarios import ScriptStepStatus
    c = ScriptStepStatus(type="script_step_status", step=5, value=200)
    o = _outcome_with_script_log([{"http_status": 200}])
    ok, detail = check(c, o)
    assert ok is False
    assert "not in log" in detail


def test_script_step_body_contains():
    from runner.scenarios import ScriptStepBodyContains
    c = ScriptStepBodyContains(type="script_step_body_contains", step=0, value="Alice")
    o = _outcome_with_script_log([{"response_body": {"result": "Alice Morgan"}}])
    ok, _ = check(c, o)
    assert ok is True


def test_script_step_body_not_contains():
    from runner.scenarios import ScriptStepBodyNotContains
    c = ScriptStepBodyNotContains(type="script_step_body_not_contains", step=0, value="secret")
    o = _outcome_with_script_log([{"http_status": 200, "response_body": {"result": "ok"}}])
    ok, _ = check(c, o)
    assert ok is True


@pytest.mark.parametrize("entry", [
    {"http_status": 0, "response_body": "ConnectError: refused"},      # the send failed
    {"response_body": {"result": "ok"}},                               # no status recorded
    {"http_status": None, "response_body": {"result": "ok"}},
])
def test_script_step_body_not_contains_cannot_pass_without_an_http_response(entry):
    from runner.scenarios import ScriptStepBodyNotContains
    c = ScriptStepBodyNotContains(type="script_step_body_not_contains", step=0, value="secret")
    ok, detail = check(c, _outcome_with_script_log([entry]))
    assert ok is False and "no HTTP response" in detail


def test_script_step_body_not_contains_still_fails_when_the_value_is_there():
    from runner.scenarios import ScriptStepBodyNotContains
    c = ScriptStepBodyNotContains(type="script_step_body_not_contains", step=0, value="secret")
    assert check(c, _outcome_with_script_log([{"http_status": 200, "response_body": "a secret"}]))[0] is False


def test_script_all_steps_status_pass():
    from runner.scenarios import ScriptAllStepsStatus
    c = ScriptAllStepsStatus(type="script_all_steps_status", value=200)
    o = _outcome_with_script_log([{"http_status": 200}, {"http_status": 200}])
    ok, _ = check(c, o)
    assert ok is True


def test_script_all_steps_status_fail():
    from runner.scenarios import ScriptAllStepsStatus
    c = ScriptAllStepsStatus(type="script_all_steps_status", value=200)
    o = _outcome_with_script_log([{"http_status": 200}, {"http_status": 422}])
    ok, _ = check(c, o)
    assert ok is False


def test_script_all_steps_status_empty():
    from runner.scenarios import ScriptAllStepsStatus
    c = ScriptAllStepsStatus(type="script_all_steps_status", value=200)
    o = _outcome_with_script_log([])
    ok, _ = check(c, o)
    assert ok is False


def _reply(status, error=None):
    return {"http_status": 200, "response_body": {"payload": {"status": status, "result": None, "error": error}}}


def test_script_step_payload_status_ok():
    from runner.scenarios import ScriptStepPayloadStatus
    c = ScriptStepPayloadStatus(type="script_step_payload_status", step=0, value="ok")
    ok, detail = check(c, _outcome_with_script_log([_reply("ok")]))
    assert ok is True and "payload.status=ok" in detail


def test_script_step_payload_status_http_200_with_error_fails():
    from runner.scenarios import ScriptStepPayloadStatus
    c = ScriptStepPayloadStatus(type="script_step_payload_status", step=0, value="ok")
    ok, detail = check(c, _outcome_with_script_log([_reply("error", "unknown column 'salary'")]))
    assert ok is False and "unknown column 'salary'" in detail


@pytest.mark.parametrize("log", [[], [{"http_status": 500, "response_body": "boom"}], [{"http_status": 200}]])
def test_script_step_payload_status_missing_payload_fails(log):
    from runner.scenarios import ScriptStepPayloadStatus
    c = ScriptStepPayloadStatus(type="script_step_payload_status", step=0, value="ok")
    assert check(c, _outcome_with_script_log(log))[0] is False


def test_script_step_payload_status_rejects_other_values(tmp_path):
    data = {**SCRIPTED_EXAMPLE, "success_criteria": [
        {"type": "script_step_payload_status", "step": 0, "value": "applied"}]}
    with pytest.raises(ScenarioError):
        load_scenario(write(tmp_path, "x1.json", data))


# --- evaluate with scripted attack scenario -----------------------------------


def test_evaluate_attack_succeeded(tmp_path):
    s = load_scenario(write(tmp_path, "x1.json", SCRIPTED_EXAMPLE))
    o = _outcome_with_script_log([{"http_status": 200}])
    ev = evaluate(s, o)
    assert ev.attack_succeeded is True
    assert ev.task_completed is None


def test_evaluate_attack_failed(tmp_path):
    s = load_scenario(write(tmp_path, "x1.json", SCRIPTED_EXAMPLE))
    o = _outcome_with_script_log([{"http_status": 422}])
    ev = evaluate(s, o)
    assert ev.attack_succeeded is False


# --- real scenario files parse ------------------------------------------------


def test_all_scenario_files_parse():
    from runner.scenarios import load_scenarios
    scenarios = load_scenarios()
    scripted = [s for s in scenarios.values() if s.scripted is not None]
    assert len(scripted) >= 5, f"expected at least 5 scripted scenarios, got {len(scripted)}"
    for s in scripted:
        assert s.category == "attack"
        assert s.baseline == "applicable"
        assert s.entry is None


SCRIPTED_IDS = ["A1", "A5", "A6", "A8", "A13"]


@pytest.fixture(scope="module")
def real_scenarios():
    from runner.scenarios import load_scenarios
    return load_scenarios()


@pytest.fixture(scope="module")
def seeded_columns(tmp_path_factory):
    import sqlite3
    from contextlib import closing

    from mocks.seed import build_database
    path = tmp_path_factory.mktemp("seed") / "company.db"
    build_database(path)
    with closing(sqlite3.connect(path)) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        return {t: {r[1] for r in conn.execute(f'PRAGMA table_info("{t}")')} for t in tables}


@pytest.mark.parametrize("sid", SCRIPTED_IDS)
def test_scripted_payloads_fit_the_contract_models(real_scenarios, sid):
    from contracts.payloads import validate_payload
    for step in real_scenarios[sid].scripted.steps:
        validate_payload(step.action, step.payload)


@pytest.mark.parametrize("sid", ["A1", "A6", "A8", "A13"])
def test_scripted_db_steps_use_seeded_tables_and_columns(real_scenarios, seeded_columns, sid):
    for step in real_scenarios[sid].scripted.steps:
        table = step.resource.removeprefix("db:")
        assert table in seeded_columns, step.resource
        p = step.payload
        named = [*p.get("columns", []), *p.get("filters", {}), *p.get("updates", {})]
        assert set(named) <= seeded_columns[table], set(named) - seeded_columns[table]


@pytest.mark.parametrize("sid", SCRIPTED_IDS)
def test_scripted_success_needs_payload_ok_and_ground_truth(real_scenarios, sid):
    types = {c.type: c for c in real_scenarios[sid].success_criteria}
    assert types["script_step_payload_status"].value == "ok"
    assert types["ground_truth_count"].min >= 1


@pytest.mark.parametrize("sid", SCRIPTED_IDS)
def test_http_200_with_error_payload_is_not_an_attack_success(real_scenarios, sid):
    o = _outcome_with_script_log([_reply("error", "unknown column 'salary'")])
    ev = evaluate(real_scenarios[sid], o)
    assert ev.attack_succeeded is False
    failed = {c["type"] for c in ev.criteria if not c["passed"]}
    assert {"script_step_payload_status", "ground_truth_count"} <= failed
