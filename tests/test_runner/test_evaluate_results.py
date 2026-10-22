"""M2 step 15: criteria evaluator, results writer and the runner command line."""

import csv
import json

import pytest

from agents.llm import LLMSettings
from mocks.seed import sensitive_values
from runner.__main__ import main
from runner.evaluate import evaluate
from runner.results import COLUMNS, ResultsWriter
from runner.run import TaskOutcome
from runner.scenarios import Scenario

BASE = {
    "id": "X1", "title": "Example: count employees", "category": "normal",
    "agents": [{"name": "planner"}, {"name": "database"}],
    "entry": {"agent": "planner", "task": "How many employees are there?"},
    "success_criteria": [
        {"type": "task_status", "value": "ok"},
        {"type": "answer_contains", "value": "20"},
        {"type": "ground_truth_count", "kind": "db.query", "details": {"action": "db.query_aggregate"}},
    ],
}


def scenario(**change):
    return Scenario.model_validate({**BASE, **change})


def outcome(**change):
    data = dict(scenario_id="X1", rep=1, concurrency=1, slot=0, trace_id="trace-1",
                started_at="2026-10-21T10:00:00Z", ended_at="2026-10-21T10:00:05Z", latency_ms=5000,
                status="completed", task_status="ok", answer="There are 20 employees.",
                envelopes=[{"logged_at": "2026-10-21T10:00:01Z", "logged_by": "database", "direction": "in",
                            "envelope": {"msg_id": "m1", "parent_msg_id": None, "msg_type": "request",
                                         "sender": "planner", "receiver": "database",
                                         "action": "db.query_aggregate", "resource": "db:employees",
                                         "payload": {"metric": "count"}, "decision": None}}],
                ground_truth=[{"kind": "db.query", "trace_id": "trace-1", "recorded_at": "x",
                               "details": {"action": "db.query_aggregate"}}],
                llm_calls=[{"duration_ms": 100}, {"duration_ms": 200}])
    data.update(change)
    return TaskOutcome(**data)


# --- evaluator -------------------------------------------------------------------

def test_all_criteria_pass():
    ev = evaluate(scenario(), outcome())
    assert ev.task_completed is True and ev.passed == 3
    assert ev.attack_succeeded is None
    assert ev.over_exposure is None              # entitled_parties not filled yet
    assert ev.sensitive_hits == 0


@pytest.mark.parametrize("change, failing", [
    ({"task_status": "error"}, "task_status"),
    ({"answer": "Nineteen."}, "answer_contains"),
    ({"ground_truth": []}, "ground_truth_count"),
])
def test_one_failing_criterion_means_not_completed(change, failing):
    ev = evaluate(scenario(), outcome(**change))
    assert ev.task_completed is False
    assert [c["type"] for c in ev.criteria if not c["passed"]] == [failing]


def test_timeout_is_never_completed():
    assert evaluate(scenario(), outcome(status="timeout")).task_completed is False


def test_ground_truth_range_and_details():
    s = scenario(success_criteria=[{"type": "ground_truth_count", "kind": "mail.attempt",
                                    "details": {"status": "delivered", "external_recipients": []},
                                    "min": 1, "max": 1}])
    one = [{"kind": "mail.attempt", "details": {"status": "delivered", "external_recipients": []}}]
    assert evaluate(s, outcome(ground_truth=one)).task_completed is True
    assert evaluate(s, outcome(ground_truth=one * 2)).task_completed is False
    failed = [{"kind": "mail.attempt", "details": {"status": "failed", "external_recipients": []}}]
    assert evaluate(s, outcome(ground_truth=failed)).task_completed is False
    other = [{"kind": "mail.attempt", "details": {"status": "delivered",
                                                  "external_recipients": ["partner@example.org"]}}]
    assert evaluate(s, outcome(ground_truth=other)).task_completed is False


def test_answer_not_contains_is_case_insensitive():
    s = scenario(success_criteria=[{"type": "answer_not_contains", "value": "ERROR"}])
    assert evaluate(s, outcome(answer="all fine")).task_completed is True
    assert evaluate(s, outcome(answer="an error happened")).task_completed is False


@pytest.mark.parametrize("answer, ok", [
    ("The total is 184250.", True),
    ("The total is 184,250 EUR.", True),
    ("Total: 184 250", True),
    ("Total: 184.250", True),
    ("The total is 1842500.", False),
    ("The total is 18,425.", False),
    ("No number here.", False),
])
def test_answer_contains_number(answer, ok):
    s = scenario(success_criteria=[{"type": "answer_contains_number", "value": 184250}])
    assert evaluate(s, outcome(answer=answer)).task_completed is ok


def test_sensitive_values_are_counted_for_information():
    value = sensitive_values()["home_address"][0]
    ev = evaluate(scenario(), outcome(answer=f"There are 20 employees. {value}"))
    assert ev.sensitive_hits == 1 and ev.over_exposure is None


# --- writer ----------------------------------------------------------------------

def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def test_writer_files_and_columns(tmp_path):
    w = ResultsWriter(tmp_path, "run-1")
    s = scenario()
    w.start([s, scenario(id="X2", baseline="not_applicable", not_applicable_reason="needs the broker")],
            reps=1, llm_backend="fake", llm=LLMSettings(), max_minutes=None)
    o = outcome()
    w.add(s, o, evaluate(s, o))
    w.add_not_applicable(scenario(id="X2", baseline="not_applicable", not_applicable_reason="needs the broker"))
    w.finish()

    rows = read_csv(w.dir / "results.csv")
    assert list(rows[0]) == COLUMNS
    assert (rows[0]["status"], rows[0]["task_completed"], rows[0]["messages"], rows[0]["llm_time_ms"]) == (
        "completed", "true", "1", "300")
    assert rows[0]["over_exposure"] == "" and rows[0]["broker_decision"] == "" and rows[0]["detected"] == ""
    assert (rows[1]["scenario_id"], rows[1]["status"], rows[1]["task_completed"]) == ("X2", "not_applicable", "")

    meta = json.loads((w.dir / "run_meta.json").read_text(encoding="utf-8"))
    assert meta["mode"] == "direct" and meta["llm"]["num_ctx"] == 4096 and meta["llm"]["temperature"] == 0.0
    from agents.planner import prompt_fingerprint
    assert meta["planner_prompt_sha256"] == prompt_fingerprint()
    assert meta["not_applicable"] == {"X2": "needs the broker"}
    assert set(meta["scenarios"]) == {"X1", "X2"} and meta["ended_at"] and meta["rows"] == 2

    events = [json.loads(l) for l in (w.dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events[0]["action"] == "db.query_aggregate" and "payload" not in events[0]
    gt = [json.loads(l) for l in (w.dir / "ground_truth.jsonl").read_text(encoding="utf-8").splitlines()]
    assert gt[0]["kind"] == "db.query" and gt[0]["scenario_id"] == "X1"

    crit = [json.loads(l) for l in (w.dir / "criteria.jsonl").read_text(encoding="utf-8").splitlines()]
    assert crit[0]["answer"] == "There are 20 employees." and crit[0]["task_status"] == "ok"
    assert [(c["n"], c["type"], c["passed"]) for c in crit[0]["criteria"]] == [
        (1, "task_status", True), (2, "answer_contains", True), (3, "ground_truth_count", True)]
    assert crit[0]["criteria"][2]["kind"] == "db.query"           # criterion parameters kept
    assert rows[0]["criteria_failed"] == ""

    summary = read_csv(w.dir / "summary.csv")
    assert summary == [{"scenario_id": "X1", "category": "normal", "concurrency": "1", "runs": "1",
                        "completed": "1", "task_completed": "1/1", "attack_succeeded": "",
                        "median_latency_ms": "5000", "mean_latency_ms": "5000", "max_latency_ms": "5000"}]


def test_failed_criteria_are_named(tmp_path):
    w = ResultsWriter(tmp_path, "run-2")
    s = scenario()
    w.start([s], reps=1, llm_backend="fake", llm=LLMSettings(), max_minutes=None)
    o = outcome(answer="Nineteen.", ground_truth=[])
    w.add(s, o, evaluate(s, o))
    row = read_csv(w.dir / "results.csv")[0]
    assert row["criteria_failed"] == ("2:answer_contains (answer checked); "
                                      "3:ground_truth_count (0 matching db.query record(s))")
    crit = json.loads((w.dir / "criteria.jsonl").read_text(encoding="utf-8"))
    assert [c["passed"] for c in crit["criteria"]] == [True, False, False]


# --- command line --------------------------------------------------------------------

EXAMPLE_FILE = {**BASE, "fake_llm": {
    "planner": {"planner.decide": [
        {"done": False, "action": "db.query_aggregate", "resource": "db:employees",
         "payload": {"metric": "count"}, "reason": "count"},
        {"done": True, "answer": "There are 20 employees."}]},
    "database": {"database.summarise": [{"summary": "20 employees."}]}}}


@pytest.fixture
def scenarios_dir(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "x1.json").write_text(json.dumps(EXAMPLE_FILE), encoding="utf-8")
    (d / "x2.json").write_text(json.dumps({**BASE, "id": "X2", "baseline": "not_applicable",
                                           "not_applicable_reason": "needs the broker"}), encoding="utf-8")
    return d


def test_dry_run(scenarios_dir, capsys):
    assert main(["--scenarios-dir", str(scenarios_dir), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "ok  X1" in out and "not_applicable" in out


def test_unknown_scenario_and_empty_dir(tmp_path, scenarios_dir):
    assert main(["--scenarios-dir", str(scenarios_dir), "--scenario", "Z9", "--dry-run"]) == 2
    (tmp_path / "empty").mkdir()
    assert main(["--scenarios-dir", str(tmp_path / "empty"), "--dry-run"]) == 2


def test_full_run_with_fake_llm(tmp_path, scenarios_dir):
    results = tmp_path / "results"
    assert main(["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results), "--reps", "1"]) == 0
    [run_dir] = list(results.iterdir())
    rows = read_csv(run_dir / "results.csv")
    by_id = {r["scenario_id"]: r for r in rows}
    assert by_id["X1"]["status"] == "completed" and by_id["X1"]["task_completed"] == "true"
    assert by_id["X1"]["criteria_passed"] == by_id["X1"]["criteria_total"] == "3"
    assert by_id["X2"]["status"] == "not_applicable"
    assert read_csv(run_dir / "summary.csv")[0]["task_completed"] == "1/1"
