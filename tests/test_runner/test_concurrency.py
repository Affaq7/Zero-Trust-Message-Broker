"""Runner concurrency smoke test: N1 with 10 tasks at once, fake LLM.

A runner test only, not scenario P1 (P1 stays blocked on N4). The fake LLM
uses rules (not consumed, chosen by prompt text) so every task gets the
right reply however the 10 tasks interleave in the shared planner process.
"""

import csv

from runner.evaluate import evaluate
from runner.results import ResultsWriter
from runner.run import run_repetition
from runner.scenarios import DEFAULT_SCENARIOS_DIR, load_scenarios
from agents.llm import LLMSettings

CONCURRENCY = 10

FAKE_RULES = {
    "planner": {"planner.decide": {
        "rules": [{"if_prompt_contains": "OK. Result:",
                   "reply": {"done": True, "answer": "The total cost of Project X so far is 184,250."}}],
        "default": {"done": False, "action": "db.query_aggregate", "resource": "db:project_costs",
                    "payload": {"metric": "sum", "column": "amount", "filters": {"project": "Project X"}},
                    "reason": "sum the cost items of Project X"},
    }},
    "database": {"database.summarise": {"default": {"summary": "Project X cost items add up to 184,250."}}},
}


def test_n1_with_ten_concurrent_tasks(tmp_path):
    n1 = load_scenarios(DEFAULT_SCENARIOS_DIR)["N1"].model_copy(update={"fake_llm": FAKE_RULES})
    outcomes = run_repetition(n1, rep=1, run_dir=tmp_path / "results", concurrency=CONCURRENCY)

    assert [o.slot for o in outcomes] == list(range(CONCURRENCY))
    assert len({o.trace_id for o in outcomes}) == CONCURRENCY            # one trace per task
    assert all(o.status == "completed" and o.task_status == "ok" for o in outcomes), \
        [(o.slot, o.status, o.error) for o in outcomes]

    for o in outcomes:
        # Every task's records belong to that task only, and each did exactly one query.
        assert all(e["envelope"]["trace_id"] == o.trace_id for e in o.envelopes)
        assert [(e["logged_by"], e["direction"]) for e in o.envelopes] == [("database", "in"), ("database", "out")]
        assert [g["kind"] for g in o.ground_truth] == ["db.query"]
        ev = evaluate(n1, o)
        assert ev.task_completed, (o.slot, ev.criteria)
        # Regression: LLM calls are matched by trace_id, not time window. Each task
        # makes exactly 2 planner decisions and 1 database summary.
        assert [c["purpose"] for c in o.llm_calls] == ["planner.decide", "database.summarise", "planner.decide"]
        assert all(c["trace_id"] == o.trace_id for c in o.llm_calls)

    assert sum(len(o.llm_calls) for o in outcomes) == 3 * CONCURRENCY

    writer = ResultsWriter(tmp_path / "written", "concurrency")
    writer.start([n1], reps=1, llm_backend="fake", llm=LLMSettings(), max_minutes=None)
    for o in outcomes:
        writer.add(n1, o, evaluate(n1, o))
    writer.finish()
    with open(writer.dir / "results.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert [r["llm_calls"] for r in rows] == ["3"] * CONCURRENCY
    assert all(int(r["llm_time_ms"]) == sum(c["duration_ms"] for c in o.llm_calls)
               for r, o in zip(rows, outcomes))
    summary = (writer.dir / "summary.csv").read_text(encoding="utf-8").splitlines()
    assert summary[1].startswith(f"N1,normal,{CONCURRENCY},{CONCURRENCY},{CONCURRENCY},{CONCURRENCY}/{CONCURRENCY},")
