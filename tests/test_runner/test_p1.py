"""Scenario P1 (N4 at concurrency 1, 10 and 50, fake LLM) and the per-level statistics."""

import csv
import json

import pytest

from runner.__main__ import main
from runner.evaluate import evaluate
from runner.report import performance_lines, render_md, scenario_rows
from runner.results import level_stats, percentile
from runner.run import run_repetition
from runner.scenarios import DEFAULT_SCENARIOS_DIR, load_scenarios


@pytest.fixture(scope="module")
def scenarios():
    return load_scenarios(DEFAULT_SCENARIOS_DIR)


# --- the file -----------------------------------------------------------------------------------

def test_p1_is_n4_at_three_levels_with_a_fake_script_that_survives_interleaving(scenarios):
    p1, n4 = scenarios["P1"], scenarios["N4"]
    assert (p1.category, p1.baseline, p1.concurrency) == ("performance", "applicable", [1, 10, 50])
    assert p1.entry == n4.entry and p1.agents == n4.agents and p1.success_criteria == n4.success_criteria
    assert p1.expected_decision == "Latency and throughput overhead measured"
    planner = p1.fake_llm["planner"]["planner.decide"]
    assert not isinstance(planner, list) and len(planner.rules) == 3          # rules, not consumed in order
    for agent, purposes in p1.fake_llm.items():
        assert all(not isinstance(v, list) for v in purposes.values()), agent


def test_the_rules_pick_each_step_from_the_prompt_history(scenarios):
    rules = scenarios["P1"].fake_llm["planner"]["planner.decide"]
    first = rules.default
    assert first["action"] == "research.lookup"

    def pick(prompt):
        return next((r.reply for r in rules.rules if r.if_prompt_contains in prompt), rules.default)
    assert pick("User task: x")["action"] == "research.lookup"
    assert pick("Step 1: research.lookup on research:query -> OK")["action"] == "db.query_aggregate"
    assert pick("Step 1: research.lookup ...\nStep 2: db.query_aggregate on db:x -> OK")["action"] == \
        "tool.send_email_internal"
    assert pick("Step 1: a\nStep 2: db.query_aggregate\nStep 3: tool.send_email_internal -> DELIVERED")["done"]


def test_rules_scripts_are_validated():
    from pydantic import ValidationError

    from runner.scenarios import Scenario
    base = json.loads((DEFAULT_SCENARIOS_DIR / "n1.json").read_text(encoding="utf-8"))
    with pytest.raises(ValidationError):
        Scenario.model_validate({**base, "fake_llm": {"planner": {"planner.decide": {}}}})
    with pytest.raises(ValidationError):
        Scenario.model_validate({**base, "fake_llm": {"planner": {"planner.decide": {"rules": [{"reply": 1}]}}}})
    with pytest.raises(ValidationError):
        Scenario.model_validate({**base, "fake_llm": {"planner": {"planner.decide": {"oops": 1}}}})


# --- statistics ---------------------------------------------------------------------------------

@pytest.mark.parametrize("values, q, expected", [
    ([5], 95, 5), ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50, 5), ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95, 10),
    (list(range(1, 51)), 95, 48), (list(range(1, 51)), 50, 25), ([3, 1, 2], 100, 3)])
def test_percentile_is_nearest_rank(values, q, expected):
    assert percentile(values, q) == expected


def row(rep, start, end, lat, status="completed", done=True, msgs=5):
    return {"scenario_id": "P1", "category": "performance", "rep": rep, "concurrency": 10, "status": status,
            "task_completed": done, "e2e_latency_ms": lat, "messages": msgs,
            "started_at": f"2026-11-03T10:00:{start:06.3f}Z", "ended_at": f"2026-11-03T10:00:{end:06.3f}Z"}


def test_level_stats_wall_time_and_throughput():
    rows = [row(1, 0.0, 10.0, 10000), row(1, 0.5, 20.0, 19500), row(1, 1.0, 30.0, 29000, "timeout", False)]
    s = level_stats(rows)
    assert (s["tasks"], s["completed"], s["task_completed"]) == (3, 2, 2)
    assert (s["p50_ms"], s["p95_ms"], s["max_ms"]) == (14750, 19500, 19500)       # completed tasks only (median of 10000 and 19500)
    assert s["wall_s"] == 30.0 and s["throughput_per_s"] == round(2 / 30.0, 3)
    assert s["median_messages"] == 5


def test_wall_time_is_summed_over_repetitions():
    s = level_stats([row(1, 0.0, 10.0, 10000), row(2, 0.0, 20.0, 20000)])
    assert s["wall_s"] == 30.0 and s["throughput_per_s"] == round(2 / 30.0, 3)


def test_no_completed_task_gives_empty_numbers():
    s = level_stats([row(1, 0.0, 5.0, 5000, "error", False)])
    assert (s["completed"], s["p50_ms"], s["p95_ms"]) == (0, None, None) and s["throughput_per_s"] == 0.0


def test_the_report_has_a_concurrency_table_and_keeps_performance_out_of_the_scenario_table():
    rows = [row(1, 0.0, 10.0, 10000, msgs=5)]
    rows[0].update(run_id="r", baseline="applicable", trace_id="t", attack_succeeded=None, llm_calls=7,
                   not_applicable_reason=None)
    meta = {"mode": "direct", "git_commit": "abc1234", "planner_prompt_version": "v2",
            "planner_prompt_sha256": "e" * 64, "llm": {"backend": "fake"}}
    lines = "\n".join(performance_lines([("r", meta, rows)]))
    assert "| P1 | 10 | 1/1 | 1/1 | 10.0 s | 10.0 s | 5 | 10.0 s | 0.100 tasks/s |" in lines
    md = render_md("T", [("r", meta, rows)], scenario_rows(rows))
    assert "## Performance (concurrency levels)" in md and "| P1 | performance |" not in md


# --- runs (fake LLM, real processes) ----------------------------------------------------------

def test_p1_at_concurrency_one_and_ten(scenarios, tmp_path):
    p1 = scenarios["P1"]
    for level in (1, 10):
        outcomes = run_repetition(p1, rep=1, run_dir=tmp_path / "results", concurrency=level)
        assert len(outcomes) == level
        for o in outcomes:
            ev = evaluate(p1, o)
            assert o.status == "completed" and ev.task_completed, (level, o.slot, o.error, ev.criteria)
            assert sum(1 for e in o.envelopes if e["direction"] == "in") == 5       # N4's five messages
            assert len(o.llm_calls) == 7
            assert all(e["envelope"]["trace_id"] == o.trace_id for e in o.envelopes)


def test_cli_records_levels_in_the_summary(scenarios, tmp_path):
    results = tmp_path / "results"
    one = tmp_path / "scenarios"
    one.mkdir()
    p1 = json.loads((DEFAULT_SCENARIOS_DIR / "p1.json").read_text(encoding="utf-8"))
    (one / "p1.json").write_text(json.dumps({**p1, "concurrency": [1, 3]}), encoding="utf-8")
    assert main(["--scenarios-dir", str(one), "--results-dir", str(results), "--reps", "1"]) == 0
    [run_dir] = list(results.iterdir())
    with open(run_dir / "summary.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert [(r["scenario_id"], r["concurrency"], r["runs"], r["completed"], r["task_completed"]) for r in rows] == [
        ("P1", "1", "1", "1", "1/1"), ("P1", "3", "3", "3", "3/3")]
    assert all(r["median_messages"] == "5" and float(r["wall_time_s"]) > 0 and float(r["throughput_per_s"]) > 0
               and int(r["p95_latency_ms"]) > 0 for r in rows)
