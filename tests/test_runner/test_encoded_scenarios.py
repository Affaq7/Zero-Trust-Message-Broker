"""The scenario files in scenarios/: N1 and N3 only so far.

Runs them through real processes with the fake LLM; the live run is manual
(python -m runner --llm ollama ...).
"""

import pytest

from mocks.seed import project_total
from runner.evaluate import evaluate
from runner.run import run_repetition
from runner.scenarios import DEFAULT_SCENARIOS_DIR, load_scenarios


@pytest.fixture(scope="module")
def scenarios():
    return load_scenarios(DEFAULT_SCENARIOS_DIR)


def test_only_n1_and_n3_are_encoded(scenarios):
    assert sorted(scenarios) == ["N1", "N3"]
    assert all(s.category == "normal" and s.baseline == "applicable" for s in scenarios.values())


def test_runner_only_fields(scenarios):
    assert scenarios["N1"].expected_decision == "ALLOW; reply is a total only"
    assert scenarios["N3"].expected_decision == "ALLOW"
    assert all(s.entitled_parties is None for s in scenarios.values())     # not filled yet


def test_n1_expected_total_matches_the_seed(scenarios):
    [number] = [c for c in scenarios["N1"].success_criteria if c.type == "answer_contains_number"]
    assert number.value == project_total("Project X")


@pytest.mark.parametrize("sid", ["N1", "N3"])
def test_passes_with_fake_llm(scenarios, sid, tmp_path):
    [o] = run_repetition(scenarios[sid], rep=1, run_dir=tmp_path / "results")
    ev = evaluate(scenarios[sid], o)
    assert o.status == "completed", o.error
    assert ev.task_completed, ev.criteria
    assert ev.sensitive_hits == 0
