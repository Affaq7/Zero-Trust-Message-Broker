"""M2 step 13: scenario schema and loader (neutral example scenarios only)."""

import ast
import json
import re
from pathlib import Path

import pytest

from runner.scenarios import ScenarioError, load_scenario, load_scenarios

REPO_ROOT = Path(__file__).resolve().parents[2]

EXAMPLE = {
    "id": "X1",
    "title": "Example: count employees",
    "category": "normal",
    "agents": [{"name": "planner"}, {"name": "database"}],
    "entry": {"agent": "planner", "task": "How many employees are there?"},
    "success_criteria": [
        {"type": "task_status", "value": "ok"},
        {"type": "answer_contains", "value": "20"},
        {"type": "ground_truth_count", "kind": "db.query", "details": {"action": "db.query_aggregate"}, "min": 1},
    ],
}


def write(dirpath, name, data):
    path = dirpath / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_example_loads_with_defaults(tmp_path):
    s = load_scenario(write(tmp_path, "x1.json", EXAMPLE))
    assert s.id == "X1" and s.baseline == "applicable"
    assert (s.reps, s.timeout_s, s.concurrency) == (1, 900, [1])
    assert s.expected_decision is None and s.entitled_parties is None     # left unfilled
    assert [c.type for c in s.success_criteria] == ["task_status", "answer_contains", "ground_truth_count"]


def test_unfilled_fields_accepted_when_present(tmp_path):
    s = load_scenario(write(tmp_path, "x1.json", {**EXAMPLE, "expected_decision": None, "entitled_parties": None}))
    assert s.entitled_parties is None


def test_load_directory_ignores_subfolders(tmp_path):
    write(tmp_path, "x1.json", EXAMPLE)
    write(tmp_path, "x2.json", {**EXAMPLE, "id": "X2"})
    (tmp_path / "source").mkdir()
    write(tmp_path / "source", "other.json", {"not": "a scenario"})
    assert sorted(load_scenarios(tmp_path)) == ["X1", "X2"]


def test_duplicate_ids_rejected(tmp_path):
    write(tmp_path, "a.json", EXAMPLE)
    write(tmp_path, "b.json", EXAMPLE)
    with pytest.raises(ScenarioError, match="duplicate"):
        load_scenarios(tmp_path)


@pytest.mark.parametrize("change", [
    {"id": "x1"},
    {"category": "other"},
    {"agents": []},
    {"agents": [{"name": "planner"}, {"name": "planner"}]},
    {"entry": {"agent": "tool", "task": "x"}},                       # entry not started
    {"entry": {"agent": "planner", "task": ""}},
    {"fake_llm": {"tool": {"tool.compose_email": []}}},               # agent not started
    {"baseline": "not_applicable"},                                   # needs a reason
    {"concurrency": [0]},
    {"reps": 0},
    {"success_criteria": [{"type": "unknown"}]},
    {"success_criteria": [{"type": "ground_truth_count", "kind": "db.query", "min": 3, "max": 1}]},
    {"agents": [{"name": "planner", "extra": 1}, {"name": "database"}]},
    {"surprise": True},
])
def test_invalid_scenarios_rejected(tmp_path, change):
    with pytest.raises(ScenarioError):
        load_scenario(write(tmp_path, "bad.json", {**EXAMPLE, **change}))


def test_not_applicable_with_reason(tmp_path):
    s = load_scenario(write(tmp_path, "x3.json", {**EXAMPLE, "id": "X3", "baseline": "not_applicable",
                                                   "not_applicable_reason": "needs the broker"}))
    assert s.baseline == "not_applicable"


def test_bad_json_reported_with_path(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ScenarioError, match="broken.json"):
        load_scenario(path)


def _docstrings(tree):
    nodes = [tree, *[n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))]]
    return {id(n.body[0].value) for n in nodes
            if n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}


def test_agent_code_never_reads_runner_data():
    # Agents must not import the runner or the mock world's data (seeded
    # sensitive values), and must not mention runner-only names in code.
    words = re.compile(r"scenarios|expected_decision|entitled_parties|trust_score", re.I)
    hits = []
    for path in (REPO_ROOT / "agents").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        skip = _docstrings(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module or ""]
            else:
                mods = []
            hits += [f"{path.name}: imports {m}" for m in mods if m.split(".")[0] in {"runner", "mocks"}]
            if isinstance(node, ast.Name) and words.search(node.id):
                hits.append(f"{path.name}: name {node.id}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip \
                    and words.search(node.value):
                hits.append(f"{path.name}: string {node.value[:40]!r}")
    assert hits == []
