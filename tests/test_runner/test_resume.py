"""python -m runner --resume: carry on an interrupted run (fake LLM, real processes)."""

import csv
import json
import shutil

import pytest

import runner.__main__ as cli
from runner.run import run_repetition as real_run_repetition
from runner.scenarios import DEFAULT_SCENARIOS_DIR


@pytest.fixture
def scenarios_dir(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    for name in ("n1.json", "a9.json"):
        shutil.copy(DEFAULT_SCENARIOS_DIR / name, d / name)
    return d


def rows(run_dir):
    with open(run_dir / "results.csv", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def interrupt_on_call(n, monkeypatch):
    calls = {"n": 0}

    def fake(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == n:
            raise KeyboardInterrupt
        return real_run_repetition(*args, **kwargs)
    monkeypatch.setattr(cli, "run_repetition", fake)
    return calls


def test_interrupt_then_resume(tmp_path, scenarios_dir, monkeypatch):
    results = tmp_path / "results"
    base = ["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results)]
    interrupt_on_call(3, monkeypatch)
    assert cli.main(base + ["--reps", "3"]) == 130
    [run_dir] = list(results.iterdir())
    first = rows(run_dir)
    assert sorted((r["scenario_id"], r["rep"]) for r in first) == [("A9", ""), ("N1", "1"), ("N1", "2")]
    assert json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))["stopped_early"] is True

    # A half-written folder from the interrupted repetition is moved aside.
    (run_dir / "N1" / "c1" / "rep03").mkdir(parents=True)

    monkeypatch.setattr(cli, "run_repetition", real_run_repetition)
    assert cli.main(base + ["--resume", run_dir.name]) == 0
    after = rows(run_dir)
    assert sorted((r["scenario_id"], r["rep"]) for r in after) == [
        ("A9", ""), ("N1", "1"), ("N1", "2"), ("N1", "3")]                 # nothing repeated
    assert [r["trace_id"] for r in after[:3]] == [r["trace_id"] for r in first]
    assert all(r["task_completed"] == "true" for r in after if r["scenario_id"] == "N1")
    assert any(p.name.startswith("rep03.partial-") for p in (run_dir / "N1" / "c1").iterdir())

    meta = json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))
    assert meta["stopped_early"] is False and meta["rows"] == 4 and len(meta["resumes"]) == 1
    summary = (run_dir / "summary.csv").read_text(encoding="utf-8").splitlines()
    assert summary[1].startswith("N1,normal,1,3,3,3/3,")


def test_resume_of_a_finished_run_does_nothing(tmp_path, scenarios_dir, monkeypatch):
    results = tmp_path / "results"
    base = ["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results)]
    assert cli.main(base + ["--reps", "1"]) == 0
    [run_dir] = list(results.iterdir())
    before = (run_dir / "results.csv").read_text(encoding="utf-8")

    def must_not_run(*a, **kw):
        raise AssertionError("nothing should run")
    monkeypatch.setattr(cli, "run_repetition", must_not_run)
    assert cli.main(base + ["--resume", run_dir.name]) == 0
    assert (run_dir / "results.csv").read_text(encoding="utf-8") == before


def test_resume_refuses_changed_scenarios_and_bad_input(tmp_path, scenarios_dir, monkeypatch):
    results = tmp_path / "results"
    base = ["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results)]
    interrupt_on_call(1, monkeypatch)
    assert cli.main(base + ["--reps", "2"]) == 130
    [run_dir] = list(results.iterdir())

    data = json.loads((scenarios_dir / "n1.json").read_text(encoding="utf-8"))
    data["timeout_s"] = 600
    (scenarios_dir / "n1.json").write_text(json.dumps(data), encoding="utf-8")
    assert cli.main(base + ["--resume", run_dir.name]) == 2              # scenario file changed
    assert cli.main(base + ["--resume", "no-such-run"]) == 2
    assert cli.main(base + ["--resume", run_dir.name, "--reps", "5"]) == 2
