"""runner --mode direct|broker: MODE for the agent processes, recorded in run_meta.json."""

import csv
import json

import pytest

import runner.run as run_module
from agents.llm import LLMSettings
from runner.__main__ import main
from runner.processes import Testbed, TestbedConfig
from runner.results import ResultsWriter
from tests.test_runner.test_evaluate_results import EXAMPLE_FILE, scenario


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# --- environment of the processes ------------------------------------------------------------------

@pytest.mark.parametrize("given, expected", [(None, "direct"), ("direct", "direct"), ("broker", "broker")])
def test_processes_get_the_mode(tmp_path, given, expected):
    config = TestbedConfig(agents=[{"name": "dummy"}, {"name": "planner"}], run_dir=tmp_path,
                           **({} if given is None else {"mode": given}))
    tb = Testbed(config)
    tb._plan()
    try:
        agents = {name: p for name, p in tb.procs.items() if name not in ("mocks", "broker")}
        assert {p.env["MODE"] for p in agents.values()} == {expected}
        assert "MODE" not in tb.procs["mocks"].env                   # the mock services have no mode
        assert ("broker" in tb.procs) == (expected == "broker")      # broker mode adds the broker process
    finally:
        tb.stop()                                                     # removes a broker run's temp keys


def test_an_inherited_mode_is_not_passed_on(monkeypatch, tmp_path):
    monkeypatch.setenv("MODE", "broker")
    tb = Testbed(TestbedConfig(agents=[{"name": "dummy"}], run_dir=tmp_path))
    tb._plan()
    assert tb.procs["dummy"].env["MODE"] == "direct"


class Stop(Exception):
    pass


@pytest.mark.parametrize("passed, expected", [(None, "direct"), ("broker", "broker")])
def test_run_repetition_passes_the_mode(monkeypatch, tmp_path, passed, expected):
    seen = {}

    class Capture:
        def __init__(self, config):
            seen["config"] = config
            raise Stop

    monkeypatch.setattr(run_module, "Testbed", Capture)
    with pytest.raises(Stop):
        run_module.run_repetition(scenario(), 1, tmp_path, **({} if passed is None else {"mode": passed}))
    assert seen["config"].mode == expected


# --- run_meta.json ---------------------------------------------------------------------------------

@pytest.mark.parametrize("mode", [None, "direct", "broker"])
def test_meta_records_the_mode(tmp_path, mode):
    w = ResultsWriter(tmp_path, "r")
    w.start([scenario()], reps=1, llm_backend="fake", llm=LLMSettings(), max_minutes=None,
            **({} if mode is None else {"mode": mode}))
    assert json.loads(w.meta_path.read_text(encoding="utf-8"))["mode"] == (mode or "direct")


# --- command line ----------------------------------------------------------------------------------

@pytest.fixture
def scenarios_dir(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "x1.json").write_text(json.dumps(EXAMPLE_FILE), encoding="utf-8")
    return d


def run_cli(tmp_path, scenarios_dir, *extra):
    results = tmp_path / "results"
    code = main(["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results), "--reps", "1", *extra])
    [run_dir] = list(results.iterdir())
    return code, run_dir


def meta_of(run_dir):
    return json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))


def test_default_is_direct_and_tasks_complete(tmp_path, scenarios_dir):
    code, run_dir = run_cli(tmp_path, scenarios_dir)
    assert code == 0 and meta_of(run_dir)["mode"] == "direct"
    assert read_csv(run_dir / "results.csv")[0]["task_completed"] == "true"


def test_broker_mode_runs_every_message_through_a_real_broker(tmp_path, scenarios_dir, capsys):
    code, run_dir = run_cli(tmp_path, scenarios_dir, "--mode", "broker")
    assert code == 0 and meta_of(run_dir)["mode"] == "broker"
    assert "MODE=broker" in capsys.readouterr().out
    [row] = read_csv(run_dir / "results.csv")
    # the planner's request went through the broker (real identity and policy) and was allowed
    assert row["task_completed"] == "true" and row["broker_decision"] == "ALLOW:POLICY_ALLOW"
    broker = meta_of(run_dir)["broker"]
    assert {"verify_identity", "evaluate_policy"} <= set(broker["broker_real"]) and broker["stubbed"]
    rep = run_dir / "X1" / "c1" / "rep01"
    assert (rep / "processes" / "broker.log").exists()
    assert [json.loads(line)["decision"] for line in
            (run_dir / "broker_decisions.jsonl").read_text(encoding="utf-8").splitlines()] == ["ALLOW"]


def test_the_report_shows_the_mode(tmp_path, scenarios_dir):
    from runner.report import load_run, render_md, scenario_rows
    _, run_dir = run_cli(tmp_path, scenarios_dir, "--mode", "broker")
    meta, rows = load_run(run_dir)
    assert "| broker |" in render_md("T", [("r", meta, rows)], scenario_rows(rows))


def test_an_unknown_mode_is_refused(tmp_path, scenarios_dir, capsys):
    with pytest.raises(SystemExit):
        main(["--scenarios-dir", str(scenarios_dir), "--mode", "both", "--dry-run"])
    assert "invalid choice" in capsys.readouterr().err


def test_resume_keeps_the_runs_mode_and_refuses_the_option(tmp_path, scenarios_dir, capsys):
    results = tmp_path / "results"
    assert main(["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results), "--reps", "1",
                 "--mode", "broker"]) == 0
    [run_dir] = list(results.iterdir())
    (run_dir / "results.csv").write_text(",".join(read_csv(run_dir / "results.csv")[0]) + "\n", encoding="utf-8")
    args = ["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results)]
    assert main([*args, "--resume", run_dir.name, "--mode", "direct"]) == 2
    assert "--mode" in capsys.readouterr().err
    assert main([*args, "--resume", run_dir.name]) == 0
    assert meta_of(run_dir)["mode"] == "broker"
    [row] = read_csv(run_dir / "results.csv")
    assert row["broker_decision"] == "ALLOW:POLICY_ALLOW"             # the resumed repetition ran in broker mode too
