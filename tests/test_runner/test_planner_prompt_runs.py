"""Planner prompt version in the runner: scenario field, CLI override, run metadata,
research timings and the report flags."""

import csv
import hashlib
import json
from typing import get_args

import pytest
from pydantic import ValidationError

import runner.run as run_module
from agents.llm import LLMSettings
from agents.planner import PROMPT_VERSIONS, prompt_fingerprint
from runner.__main__ import main
from runner.processes import Testbed, TestbedConfig
from runner.report import LOOKUP_WARN_MS, lookup_lines, prompt_cells, render_md, scenario_rows
from runner.results import (
    COLUMNS,
    ResultsWriter,
    _row_from_csv,
    effective_planner_versions,
    lookup_durations_ms,
    scenario_checksum,
)
from runner.scenarios import Scenario
from tests.test_runner.test_evaluate_results import BASE, EXAMPLE_FILE, outcome, scenario


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# --- scenario field, checksum, resolution ----------------------------------------------------

def test_the_scenario_field_matches_the_planner_versions():
    allowed = get_args(get_args(Scenario.model_fields["planner_prompt"].annotation)[0])
    assert allowed == PROMPT_VERSIONS
    assert scenario().planner_prompt is None


@pytest.mark.parametrize("bad", ["v3", "V1", "", 2])
def test_unknown_version_in_a_scenario_is_refused(bad):
    with pytest.raises(ValidationError):
        scenario(planner_prompt=bad)


def test_checksum_is_unchanged_while_the_field_is_unset():
    # Runs made before the field existed hashed model_dump_json() without it.
    s = scenario()
    assert scenario_checksum(s) == hashlib.sha256(s.model_dump_json(exclude={"planner_prompt"}).encode("utf-8")).hexdigest()
    assert scenario_checksum(scenario(planner_prompt="v2")) != scenario_checksum(s)
    assert scenario_checksum(scenario(planner_prompt="v1")) != scenario_checksum(s)


def test_effective_versions_override_beats_field_beats_default():
    a, b = scenario(id="A1"), scenario(id="A2", planner_prompt="v2")
    na = scenario(id="A3", baseline="not_applicable", not_applicable_reason="x")
    assert effective_planner_versions([a, b, na]) == {"A1": "v1", "A2": "v2"}       # not_applicable runs nothing
    assert effective_planner_versions([a, b], "v2") == {"A1": "v2", "A2": "v2"}
    assert effective_planner_versions([a, b], "v1") == {"A1": "v1", "A2": "v1"}
    with pytest.raises(ValueError):
        effective_planner_versions([a], "v9")


# --- process environment ---------------------------------------------------------------------

def test_the_planner_process_gets_the_version(tmp_path):
    for given, expected in (("", ""), ("v2", "v2")):
        tb = Testbed(TestbedConfig(agents=[{"name": "dummy"}], run_dir=tmp_path / (given or "none"),
                                   planner_prompt=given))
        tb._plan()
        assert tb.procs["dummy"].env["PLANNER_PROMPT"] == expected


def test_inherited_planner_prompt_is_not_passed_on(monkeypatch, tmp_path):
    monkeypatch.setenv("PLANNER_PROMPT", "v2")
    tb = Testbed(TestbedConfig(agents=[{"name": "dummy"}], run_dir=tmp_path))
    tb._plan()
    assert tb.procs["dummy"].env["PLANNER_PROMPT"] == ""


class Stop(Exception):
    pass


@pytest.mark.parametrize("field, override, expected", [
    (None, None, ""), ("v2", None, "v2"), (None, "v2", "v2"), ("v2", "v1", "v1"), ("v1", None, "v1")])
def test_run_repetition_passes_the_version(monkeypatch, tmp_path, field, override, expected):
    seen = {}

    class Capture:
        def __init__(self, config):
            seen["config"] = config
            raise Stop

    monkeypatch.setattr(run_module, "Testbed", Capture)
    with pytest.raises(Stop):
        run_module.run_repetition(scenario(planner_prompt=field), 1, tmp_path, planner_prompt=override)
    assert seen["config"].planner_prompt == expected


# --- run_meta ---------------------------------------------------------------------------------

def start(tmp_path, scenarios, versions=None):
    w = ResultsWriter(tmp_path, "r")
    w.start(scenarios, reps=1, llm_backend="fake", llm=LLMSettings(), max_minutes=None, planner_versions=versions)
    return json.loads(w.meta_path.read_text(encoding="utf-8"))


def test_meta_records_one_version_and_its_fingerprint(tmp_path):
    meta = start(tmp_path, [scenario(id="A1"), scenario(id="A2")])
    assert meta["planner_prompt_version"] == "v1" and meta["mixed_planner_prompt_versions"] is False
    assert meta["planner_prompt_sha256"] == prompt_fingerprint("v1") == meta["planner_prompts"]["v1"]
    assert meta["scenario_planner_prompt"] == {"A1": "v1", "A2": "v1"}


def test_meta_for_a_v2_run(tmp_path):
    meta = start(tmp_path, [scenario(id="A1"), scenario(id="A2")], {"A1": "v2", "A2": "v2"})
    assert meta["planner_prompt_version"] == "v2"
    assert meta["planner_prompt_sha256"] == prompt_fingerprint("v2") != prompt_fingerprint("v1")


def test_meta_flags_a_mixed_run(tmp_path):
    meta = start(tmp_path, [scenario(id="A1"), scenario(id="A2", planner_prompt="v2")])
    assert meta["planner_prompt_version"] == "mixed" and meta["mixed_planner_prompt_versions"] is True
    assert meta["planner_prompt_sha256"] is None
    assert meta["planner_prompts"] == {"v1": prompt_fingerprint("v1"), "v2": prompt_fingerprint("v2")}
    assert meta["scenario_planner_prompt"] == {"A1": "v1", "A2": "v2"}


# --- research timings -------------------------------------------------------------------------

def env_row(by, direction, action, msg_id, parent, at):
    return {"logged_at": at, "logged_by": by, "direction": direction,
            "envelope": {"msg_id": msg_id, "parent_msg_id": parent, "action": action,
                         "msg_type": "request" if direction == "in" else "response"}}


LOOKUP_ENVELOPES = [
    env_row("research", "in", "research.lookup", "m1", None, "2026-10-24T10:00:00.000000Z"),
    env_row("tool", "in", "file.read_internal", "m2", "m1", "2026-10-24T10:00:01.000000Z"),
    env_row("tool", "out", "file.read_internal", "m3", "m2", "2026-10-24T10:00:02.000000Z"),
    env_row("research", "out", "research.lookup", "m4", "m1", "2026-10-24T10:00:21.500000Z"),
    env_row("planner", "in", "db.query_aggregate", "m5", None, "2026-10-24T10:00:22.000000Z"),
]


def test_lookup_duration_is_request_in_to_response_out_at_research():
    assert lookup_durations_ms(LOOKUP_ENVELOPES) == [21500]
    assert lookup_durations_ms([]) == [] and lookup_durations_ms(LOOKUP_ENVELOPES[1:3]) == []


def test_two_lookups_are_timed_separately():
    second = [env_row("research", "in", "research.lookup", "n1", None, "2026-10-24T10:01:00.000000Z"),
              env_row("research", "out", "research.lookup", "n2", "n1", "2026-10-24T10:01:05.000000Z")]
    assert lookup_durations_ms(LOOKUP_ENVELOPES + second) == [21500, 5000]


def test_results_row_has_research_time_and_slowest_lookup(tmp_path):
    w = ResultsWriter(tmp_path, "t")
    s = scenario()
    w.start([s], reps=1, llm_backend="fake", llm=LLMSettings(), max_minutes=None)
    calls = [{"purpose": "planner.decide", "duration_ms": 100}, {"purpose": "research.decide", "duration_ms": 7000},
             {"purpose": "tool.compose_email", "duration_ms": 50}]
    from runner.evaluate import evaluate
    with_lookup = outcome(envelopes=LOOKUP_ENVELOPES, llm_calls=calls)
    w.add(s, with_lookup, evaluate(s, with_lookup))
    without = outcome(rep=2)
    w.add(s, without, evaluate(s, without))
    first, second = read_csv(w.csv_path)
    assert list(first) == COLUMNS
    assert (first["research_llm_time_ms"], first["research_lookup_ms_max"], first["llm_time_ms"]) == (
        "7000", "21500", "7150")
    assert (second["research_llm_time_ms"], second["research_lookup_ms_max"]) == ("", "")
    back = _row_from_csv(first)
    assert back["research_llm_time_ms"] == 7000 and back["research_lookup_ms_max"] == 21500


# --- report -----------------------------------------------------------------------------------

def row(sid, rep, lookup_ms, research_ms, trace="t"):
    return {"run_id": "r", "scenario_id": sid, "category": "normal", "baseline": "applicable", "rep": rep,
            "status": "completed", "task_completed": True, "attack_succeeded": None, "e2e_latency_ms": 90000,
            "llm_calls": 3, "messages": 2, "trace_id": f"{trace}{rep}", "research_lookup_ms_max": lookup_ms,
            "research_llm_time_ms": research_ms, "not_applicable_reason": None}


META = {"mode": "direct", "git_commit": "abcdef1234", "planner_prompt_version": "v2",
        "planner_prompt_sha256": "e" * 64, "llm": {"backend": "fake"}}


def test_report_flags_every_lookup_over_45_seconds():
    rows = [row("N2", 1, 21500, 12000), row("N2", 2, LOOKUP_WARN_MS + 1, 30000), row("N2", 3, 44999, 20000)]
    text = "\n".join(lookup_lines([("r", META, rows)]))
    assert text.count("SLOW LOOKUP") == 1 and "N2 rep 2 (run r, trace t2): 45.0 s" in text
    assert "| N2 | 3 | 20.0 s | 45.0 s | 1 |" in text
    assert LOOKUP_WARN_MS == 45_000


def test_report_says_when_no_lookup_is_slow_and_stays_silent_without_lookups():
    text = "\n".join(lookup_lines([("r", META, [row("N2", 1, 30000, 10000)])]))
    assert "SLOW LOOKUP" not in text and "No lookup took longer than 45 s." in text
    assert lookup_lines([("r", META, [row("N1", 1, None, None)])]) == []


def test_scenario_rows_carry_the_research_columns():
    [t] = scenario_rows([row("N2", 1, 20000, 8000), row("N2", 2, 50000, 10000)])
    assert (t["median_research_llm_ms"], t["max_lookup_ms"], t["slow_lookups"]) == (9000, 50000, 1)
    [n1] = scenario_rows([row("N1", 1, None, None)])
    assert (n1["median_research_llm_ms"], n1["max_lookup_ms"], n1["slow_lookups"]) == (None, None, 0)


def test_the_runs_table_shows_version_and_flags_mixed_runs():
    assert prompt_cells(META)[0] == "v2" and "e" * 64 in prompt_cells(META)[1]
    mixed = {**META, "planner_prompt_version": "mixed", "planner_prompt_sha256": None,
             "mixed_planner_prompt_versions": True, "planner_prompts": {"v1": "a" * 64, "v2": "b" * 64},
             "scenario_planner_prompt": {"N1": "v1", "N2": "v2"}}
    version, cell, note = prompt_cells(mixed)
    assert version == "MIXED" and "v1: `" + "a" * 64 in cell and "v2: `" + "b" * 64 in cell
    assert note.startswith("WARNING") and "N1=v1, N2=v2" in note
    md = render_md("T", [("r", mixed, [row("N2", 1, 1000, 500)])], scenario_rows([row("N2", 1, 1000, 500)]))
    assert "| MIXED |" in md and "WARNING: this run mixes planner prompt versions" in md
    two = render_md("T", [("r1", META, []), ("r2", {**META, "planner_prompt_version": "v1"}, [])], [])
    assert "different planner prompt versions" in two


def test_an_old_run_without_versions_is_labelled():
    old = {"mode": "direct", "git_commit": "unknown", "planner_prompt_sha256": "c" * 64, "llm": {}}
    assert prompt_cells(old)[0] == "v1 (run predates prompt versions)"


# --- command line, end to end with the fake LLM -----------------------------------------------

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


def planner_prompt_file(run_dir):
    [path] = list(run_dir.glob("X1/c1/rep01/logs/prompts/planner/*/step01.txt"))
    return path.read_text(encoding="utf-8")


def test_default_run_uses_v1(tmp_path, scenarios_dir):
    code, run_dir = run_cli(tmp_path, scenarios_dir, "--debug-prompts")
    meta = json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))
    assert code == 0 and meta["planner_prompt_version"] == "v1"
    assert meta["planner_prompt_sha256"] == prompt_fingerprint("v1")
    assert "Known sources:" not in planner_prompt_file(run_dir)


def test_cli_override_runs_the_planner_with_v2(tmp_path, scenarios_dir):
    code, run_dir = run_cli(tmp_path, scenarios_dir, "--debug-prompts", "--planner-prompt", "v2")
    meta = json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))
    assert code == 0 and meta["planner_prompt_version"] == "v2"
    assert meta["scenario_planner_prompt"] == {"X1": "v2"}
    assert meta["planner_prompt_sha256"] == prompt_fingerprint("v2")
    assert "Known sources:" in planner_prompt_file(run_dir)
    assert read_csv(run_dir / "results.csv")[0]["task_completed"] == "true"


def test_a_scenario_can_ask_for_v2(tmp_path, scenarios_dir):
    (scenarios_dir / "x1.json").write_text(json.dumps({**EXAMPLE_FILE, "planner_prompt": "v2"}), encoding="utf-8")
    code, run_dir = run_cli(tmp_path, scenarios_dir, "--debug-prompts")
    assert "Known sources:" in planner_prompt_file(run_dir)
    assert json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))["planner_prompt_version"] == "v2"


def test_the_override_wins_over_the_scenario_file(tmp_path, scenarios_dir):
    (scenarios_dir / "x1.json").write_text(json.dumps({**EXAMPLE_FILE, "planner_prompt": "v2"}), encoding="utf-8")
    _, run_dir = run_cli(tmp_path, scenarios_dir, "--debug-prompts", "--planner-prompt", "v1")
    assert "Known sources:" not in planner_prompt_file(run_dir)


def test_a_mixed_run_is_announced_and_flagged(tmp_path, scenarios_dir, capsys):
    (scenarios_dir / "x2.json").write_text(
        json.dumps({**EXAMPLE_FILE, "id": "X2", "planner_prompt": "v2"}), encoding="utf-8")
    code, run_dir = run_cli(tmp_path, scenarios_dir)
    meta = json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))
    assert code == 0 and meta["planner_prompt_version"] == "mixed"
    assert "mixes planner prompt versions" in capsys.readouterr().out


def test_resume_takes_the_runs_own_versions(tmp_path, scenarios_dir, capsys):
    results = tmp_path / "results"
    assert main(["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results), "--reps", "1",
                 "--planner-prompt", "v2"]) == 0
    [run_dir] = list(results.iterdir())
    (run_dir / "results.csv").write_text(",".join(COLUMNS) + "\n", encoding="utf-8")      # as if nothing finished
    args = ["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results)]
    assert main([*args, "--resume", run_dir.name, "--planner-prompt", "v1"]) == 2
    assert "--planner-prompt" in capsys.readouterr().err
    assert main([*args, "--resume", run_dir.name, "--debug-prompts"]) == 0
    assert "Known sources:" in planner_prompt_file(run_dir)          # the resumed repetition ran with v2
