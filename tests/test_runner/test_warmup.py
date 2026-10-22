"""Runner warm-up before live runs (tested with the fake backend and stubs; no Ollama)."""

import csv
import json
import shutil

import pytest

import runner.__main__ as cli
from agents.llm import FakeLLM, LLMSettings, LLMUnavailableError
from runner.run import TaskOutcome
from runner.scenarios import DEFAULT_SCENARIOS_DIR
from runner.warmup import IDLE_LIMIT_S, Warmup, WarmupFailed, warm_up_call


class Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def make_warmup(backend="ollama", durations=None, clock=None, fail=False):
    calls = []

    def call():
        calls.append(1)
        if fail:
            raise LLMUnavailableError("Ollama unreachable")
        return (durations or [30.0] * 10)[len(calls) - 1]
    return Warmup(backend, call, clock or Clock()), calls


# --- when to warm up -------------------------------------------------------------

def test_first_scenario_is_warmed_and_recorded():
    w, calls = make_warmup(durations=[35.14])
    rec = w.before_scenario("N1")
    assert len(calls) == 1
    assert (rec["before_scenario"], rec["duration_s"], rec["ok"]) == ("N1", 35.1, True)
    assert rec["reason"] == "first scenario of this run" and rec["at"].endswith("Z")
    assert w.records == [rec]


def test_no_second_warmup_within_four_minutes():
    clock = Clock()
    w, calls = make_warmup(clock=clock)
    w.before_scenario("N1")
    w.note_repetition([])                          # no LLM calls: last activity = now
    clock.now += IDLE_LIMIT_S                      # exactly 4 minutes: still warm
    assert w.before_scenario("N3") is None
    assert len(calls) == 1


def test_warmup_again_after_more_than_four_minutes():
    clock = Clock()
    w, calls = make_warmup(clock=clock)
    w.before_scenario("N1")
    w.note_repetition([])
    clock.now += IDLE_LIMIT_S + 1
    rec = w.before_scenario("N3")
    assert len(calls) == 2 and rec["before_scenario"] == "N3"
    assert rec["reason"] == "241 s since the last LLM call"
    assert [r["before_scenario"] for r in w.records] == ["N1", "N3"]


def test_idle_time_counts_from_the_last_llm_call_of_a_repetition():
    clock = Clock(1_000_000.0)
    w, calls = make_warmup(clock=clock)
    w.before_scenario("N1")
    last_call = "1970-01-12T13:46:40Z"             # epoch 1,000,000 s
    outcome = TaskOutcome("N1", 1, 1, 0, "t", "x", "y", 5, "completed",
                          llm_calls=[{"logged_at": "1970-01-12T13:46:30Z"}, {"logged_at": last_call}])
    w.note_repetition([outcome])
    clock.now = 1_000_000.0 + IDLE_LIMIT_S - 1     # a long task ended just now: still warm
    assert w.before_scenario("N3") is None
    clock.now = 1_000_000.0 + IDLE_LIMIT_S + 1
    assert w.before_scenario("N3") is not None and len(calls) == 2


def test_fake_backend_never_warms_up():
    w, calls = make_warmup(backend="fake")
    assert w.enabled is False
    assert w.before_scenario("N1") is None and calls == [] and w.records == []


def test_failed_warmup_is_recorded_and_stops():
    w, calls = make_warmup(fail=True)
    with pytest.raises(WarmupFailed, match="LLMUnavailableError"):
        w.before_scenario("N1")
    assert w.records[0]["ok"] is False and w.records[0]["duration_s"] is None


def test_warm_up_call_is_one_small_json_call(tmp_path):
    llm = FakeLLM(LLMSettings(backend="fake"), "warmup", tmp_path,
                  script={"runner.warmup": [{"ok": True}]})
    assert warm_up_call(llm) >= 0
    [line] = [json.loads(l) for l in (tmp_path / "llm" / "warmup.jsonl").read_text(encoding="utf-8").splitlines()]
    assert line["purpose"] == "runner.warmup" and line["trace_id"] is None and line["est_prompt_tokens"] < 50


# --- through the command line --------------------------------------------------------

@pytest.fixture
def scenarios_dir(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    for name in ("n1.json", "n3.json", "a9.json"):
        shutil.copy(DEFAULT_SCENARIOS_DIR / name, d / name)
    return d


def read_meta(results):
    [run] = list(results.iterdir())
    return run, json.loads((run / "run_meta.json").read_text(encoding="utf-8"))


def test_fake_run_skips_warmup_and_says_so(tmp_path, scenarios_dir, monkeypatch):
    monkeypatch.setattr(cli, "warm_up_call", lambda llm: pytest.fail("fake runs must not warm up"))
    results = tmp_path / "results"
    assert cli.main(["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results),
                     "--scenario", "N1", "--reps", "1"]) == 0
    run, meta = read_meta(results)
    assert meta["warmups"] == [] and meta["warmup_note"] == "skipped: LLM backend is fake"
    assert not (run / "warmup_llm").exists()


def stub_live(monkeypatch, calls, durations=None):
    """A live-style run without Ollama: stub the warm-up call and the repetition."""
    durations = iter(durations or [40.0, 12.0])

    def warm(llm):
        calls.append("warm-up")
        return next(durations)

    def repetition(scenario, rep, run_dir, **kw):
        calls.append(f"{scenario.id} rep {rep}")
        assert kw["llm_backend"] == "ollama"
        return [TaskOutcome(scenario.id, rep, 1, 0, f"trace-{scenario.id}-{rep}", "2026-10-22T10:00:00Z",
                            "2026-10-22T10:01:00Z", 60000, "completed", task_status="ok", answer="x")]
    monkeypatch.setattr(cli, "make_warmup_client", lambda settings, log_dir: object())
    monkeypatch.setattr(cli, "warm_up_call", warm)
    monkeypatch.setattr(cli, "run_repetition", repetition)


def test_live_run_warms_up_once_before_the_first_scenario(tmp_path, scenarios_dir, monkeypatch):
    calls = []
    stub_live(monkeypatch, calls)
    results = tmp_path / "results"
    assert cli.main(["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results),
                     "--llm", "ollama", "--reps", "1"]) == 0
    assert calls == ["warm-up", "N1 rep 1", "N3 rep 1"]          # one warm-up, before the first task
    run, meta = read_meta(results)
    assert len(meta["warmups"]) == 1 and "warmup_note" not in meta
    assert meta["warmups"][0]["before_scenario"] == "N1" and meta["warmups"][0]["duration_s"] == 40.0
    assert meta["llm"]["backend"] == "ollama"


def test_warmup_time_never_enters_task_results(tmp_path, scenarios_dir, monkeypatch):
    calls = []
    stub_live(monkeypatch, calls, durations=[40.0])
    results = tmp_path / "results"
    cli.main(["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results),
              "--llm", "ollama", "--scenario", "N1", "--reps", "1"])
    run, meta = read_meta(results)
    with open(run / "results.csv", encoding="utf-8", newline="") as f:
        [row] = list(csv.DictReader(f))
    assert row["e2e_latency_ms"] == "60000"                       # the task's own time only
    assert row["llm_calls"] == "0" and row["llm_time_ms"] == "0"
    for name in ("events.jsonl", "ground_truth.jsonl", "criteria.jsonl", "summary.csv"):
        assert "warm" not in (run / name).read_text(encoding="utf-8").lower()
    assert "warm" not in row["trace_id"]


def test_warmup_failure_stops_before_any_task(tmp_path, scenarios_dir, monkeypatch, capsys):
    calls = []
    stub_live(monkeypatch, calls)

    def down(llm):
        calls.append("warm-up")
        raise LLMUnavailableError("Ollama unreachable")
    monkeypatch.setattr(cli, "warm_up_call", down)
    results = tmp_path / "results"
    assert cli.main(["--scenarios-dir", str(scenarios_dir), "--results-dir", str(results),
                     "--llm", "ollama", "--reps", "1"]) == 130
    assert calls == ["warm-up"]                                   # no task ran
    run, meta = read_meta(results)
    assert meta["stopped_early"] is True and meta["warmups"][0]["ok"] is False
    assert "warm-up failed" in capsys.readouterr().err
    assert not (run / "results.csv").exists() or "N1" not in (run / "results.csv").read_text(encoding="utf-8")
