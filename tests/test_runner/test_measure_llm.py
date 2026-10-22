"""python -m runner.measure_llm (tested with the fake LLM; the live run is the user's)."""

import pytest

import runner.measure_llm as m
from agents.llm import FakeLLM, LLMSettings, LLMUnavailableError
from agents.planner import prompt_fingerprint

DECISION = {"done": False, "action": "db.query_aggregate", "resource": "db:project_costs",
            "payload": {"metric": "sum", "column": "amount", "filters": {"project": "Project X"}},
            "reason": "measure"}


def fake(tmp_path):
    return FakeLLM(LLMSettings(backend="fake"), "measure", tmp_path,
                   script={"measure.planner": {"default": DECISION}})


def doc(tmp_path):
    d = tmp_path / "measurements.md"
    d.write_text("# Measurements\n\nExisting text.\n", encoding="utf-8")
    return d


def test_prompts_are_planner_sized_and_differ_per_call():
    system, user = m.planner_prompts()
    assert "You are the planner agent of Zephyr Corp." in system
    assert user(1) != user(2) and "(measurement call 2)" in user(2)
    assert user(1).endswith("Choose the next action, or finish.")


def test_measure_counts_warmup_separately(tmp_path):
    result = m.measure(fake(tmp_path), calls=10)
    assert len(result["durations_s"]) == 10 and result["failed"] == 0 and result["warmup_s"] >= 0
    s = m.stats(result)
    assert s["min"] <= s["median"] <= s["max"] and s["spread"] == pytest.approx(s["max"] - s["min"])


def test_record_adds_one_row_per_measurement(tmp_path):
    d = doc(tmp_path)
    result = {"warmup_s": 30.0, "durations_s": [18.0, 19.0, 21.0], "failed": 0, "calls": 3}
    for _ in range(2):
        m.record(d, result, m.stats(result), LLMSettings(), prompt_fingerprint())
    text = d.read_text(encoding="utf-8")
    assert text.startswith("# Measurements\n\nExisting text.\n")
    assert text.count(m.HEADING) == 1 and text.count("| Date (UTC) |") == 1
    rows = [l for l in text.splitlines() if l.startswith("| 20")]
    assert len(rows) == 2
    assert "| 3 | 19.0 s | 18.0 s | 21.0 s | 3.0 s | 19.3 s | 0 | 30.0 s | llama3:8b | 4096 |" in rows[0]
    assert f"`{prompt_fingerprint()[:12]}`" in rows[0]


def test_cli_writes_with_the_live_client_replaced_by_fake(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "make_client", lambda settings, log_dir: fake(tmp_path))
    d = doc(tmp_path)
    assert m.main(["--calls", "4", "--doc", str(d), "--log-dir", str(tmp_path)]) == 0
    assert "| 4 |" in d.read_text(encoding="utf-8")
    assert m.main(["--calls", "2", "--doc", str(d), "--no-write"]) == 0
    assert d.read_text(encoding="utf-8").count("| 20") == 1           # --no-write left it alone


def test_unreachable_llm_records_nothing(tmp_path, monkeypatch):
    class Down:
        def decide(self, **kw):
            raise LLMUnavailableError("Ollama unreachable")
    monkeypatch.setattr(m, "make_client", lambda settings, log_dir: Down())
    d = doc(tmp_path)
    before = d.read_text(encoding="utf-8")
    assert m.main(["--calls", "3", "--doc", str(d)]) == 2
    assert d.read_text(encoding="utf-8") == before
    assert m.main(["--calls", "0", "--doc", str(d)]) == 2


def test_fake_backend_in_the_shell_is_ignored(tmp_path, monkeypatch):
    seen = {}

    def capture(settings, log_dir):
        seen["settings"] = settings
        return fake(tmp_path)
    monkeypatch.setenv("LLM_BACKEND", "fake")
    monkeypatch.setattr(m, "make_client", capture)
    m.main(["--calls", "1", "--no-write"])
    assert seen["settings"].backend == "ollama"
