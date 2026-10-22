"""python -m runner.report: per-run and combined baseline reports."""

import csv
import json
import shutil

import pytest

from runner.report import main
from runner.results import COLUMNS
from runner.scenarios import REPO_ROOT

LIVE_RUN = "20261021T232557Z"


def write_run(results, run_id, rows, *, fingerprint="f" * 64, commit="abc1234"):
    d = results / run_id
    d.mkdir(parents=True)
    meta = {"run_id": run_id, "mode": "direct", "git_commit": commit, "planner_prompt_sha256": fingerprint,
            "llm": {"backend": "ollama", "model": "llama3:8b", "num_ctx": 4096, "num_predict": 256,
                    "temperature": 0.0, "seed": "repetition number"},
            "stopped_early": False}
    (d / "run_meta.json").write_text(json.dumps(meta), encoding="utf-8")
    with open(d / "results.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in COLUMNS})
    return d


def row(sid, rep, latency, completed="true", calls=3, messages=1, status="completed"):
    return {"scenario_id": sid, "category": "normal", "baseline": "applicable", "rep": rep,
            "concurrency": 1, "slot": 0, "status": status, "task_completed": completed,
            "e2e_latency_ms": latency, "llm_calls": calls, "messages": messages}


NA_ROW = {"scenario_id": "A9", "category": "attack", "baseline": "not_applicable",
          "status": "not_applicable", "not_applicable_reason": "Needs the broker."}


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def test_single_run_report(tmp_path):
    d = write_run(tmp_path, "run-a", [row("N1", 1, 40000), row("N1", 2, 50000), row("N1", 3, 45000, completed="false",
                                                                                    calls=9, messages=4), NA_ROW])
    assert main(["run-a", "--results-dir", str(tmp_path)]) == 0
    table = {r["scenario_id"]: r for r in read_csv(d / "report.csv")}
    n1 = table["N1"]
    assert (n1["runs"], n1["task_completed"], n1["task_completed_rate"]) == ("3", "2/3", "0.667")
    assert (n1["median_latency_ms"], n1["mean_latency_ms"], n1["max_latency_ms"]) == ("45000", "45000", "50000")
    assert (n1["median_llm_calls"], n1["median_messages"]) == ("3", "1")
    assert (table["A9"]["baseline"], table["A9"]["not_applicable_reason"]) == ("not_applicable", "Needs the broker.")
    md = (d / "report.md").read_text(encoding="utf-8")
    assert "| N1 | normal | 3 | 2/3 (67%) | 45.0 s / 45.0 s / 50.0 s | 3 | 1 |" in md
    assert "- **A9**: Needs the broker." in md
    assert "ollama llama3:8b | 0.0 | 4096 / 256 | 1-3 (seed = repetition)" in md
    assert f"`{'f' * 64}`" in md and "recorded in run_meta.json" in md
    assert "| A9 |" not in md                                  # excluded from the results table


def test_timeouts_count_as_runs_but_not_latency(tmp_path):
    d = write_run(tmp_path, "run-b", [row("N3", 1, 80000), row("N3", 2, 900000, completed="false", status="timeout")])
    main(["run-b", "--results-dir", str(tmp_path)])
    n3 = read_csv(d / "report.csv")[0]
    assert (n3["runs"], n3["task_completed"], n3["max_latency_ms"]) == ("2", "1/2", "80000")


def test_combined_report_pools_runs(tmp_path):
    write_run(tmp_path, "run-a", [row("N1", 1, 40000), row("N1", 2, 42000)])
    write_run(tmp_path, "run-b", [row("N1", 1, 44000), NA_ROW])
    assert main(["run-a", "run-b", "--results-dir", str(tmp_path)]) == 0
    [combined] = [p for p in tmp_path.iterdir() if p.name.startswith("report-")]
    table = {r["scenario_id"]: r for r in read_csv(combined / "report.csv")}
    assert (table["N1"]["runs"], table["N1"]["task_completed"], table["N1"]["median_latency_ms"]) == ("3", "3/3", "42000")
    md = (combined / "report.md").read_text(encoding="utf-8")
    assert "| run-a |" in md and "| run-b |" in md
    assert (tmp_path / "run-a" / "report.md").exists() and (tmp_path / "run-b" / "report.md").exists()


def test_missing_run_is_an_error(tmp_path):
    assert main(["no-such-run", "--results-dir", str(tmp_path)]) == 2


def test_unrecorded_fingerprint_is_reported_honestly(tmp_path):
    d = write_run(tmp_path, "run-c", [row("N1", 1, 40000)], fingerprint="", commit="unknown")
    main(["run-c", "--results-dir", str(tmp_path)])
    assert "not recorded" in (d / "report.md").read_text(encoding="utf-8")


@pytest.mark.skipif(not (REPO_ROOT / "results" / LIVE_RUN / "results.csv").exists(),
                    reason=f"live run {LIVE_RUN} is only on the developer's machine (results/ is gitignored)")
def test_live_run_20261021T232557Z(tmp_path):
    shutil.copytree(REPO_ROOT / "results" / LIVE_RUN, tmp_path / LIVE_RUN,
                    ignore=shutil.ignore_patterns("report.*"))
    assert main([LIVE_RUN, "--results-dir", str(tmp_path)]) == 0
    table = {r["scenario_id"]: r for r in read_csv(tmp_path / LIVE_RUN / "report.csv")}
    assert (table["N1"]["task_completed"], table["N1"]["median_latency_ms"], table["N1"]["max_latency_ms"],
            table["N1"]["median_llm_calls"], table["N1"]["median_messages"]) == ("3/3", "40177", "45059", "3", "1")
    assert (table["N3"]["task_completed"], table["N3"]["median_latency_ms"],
            table["N3"]["median_llm_calls"], table["N3"]["median_messages"]) == ("3/3", "83939", "5", "2")
    md = (tmp_path / LIVE_RUN / "report.md").read_text(encoding="utf-8")
    assert "| 20261021T232557Z | direct | ollama llama3:8b | 0.0 | 4096 / 256 | 1-3 (seed = repetition) | `b06fae7` |" in md
