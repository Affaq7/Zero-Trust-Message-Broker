"""Unit tests for scripts/ci/check_smoke.py (results.csv assertions)."""

import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "ci"))

import check_smoke as cs  # noqa: E402

FIELDS = ["run_id", "scenario_id", "rep", "status", "task_completed", "attack_succeeded"]


def write(dir_: Path, rows, run_id="20260101T000000Z"):
    path = dir_ / run_id / "results.csv"
    path.parent.mkdir(parents=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({"run_id": run_id, "status": "completed", **r})


def test_pass_when_true(tmp_path):
    write(tmp_path, [{"scenario_id": "N1", "rep": 1, "task_completed": "true"}])
    assert cs.check(tmp_path, "N1", "task_completed")[0] == 0


def test_fail_when_false_or_empty(tmp_path):
    write(tmp_path, [{"scenario_id": "A1", "rep": 1, "attack_succeeded": "false"},
                     {"scenario_id": "A1", "rep": 2, "attack_succeeded": ""}])
    code, msg = cs.check(tmp_path, "A1", "attack_succeeded")
    assert code == 1 and "rep 1" in msg and "rep 2" in msg


def test_no_results_is_an_error(tmp_path):
    assert cs.check(tmp_path, "N1", "task_completed")[0] == 2
    write(tmp_path, [{"scenario_id": "N2", "rep": 1, "task_completed": "true"}])
    assert cs.check(tmp_path, "N1", "task_completed")[0] == 2
    assert cs.check(tmp_path, "N2", "no_such_column")[0] == 2


def test_more_than_one_run_is_an_error(tmp_path):
    write(tmp_path, [{"scenario_id": "N1", "rep": 1, "task_completed": "true"}], "r1")
    write(tmp_path, [{"scenario_id": "N1", "rep": 1, "task_completed": "true"}], "r2")
    assert cs.check(tmp_path, "N1", "task_completed")[0] == 2
