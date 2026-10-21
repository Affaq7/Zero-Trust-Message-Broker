"""M2 step 1: mock-services skeleton, seeded database, ground-truth log."""

import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mocks.config import DEFAULT_LOG_DIR, DEFAULT_RUNTIME_DIR, MockSettings, load_mock_settings
from mocks.ground_truth import GroundTruthLog
from mocks.seed import NAMES, SENSITIVE_COLUMNS, build_database, sensitive_values

REPO_ROOT = Path(__file__).resolve().parents[2]


def query(db_path, sql, *args):
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute(sql, args).fetchall()


def dump(db_path):
    with closing(sqlite3.connect(db_path)) as conn:
        return list(conn.iterdump())


# --- seed ------------------------------------------------------------------------

def test_seed_is_deterministic(tmp_path):
    build_database(tmp_path / "a.sqlite")
    build_database(tmp_path / "b.sqlite")
    assert dump(tmp_path / "a.sqlite") == dump(tmp_path / "b.sqlite")


def test_seed_contents(tmp_path):
    db = tmp_path / "c.sqlite"
    build_database(db)
    assert query(db, "SELECT COUNT(*) FROM employees") == [(len(NAMES),)]
    assert query(db, "SELECT COUNT(*) FROM payroll") == [(len(NAMES),)]
    assert query(db, "SELECT COUNT(DISTINCT dept) FROM employees") == [(5,)]
    emails = [r[0] for r in query(db, "SELECT email FROM employees")]
    assert all(e.endswith("@corp.local") for e in emails)
    # every payroll row belongs to an employee
    assert query(db, "SELECT COUNT(*) FROM payroll p LEFT JOIN employees e "
                     "ON p.employee_id = e.id WHERE e.id IS NULL") == [(0,)]


def test_sensitive_markers_unique_and_present(tmp_path):
    db = tmp_path / "d.sqlite"
    build_database(db)
    values = sensitive_values()
    assert set(values) == {c for cols in SENSITIVE_COLUMNS.values() for c in cols}
    flat = [v for vs in values.values() for v in vs]
    assert len(flat) == len(set(flat)) == 4 * len(NAMES)    # no value repeats anywhere
    for table, cols in SENSITIVE_COLUMNS.items():
        for col in cols:
            stored = {str(r[0]) for r in query(db, f"SELECT {col} FROM {table}")}
            assert stored == set(values[col])


def test_markers_look_realistic():
    v = sensitive_values()
    assert all(s[0] == "9" and len(s) == 11 and s[3] == s[6] == "-" for s in v["ssn"])
    assert all(b.startswith("GB") and "ZTTB" in b and len(b) == 22 for b in v["bank_account"])
    assert all("Testford" in a for a in v["home_address"])
    assert all(40000 < int(s) < 200000 for s in v["salary"])


def test_build_database_replaces_existing_file(tmp_path):
    db = tmp_path / "e.sqlite"
    build_database(db)
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("DELETE FROM payroll")
        conn.commit()
    build_database(db)
    assert query(db, "SELECT COUNT(*) FROM payroll") == [(len(NAMES),)]


# --- app -------------------------------------------------------------------------

def test_health(mocks):
    assert mocks.get("/health").json() == {"status": "ok", "service": "mocks"}


def test_startup_builds_db_in_path_with_space(mocks, mock_settings):
    assert " " in str(mock_settings.db_path)
    assert mock_settings.db_path.exists()


def test_reset_restores_seed(mocks, mock_settings):
    before = dump(mock_settings.db_path)
    with closing(sqlite3.connect(mock_settings.db_path)) as conn:
        conn.execute("UPDATE payroll SET salary = 1")
        conn.execute("DELETE FROM employees WHERE id > 10")
        conn.commit()
    assert mocks.post("/reset").json() == {"status": "ok"}
    assert dump(mock_settings.db_path) == before


def test_reset_recorded_in_ground_truth(mocks, truth):
    mocks.post("/reset", headers={"X-Trace-Id": "t-reset"})
    records = truth(trace_id="t-reset")
    assert [r["kind"] for r in records] == ["reset"]
    assert records[0]["recorded_at"].endswith("Z")


def test_ground_truth_filters(mocks, truth):
    mocks.post("/reset", headers={"X-Trace-Id": "t-1"})
    mocks.post("/reset", headers={"X-Trace-Id": "t-2"})
    assert len(truth(trace_id="t-1")) == 1
    assert len(truth(kind="reset")) == 3              # startup + 2
    future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    assert truth(since=future) == []
    assert len(truth(until=future)) == 3


def test_overlong_trace_header_rejected(mocks):
    assert mocks.post("/reset", headers={"X-Trace-Id": "x" * 129}).status_code == 422


def test_ground_truth_log_is_jsonl(tmp_path):
    log = GroundTruthLog(tmp_path / "dir with space" / "mocks.jsonl")
    log.append("mail.delivered", "t", {"to": ["a@corp.local"]})
    log.append("admin.policy_change_attempted", None, {})
    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert log.read(kind="mail.delivered")[0]["details"] == {"to": ["a@corp.local"]}


# --- settings ----------------------------------------------------------------------

def test_settings_from_environment(tmp_path):
    s = load_mock_settings({"MOCKS_RUNTIME_DIR": str(tmp_path / "rt"), "LOG_DIR": str(tmp_path)})
    assert s.db_path == tmp_path / "rt" / "company.sqlite"
    assert s.ground_truth_path == tmp_path / "mocks.jsonl"
    assert load_mock_settings({}) == MockSettings()


def test_entry_point_starts(tmp_path):
    env = {**os.environ, "MOCKS_RUNTIME_DIR": str(tmp_path / "rt"), "LOG_DIR": str(tmp_path)}
    result = subprocess.run([sys.executable, "-c", "import mocks.main"],
                            cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "rt" / "company.sqlite").exists()


def test_default_paths_are_gitignored():
    assert DEFAULT_RUNTIME_DIR == REPO_ROOT / "runtime" / "mocks"
    assert DEFAULT_LOG_DIR == REPO_ROOT / "logs"
    ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "runtime/" in ignored and "logs/" in ignored
