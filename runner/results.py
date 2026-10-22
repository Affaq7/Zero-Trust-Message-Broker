"""Results files for one run (results/<run_id>/, gitignored; M7).

- run_meta.json      run settings, git commit, machine, scenario checksums
- results.csv        one row per (scenario, repetition, concurrency, slot)
- events.jsonl       one row per logged envelope (no payloads)
- ground_truth.jsonl the mock services' records for each trace
- criteria.jsonl     per outcome: the final answer and every criterion's result
- summary.csv        per scenario and concurrency: runs, completion, latency

Rows are appended as soon as a repetition ends, so an interrupted run keeps
what it finished. Scenarios marked not_applicable get one row with
status not_applicable and are left out of every rate.
"""

import csv
import hashlib
import json
import platform
import statistics
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.llm import LLMSettings
from runner.evaluate import Evaluation
from runner.run import TaskOutcome
from runner.scenarios import REPO_ROOT, Scenario

COLUMNS = [
    "run_id", "scenario_id", "category", "baseline", "rep", "concurrency", "slot", "trace_id",
    "started_at", "ended_at", "e2e_latency_ms", "status", "task_status", "task_completed",
    "attack_succeeded", "over_exposure", "sensitive_hits", "messages", "llm_calls", "llm_time_ms",
    "criteria_passed", "criteria_total", "criteria_failed", "expected_decision", "broker_decision", "detected",
    "not_applicable_reason", "error",
]
SUMMARY_COLUMNS = ["scenario_id", "category", "concurrency", "runs", "completed", "task_completed",
                   "attack_succeeded", "median_latency_ms", "mean_latency_ms", "max_latency_ms"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True,
                             text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def scenario_checksum(s: Scenario) -> str:
    return hashlib.sha256(s.model_dump_json().encode("utf-8")).hexdigest()


def _row_from_csv(row: dict[str, str]) -> dict[str, Any]:
    """A results.csv row back in the types the writer uses (for resume and summaries)."""
    def num(v):
        return int(v) if v not in ("", None) else None

    def flag(v):
        return {"true": True, "false": False}.get(v)
    out: dict[str, Any] = {k: (v if v != "" else None) for k, v in row.items()}
    for k in ("rep", "concurrency", "slot", "e2e_latency_ms", "sensitive_hits", "messages",
              "llm_calls", "llm_time_ms", "criteria_passed", "criteria_total"):
        out[k] = num(row.get(k, ""))
    for k in ("task_completed", "attack_succeeded", "over_exposure"):
        out[k] = flag(row.get(k, ""))
    return out


def _cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


class ResultsWriter:
    def __init__(self, results_dir: Path, run_id: str):
        self.run_id = run_id
        self.dir = Path(results_dir) / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.dir / "run_meta.json"
        self.csv_path = self.dir / "results.csv"
        self.rows: list[dict[str, Any]] = []

    # --- metadata ------------------------------------------------------------------

    def start(self, scenarios: list[Scenario], *, reps: int, llm_backend: str,
              llm: LLMSettings, max_minutes: float | None) -> None:
        meta = {
            "run_id": self.run_id, "started_at": _now(), "ended_at": None,
            "git_commit": _git_commit(), "mode": "direct",
            "llm": {"backend": llm_backend, "model": llm.model, "num_ctx": llm.num_ctx,
                    "num_predict": llm.num_predict, "temperature": 0.0,
                    "seed": "repetition number", "base_url": llm.base_url},
            "machine": {"platform": platform.platform(), "processor": platform.processor(),
                        "python": platform.python_version()},
            "reps": reps, "max_minutes": max_minutes,
            "scenarios": {s.id: scenario_checksum(s) for s in scenarios},
            "not_applicable": {s.id: s.not_applicable_reason for s in scenarios
                               if s.baseline == "not_applicable"},
            "stopped_early": False,
        }
        self.meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def resume(self) -> dict:
        """Reopen an existing run: load its rows and record this resume in run_meta.json."""
        meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        if self.csv_path.exists():
            with open(self.csv_path, encoding="utf-8", newline="") as f:
                self.rows = [_row_from_csv(r) for r in csv.DictReader(f)]
        commit = _git_commit()
        meta.setdefault("resumes", []).append({"at": _now(), "git_commit": commit})
        if commit != meta.get("git_commit"):
            meta["resumed_on_other_commit"] = True
        self.meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return meta

    def done_keys(self) -> tuple[set[tuple[str, int, int]], set[str]]:
        """(scenario_id, rep, concurrency) already recorded, and not_applicable ids recorded."""
        runs = {(r["scenario_id"], r["rep"], r["concurrency"]) for r in self.rows
                if r["status"] != "not_applicable"}
        na = {r["scenario_id"] for r in self.rows if r["status"] == "not_applicable"}
        return runs, na

    def finish(self, stopped_early: bool = False) -> None:
        meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        meta.update(ended_at=_now(), stopped_early=stopped_early, rows=len(self.rows))
        self.meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self.write_summary()

    # --- rows ----------------------------------------------------------------------

    def _append_csv(self, row: dict[str, Any]) -> None:
        new = not self.csv_path.exists()
        with open(self.csv_path, "a", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLUMNS)
            if new:
                w.writeheader()
            w.writerow({k: _cell(row.get(k)) for k in COLUMNS})
        self.rows.append(row)

    def _append_jsonl(self, name: str, records: list[dict]) -> None:
        with open(self.dir / name, "a", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def add(self, scenario: Scenario, o: TaskOutcome, ev: Evaluation) -> None:
        ids = {"run_id": self.run_id, "scenario_id": scenario.id, "rep": o.rep,
               "concurrency": o.concurrency, "slot": o.slot, "trace_id": o.trace_id}
        self._append_csv({
            **ids, "category": scenario.category, "baseline": scenario.baseline,
            "started_at": o.started_at, "ended_at": o.ended_at, "e2e_latency_ms": o.latency_ms,
            "status": o.status, "task_status": o.task_status, "task_completed": ev.task_completed,
            "attack_succeeded": ev.attack_succeeded, "over_exposure": ev.over_exposure,
            "sensitive_hits": ev.sensitive_hits,
            "messages": sum(1 for e in o.envelopes if e["direction"] == "in"),
            "llm_calls": len(o.llm_calls),
            "llm_time_ms": sum(c.get("duration_ms", 0) for c in o.llm_calls),
            "criteria_passed": ev.passed, "criteria_total": len(ev.criteria),
            "criteria_failed": "; ".join(f"{i}:{c['type']} ({c['detail']})"
                                         for i, c in enumerate(ev.criteria, 1) if not c["passed"]),
            "expected_decision": scenario.expected_decision, "error": o.error,
        })
        self._append_jsonl("criteria.jsonl", [{
            **ids, "status": o.status, "task_status": o.task_status, "answer": o.answer,
            "criteria": [{"n": i, **crit.model_dump(exclude_none=True), "passed": c["passed"],
                          "detail": c["detail"]}
                         for i, (crit, c) in enumerate(zip(scenario.success_criteria, ev.criteria), 1)],
        }])
        self._append_jsonl("events.jsonl", [{
            **ids, "logged_at": e["logged_at"], "logged_by": e["logged_by"], "direction": e["direction"],
            **{k: e["envelope"].get(k) for k in ("msg_id", "parent_msg_id", "msg_type", "sender",
                                                 "receiver", "action", "resource", "decision")},
        } for e in o.envelopes])
        self._append_jsonl("ground_truth.jsonl", [{**ids, **g} for g in o.ground_truth])

    def add_not_applicable(self, scenario: Scenario) -> None:
        self._append_csv({"run_id": self.run_id, "scenario_id": scenario.id,
                          "category": scenario.category, "baseline": scenario.baseline,
                          "status": "not_applicable",
                          "not_applicable_reason": scenario.not_applicable_reason,
                          "expected_decision": scenario.expected_decision})

    # --- summary -------------------------------------------------------------------

    def write_summary(self) -> None:
        groups: dict[tuple, list[dict]] = {}
        for r in self.rows:
            if r["status"] == "not_applicable":
                continue
            groups.setdefault((r["scenario_id"], r["category"], r["concurrency"]), []).append(r)
        with open(self.dir / "summary.csv", "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=SUMMARY_COLUMNS)
            w.writeheader()
            for (sid, cat, conc), rows in sorted(groups.items()):
                lat = [r["e2e_latency_ms"] for r in rows if r["status"] == "completed"]

                def rate(key):
                    vals = [r[key] for r in rows if r[key] is not None]
                    return f"{sum(vals)}/{len(vals)}" if vals else ""
                w.writerow({
                    "scenario_id": sid, "category": cat, "concurrency": conc, "runs": len(rows),
                    "completed": sum(1 for r in rows if r["status"] == "completed"),
                    "task_completed": rate("task_completed"),
                    "attack_succeeded": rate("attack_succeeded"),
                    "median_latency_ms": round(statistics.median(lat)) if lat else "",
                    "mean_latency_ms": round(statistics.fmean(lat)) if lat else "",
                    "max_latency_ms": max(lat) if lat else "",
                })
