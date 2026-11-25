"""Results files for one run (results/<run_id>/, gitignored; M7).

- run_meta.json      run settings, git commit, machine, scenario checksums
- results.csv        one row per (scenario, repetition, concurrency, slot)
- events.jsonl       one row per logged envelope (no payloads)
- ground_truth.jsonl the mock services' records for each trace
- criteria.jsonl     per outcome: the final answer and every criterion's result
- summary.csv        per scenario and concurrency: runs, completion, latency

Rows are appended as soon as a repetition ends, so an interrupted run keeps
what it finished. Scenarios marked not_applicable get one row with
status not_applicable and are left out of every rate; scenarios marked not_executed (defined,
but the testbed cannot run them yet) get one row with status not_executed, likewise left out.
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
    "research_llm_time_ms", "research_lookup_ms_max",
    "criteria_passed", "criteria_total", "criteria_failed", "expected_decision", "broker_decision", "detected",
    "not_applicable_reason", "error", "not_executed_reason",
]
SUMMARY_COLUMNS = ["scenario_id", "category", "concurrency", "runs", "completed", "task_completed",
                   "attack_succeeded", "median_latency_ms", "mean_latency_ms", "max_latency_ms",
                   "p95_latency_ms", "median_messages", "wall_time_s", "throughput_per_s"]


# Statuses of rows that never ran: no task, no latency, no rate.
NOT_RUN_STATUSES = ("not_applicable", "not_executed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True,
                             text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _prompt_fingerprint(version: str | None = None) -> str:
    from agents.planner import prompt_fingerprint   # imports LangGraph; only when a run starts
    return prompt_fingerprint(version)


def effective_planner_versions(scenarios: list[Scenario], override: str | None = None) -> dict[str, str]:
    """scenario id -> the planner prompt version it runs with (the override, else the
    scenario's own planner_prompt, else the planner's default), applicable scenarios only."""
    from agents.planner import prompt_spec          # imports LangGraph; only when a run starts
    return {s.id: prompt_spec(override or s.planner_prompt).version
            for s in scenarios if s.baseline == "applicable"}


def scenario_checksum(s: Scenario) -> str:
    # planner_prompt is left out while unset, so scenario files that do not use it
    # keep the checksum they had before the field existed (old runs stay resumable).
    exclude = {"planner_prompt"} if s.planner_prompt is None else None
    return hashlib.sha256(s.model_dump_json(exclude=exclude).encode("utf-8")).hexdigest()


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile (q in 0-100) of a non-empty list."""
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * q // 100))          # ceil(n * q / 100)
    return ordered[int(rank) - 1]


def level_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Numbers for the rows of one scenario at one concurrency level: tasks, completed, latency
    p50/p95/mean/max of completed tasks, messages per task, wall time (per repetition: first task
    start to last task end; summed over repetitions) and throughput (completed tasks per second
    of wall time)."""
    done = [r for r in rows if r["status"] == "completed"]
    lat = [r["e2e_latency_ms"] for r in done]
    walls = []
    for rep in sorted({r["rep"] for r in rows}):
        group = [r for r in rows if r["rep"] == rep and r.get("started_at") and r.get("ended_at")]
        if group:
            walls.append((max(_ts(r["ended_at"]) for r in group) - min(_ts(r["started_at"]) for r in group))
                         .total_seconds())
    wall = sum(walls)
    msgs = [r["messages"] for r in rows if r["messages"] is not None]
    return {
        "tasks": len(rows), "completed": len(done),
        "task_completed": sum(1 for r in rows if r["task_completed"]),
        "p50_ms": round(statistics.median(lat)) if lat else None,
        "p95_ms": round(percentile(lat, 95)) if lat else None,
        "mean_ms": round(statistics.fmean(lat)) if lat else None,
        "max_ms": max(lat) if lat else None,
        "median_messages": statistics.median(msgs) if msgs else None,
        "wall_s": round(wall, 1) if walls else None,
        "throughput_per_s": round(len(done) / wall, 3) if wall else None,
    }


def lookup_durations_ms(envelopes: list[dict]) -> list[int]:
    """How long each research.lookup took the research agent: from the request it
    logged ("in") to the response it logged ("out"). This is the time the planner
    waits for the reply, which send_message() limits to 60 s."""
    research = [e for e in envelopes if e.get("logged_by") == "research"]
    started = {e["envelope"]["msg_id"]: _ts(e["logged_at"]) for e in research
               if e["direction"] == "in" and e["envelope"].get("action") == "research.lookup"}
    return [round((_ts(e["logged_at"]) - started[e["envelope"]["parent_msg_id"]]).total_seconds() * 1000)
            for e in research
            if e["direction"] == "out" and e["envelope"].get("parent_msg_id") in started]


def broker_decision_cell(events: list[dict]) -> str:
    """results.csv broker_decision: each message's decision and reason code, in order."""
    return "; ".join(f"{e.get('decision')}:{e.get('reason_code')}" for e in events)


def _row_from_csv(row: dict[str, str]) -> dict[str, Any]:
    """A results.csv row back in the types the writer uses (for resume and summaries)."""
    def num(v):
        return int(v) if v not in ("", None) else None

    def flag(v):
        return {"true": True, "false": False}.get(v)
    out: dict[str, Any] = {k: (v if v != "" else None) for k, v in row.items()}
    for k in ("rep", "concurrency", "slot", "e2e_latency_ms", "sensitive_hits", "messages",
              "llm_calls", "llm_time_ms", "research_llm_time_ms", "research_lookup_ms_max",
              "criteria_passed", "criteria_total"):
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
              llm: LLMSettings, max_minutes: float | None,
              planner_versions: dict[str, str] | None = None, mode: str = "direct") -> None:
        """``planner_versions`` is scenario id -> prompt version (effective_planner_versions());
        left out, every scenario uses its own planner_prompt or the default."""
        versions = planner_versions if planner_versions is not None else effective_planner_versions(scenarios)
        used = sorted(set(versions.values())) or [None]
        prompts = {(v or "default"): _prompt_fingerprint(v) for v in used}
        single = len(used) == 1
        meta = {
            "run_id": self.run_id, "started_at": _now(), "ended_at": None,
            "git_commit": _git_commit(), "mode": mode,
            # One planner prompt version for every scenario is the rule for a final baseline run;
            # "mixed" (and a null planner_prompt_sha256) flags a run that is not one.
            "planner_prompt_version": (used[0] or "default") if single else "mixed",
            "planner_prompt_sha256": next(iter(prompts.values())) if single else None,
            "planner_prompts": prompts,
            "scenario_planner_prompt": versions,
            "mixed_planner_prompt_versions": not single,
            "llm": {"backend": llm_backend, "model": llm.model, "num_ctx": llm.num_ctx,
                    "num_predict": llm.num_predict, "temperature": 0.0,
                    "seed": "repetition number", "base_url": llm.base_url},
            "machine": {"platform": platform.platform(), "processor": platform.processor(),
                        "python": platform.python_version()},
            "reps": reps, "max_minutes": max_minutes,
            "scenarios": {s.id: scenario_checksum(s) for s in scenarios},
            "not_applicable": {s.id: s.not_applicable_reason for s in scenarios
                               if s.baseline == "not_applicable"},
            "not_executed": {s.id: s.not_executed_reason for s in scenarios
                             if s.baseline == "not_executed"},
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
                if r["status"] not in NOT_RUN_STATUSES}
        na = {r["scenario_id"] for r in self.rows if r["status"] in NOT_RUN_STATUSES}
        return runs, na

    def finish(self, stopped_early: bool = False, warmups: list[dict] | None = None,
               warmup_note: str | None = None) -> None:
        meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        meta.update(ended_at=_now(), stopped_early=stopped_early, rows=len(self.rows))
        # Warm-up calls are run metadata only, never part of any task's results.
        meta["warmups"] = meta.get("warmups", []) + list(warmups or [])
        if warmup_note:
            meta["warmup_note"] = warmup_note
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

    def note_broker(self, info: dict) -> None:
        """Record once, in run_meta.json, what the broker ran with (mode, BROKER_REAL, stubs)."""
        meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        if meta.get("broker") is None:
            meta["broker"] = info
            self.meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

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
            **self._research_times(o),
            "criteria_passed": ev.passed, "criteria_total": len(ev.criteria),
            "criteria_failed": "; ".join(f"{i}:{c['type']} ({c['detail']})"
                                         for i, c in enumerate(ev.criteria, 1) if not c["passed"]),
            "expected_decision": scenario.expected_decision, "error": o.error,
            # MODE=broker only (empty in direct mode, as before): every message's decision:reason.
            **({"broker_decision": broker_decision_cell(o.broker_events)} if o.broker_events else {}),
        })
        if o.broker_events:
            self._append_jsonl("broker_decisions.jsonl", [{**ids, "n": n, **e}
                                                          for n, e in enumerate(o.broker_events, 1)])
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

    @staticmethod
    def _research_times(o: TaskOutcome) -> dict[str, int | None]:
        """Research's own LLM time and its slowest lookup; empty when no lookup happened."""
        lookups = lookup_durations_ms(o.envelopes)
        if not lookups:
            return {"research_llm_time_ms": None, "research_lookup_ms_max": None}
        return {"research_llm_time_ms": sum(c.get("duration_ms", 0) for c in o.llm_calls
                                            if str(c.get("purpose", "")).startswith("research.")),
                "research_lookup_ms_max": max(lookups)}

    def add_not_applicable(self, scenario: Scenario) -> None:
        self._append_csv({"run_id": self.run_id, "scenario_id": scenario.id,
                          "category": scenario.category, "baseline": scenario.baseline,
                          "status": "not_applicable",
                          "not_applicable_reason": scenario.not_applicable_reason,
                          "expected_decision": scenario.expected_decision})

    def add_not_executed(self, scenario: Scenario) -> None:
        self._append_csv({"run_id": self.run_id, "scenario_id": scenario.id,
                          "category": scenario.category, "baseline": scenario.baseline,
                          "status": "not_executed",
                          "not_executed_reason": scenario.not_executed_reason,
                          "expected_decision": scenario.expected_decision})

    # --- summary -------------------------------------------------------------------

    def write_summary(self) -> None:
        groups: dict[tuple, list[dict]] = {}
        for r in self.rows:
            if r["status"] in NOT_RUN_STATUSES:
                continue
            groups.setdefault((r["scenario_id"], r["category"], r["concurrency"]), []).append(r)
        with open(self.dir / "summary.csv", "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=SUMMARY_COLUMNS)
            w.writeheader()
            for (sid, cat, conc), rows in sorted(groups.items()):
                lat = [r["e2e_latency_ms"] for r in rows if r["status"] == "completed"]
                stats = level_stats(rows)

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
                    "p95_latency_ms": stats["p95_ms"] if stats["p95_ms"] is not None else "",
                    "median_messages": stats["median_messages"] if stats["median_messages"] is not None else "",
                    "wall_time_s": stats["wall_s"] if stats["wall_s"] is not None else "",
                    "throughput_per_s": stats["throughput_per_s"] if stats["throughput_per_s"] is not None else "",
                })
