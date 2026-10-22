"""Baseline report: python -m runner.report RUN_ID [RUN_ID ...]

For each run, writes report.md and report.csv into results/<run_id>/: per
scenario the runs, task-completed rate, median/mean/max latency (completed
runs), median LLM calls and messages; the not_applicable scenarios with
their reasons; and the run's metadata (LLM, temperature, seeds, git commit,
planner prompt fingerprint). With several run ids it also writes a combined
report (runs pooled per scenario) to results/report-<time>/.

Runs made before run_meta.json stored the prompt fingerprint get it derived
only when agents/planner.py and contracts/ are unchanged between the run's
commit and the working tree; otherwise it is reported as not recorded.
"""

import argparse
import csv
import json
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runner.results import _row_from_csv
from runner.scenarios import REPO_ROOT

DEFAULT_RESULTS_DIR = REPO_ROOT / "results"
REPORT_COLUMNS = [
    "scenario_id", "category", "baseline", "runs", "task_completed", "task_completed_rate",
    "attack_succeeded", "median_latency_ms", "mean_latency_ms", "max_latency_ms",
    "median_llm_calls", "median_messages", "not_applicable_reason",
]


def load_run(run_dir: Path) -> tuple[dict, list[dict[str, Any]]]:
    meta = json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))
    with open(run_dir / "results.csv", encoding="utf-8", newline="") as f:
        rows = [_row_from_csv(r) for r in csv.DictReader(f)]
    return meta, rows


def prompt_fingerprint_for(meta: dict) -> tuple[str, str]:
    """(fingerprint or "", how it was obtained)."""
    if meta.get("planner_prompt_sha256"):
        return meta["planner_prompt_sha256"], "recorded in run_meta.json"
    commit = meta.get("git_commit") or ""
    if commit and commit != "unknown":
        same = subprocess.run(["git", "diff", "--quiet", commit, "--", "agents/planner.py", "contracts/"],
                              cwd=REPO_ROOT, capture_output=True)
        if same.returncode == 0:
            from agents.planner import prompt_fingerprint
            return prompt_fingerprint(), (f"derived: agents/planner.py and contracts/ unchanged "
                                          f"since commit {commit[:7]}")
    return "", "not recorded (run predates fingerprint recording; prompt code changed since)"


def _median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def _rate(rows, key):
    vals = [r[key] for r in rows if r[key] is not None]
    return (sum(vals), len(vals)) if vals else (None, 0)


def scenario_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    by_id: dict[str, list[dict]] = {}
    for r in rows:
        by_id.setdefault(r["scenario_id"], []).append(r)
    for sid in sorted(by_id):
        rs = by_id[sid]
        na = [r for r in rs if r["status"] == "not_applicable"]
        if na:
            out.append({"scenario_id": sid, "category": na[0]["category"], "baseline": "not_applicable",
                        "runs": 0, "not_applicable_reason": na[0]["not_applicable_reason"]})
            continue
        lat = [r["e2e_latency_ms"] for r in rs if r["status"] == "completed"]
        done, n = _rate(rs, "task_completed")
        attack, n_attack = _rate(rs, "attack_succeeded")
        out.append({
            "scenario_id": sid, "category": rs[0]["category"], "baseline": rs[0]["baseline"],
            "runs": len(rs),
            "task_completed": f"{done}/{n}" if n else "",
            "task_completed_rate": round(done / n, 3) if n else "",
            "attack_succeeded": f"{attack}/{n_attack}" if n_attack else "",
            "median_latency_ms": round(statistics.median(lat)) if lat else "",
            "mean_latency_ms": round(statistics.fmean(lat)) if lat else "",
            "max_latency_ms": max(lat) if lat else "",
            "median_llm_calls": _median([r["llm_calls"] for r in rs]),
            "median_messages": _median([r["messages"] for r in rs]),
            "not_applicable_reason": "",
        })
    return out


def _seeds(rows) -> str:
    reps = sorted({r["rep"] for r in rows if r["rep"] is not None})
    if not reps:
        return "none"
    return f"{reps[0]}-{reps[-1]}" if reps == list(range(reps[0], reps[-1] + 1)) and len(reps) > 1 \
        else ", ".join(map(str, reps))


def _fmt(v) -> str:
    if v is None or v == "":
        return "-"
    if isinstance(v, float):
        return f"{v:g}"
    return str(v)


def _ms(v) -> str:
    return "-" if v in (None, "") else f"{v / 1000:.1f} s"


def render_md(title: str, runs: list[tuple[str, dict, list]], table: list[dict]) -> str:
    lines = [f"# {title}", "", f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
             "by `python -m runner.report`.", "", "## Runs", ""]
    lines += ["| Run | Mode | LLM | Temperature | num_ctx / num_predict | Seeds | Git commit | "
              "Planner prompt SHA-256 |", "|---|---|---|---|---|---|---|---|"]
    notes = []
    for run_id, meta, rows in runs:
        llm = meta.get("llm", {})
        fp, how = prompt_fingerprint_for(meta)
        lines.append(f"| {run_id} | {meta.get('mode', '-')} | {llm.get('backend', '-')} {llm.get('model', '')} | "
                     f"{llm.get('temperature', '-')} | {llm.get('num_ctx', '-')} / {llm.get('num_predict', '-')} | "
                     f"{_seeds(rows)} (seed = repetition) | `{(meta.get('git_commit') or '-')[:7]}` | "
                     f"{('`' + fp + '`') if fp else 'not recorded'} |")
        notes.append(f"- {run_id}: prompt fingerprint {how}."
                     + (" Stopped early." if meta.get("stopped_early") else "")
                     + (f" Resumed {len(meta['resumes'])} time(s)." if meta.get("resumes") else ""))
    lines += ["", *notes, "", "## Results per scenario", "",
              "| Scenario | Category | Runs | Task completed | Median / mean / max latency | "
              "Median LLM calls | Median messages |", "|---|---|---|---|---|---|---|"]
    for t in table:
        if t["baseline"] == "not_applicable":
            continue
        rate = f"{t['task_completed']} ({t['task_completed_rate']:.0%})" if t["task_completed"] else "-"
        lines.append(f"| {t['scenario_id']} | {t['category']} | {t['runs']} | {rate} | "
                     f"{_ms(t['median_latency_ms'])} / {_ms(t['mean_latency_ms'])} / {_ms(t['max_latency_ms'])} | "
                     f"{_fmt(t['median_llm_calls'])} | {_fmt(t['median_messages'])} |")
    na = [t for t in table if t["baseline"] == "not_applicable"]
    lines += ["", "## Not applicable in direct mode", ""]
    lines += [f"- **{t['scenario_id']}**: {t['not_applicable_reason']}" for t in na] or ["- none"]
    lines += ["", "Not-applicable scenarios are excluded from every rate. Latency counts completed runs only.", ""]
    return "\n".join(lines)


def write_report(out_dir: Path, title: str, runs: list[tuple[str, dict, list]]) -> list[dict]:
    all_rows = [r for _, _, rows in runs for r in rows]
    table = scenario_rows(all_rows)
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "report.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=REPORT_COLUMNS)
        w.writeheader()
        for t in table:
            w.writerow({k: ("" if t.get(k) is None else t.get(k, "")) for k in REPORT_COLUMNS})
    (out_dir / "report.md").write_text(render_md(title, runs, table), encoding="utf-8")
    return table


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m runner.report", description="Write a baseline report.")
    p.add_argument("run_ids", nargs="+")
    p.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    args = p.parse_args(argv)
    runs = []
    for run_id in args.run_ids:
        run_dir = args.results_dir / run_id
        if not (run_dir / "run_meta.json").exists() or not (run_dir / "results.csv").exists():
            print(f"no complete run {run_id!r} in {args.results_dir}", file=sys.stderr)
            return 2
        meta, rows = load_run(run_dir)
        runs.append((run_id, meta, rows))
        write_report(run_dir, f"Baseline report: run {run_id}", [(run_id, meta, rows)])
        print(f"wrote {run_dir / 'report.md'} and report.csv")
    if len(runs) > 1:
        out = args.results_dir / f"report-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        write_report(out, f"Baseline report: runs {', '.join(args.run_ids)}", runs)
        print(f"wrote combined report to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
