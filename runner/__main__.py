"""Command line: python -m runner [options]

  --scenario ID      run only this scenario (repeatable); default: all
  --reps N           repetitions per scenario (overrides the file)
  --llm fake|ollama  LLM backend for the agents (default: fake)
  --max-minutes M    stop starting new repetitions after M minutes
  --dry-run          only load and check the scenario files

Results go to results/<run_id>/ (gitignored). Ctrl+C stops after cleaning
up the current repetition's processes and keeps the finished rows.
"""

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from agents.llm import LLMSettings
from runner.evaluate import evaluate
from runner.results import ResultsWriter
from runner.run import run_repetition
from runner.scenarios import DEFAULT_SCENARIOS_DIR, REPO_ROOT, ScenarioError, load_scenarios

DEFAULT_RESULTS_DIR = REPO_ROOT / "results"


def parse(argv):
    p = argparse.ArgumentParser(prog="python -m runner", description="Run testbed scenarios (MODE=direct).")
    p.add_argument("--scenarios-dir", type=Path, default=DEFAULT_SCENARIOS_DIR)
    p.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    p.add_argument("--scenario", action="append", default=[])
    p.add_argument("--reps", type=int)
    p.add_argument("--llm", choices=["fake", "ollama"], default="fake")
    p.add_argument("--max-minutes", type=float)
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse(argv)
    try:
        scenarios = load_scenarios(args.scenarios_dir)
    except ScenarioError as exc:
        print(f"scenario error: {exc}", file=sys.stderr)
        return 2
    if args.scenario:
        missing = sorted(set(args.scenario) - set(scenarios))
        if missing:
            print(f"unknown scenario(s): {', '.join(missing)}", file=sys.stderr)
            return 2
        scenarios = {k: v for k, v in scenarios.items() if k in args.scenario}
    if not scenarios:
        print(f"no scenario files in {args.scenarios_dir}", file=sys.stderr)
        return 2
    if args.dry_run:
        for s in scenarios.values():
            print(f"ok  {s.id}  {s.category:<11} {s.baseline:<15} {s.title}")
        return 0

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    writer = ResultsWriter(args.results_dir, run_id)
    llm = LLMSettings(base_url=os.environ.get("LLM_BASE_URL", "http://localhost:11434"))
    writer.start(list(scenarios.values()), reps=args.reps or 0, llm_backend=args.llm, llm=llm,
                 max_minutes=args.max_minutes)
    deadline = time.monotonic() + args.max_minutes * 60 if args.max_minutes else None
    stopped = False
    print(f"run {run_id} -> {writer.dir}")
    try:
        for s in scenarios.values():
            if s.baseline == "not_applicable":
                writer.add_not_applicable(s)
                print(f"{s.id}: not applicable ({s.not_applicable_reason})")
                continue
            for rep in range(1, (args.reps or s.reps) + 1):
                for conc in s.concurrency:
                    if deadline and time.monotonic() > deadline:
                        stopped = True
                        raise StopIteration
                    outcomes = run_repetition(s, rep, writer.dir, concurrency=conc,
                                              llm_backend=args.llm, llm_base_url=llm.base_url)
                    for o in outcomes:
                        ev = evaluate(s, o)
                        writer.add(s, o, ev)
                        print(f"{s.id} rep {rep} c{conc} slot {o.slot}: {o.status} "
                              f"completed={ev.task_completed} {o.latency_ms} ms")
    except StopIteration:
        print("time budget reached; stopping")
    except KeyboardInterrupt:
        stopped = True
        print("interrupted; processes stopped, finished rows kept")
    finally:
        writer.finish(stopped_early=stopped)
    print(f"results: {writer.dir}")
    return 130 if stopped and deadline is None else 0


if __name__ == "__main__":
    sys.exit(main())
