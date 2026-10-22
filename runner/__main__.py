"""Command line: python -m runner [options]

  --scenario ID      run only this scenario (repeatable); default: all
  --reps N           repetitions per scenario (overrides the file)
  --llm fake|ollama  LLM backend for the agents (default: fake)
  --max-minutes M    stop starting new repetitions after M minutes
  --resume RUN_ID    carry on an interrupted run in its own folder: skip every
                     scenario/rep already in its results.csv (same scenarios,
                     reps and LLM backend as the original run)
  --dry-run          only load and check the scenario files
  --debug-prompts    write each planner prompt to the run's logs (off by default)

Results go to results/<run_id>/ (gitignored). Ctrl+C stops after cleaning
up the current repetition's processes and keeps the finished rows.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from agents.llm import LLMSettings
from runner.evaluate import evaluate
from runner.results import ResultsWriter, scenario_checksum
from runner.run import rep_dir_for, run_repetition
from runner.scenarios import DEFAULT_SCENARIOS_DIR, REPO_ROOT, ScenarioError, load_scenarios

DEFAULT_RESULTS_DIR = REPO_ROOT / "results"


def parse(argv):
    p = argparse.ArgumentParser(prog="python -m runner", description="Run testbed scenarios (MODE=direct).")
    p.add_argument("--scenarios-dir", type=Path, default=DEFAULT_SCENARIOS_DIR)
    p.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    p.add_argument("--scenario", action="append", default=[])
    p.add_argument("--reps", type=int)
    p.add_argument("--llm", choices=["fake", "ollama"])
    p.add_argument("--max-minutes", type=float)
    p.add_argument("--resume", metavar="RUN_ID")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--debug-prompts", action="store_true",
                   help="write each planner prompt to <rep>/logs/prompts/ (off by default)")
    return p.parse_args(argv)


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def main(argv=None) -> int:
    args = parse(argv)
    try:
        scenarios = load_scenarios(args.scenarios_dir)
    except ScenarioError as exc:
        return _fail(f"scenario error: {exc}")

    if args.resume:
        if args.scenario or args.reps or args.llm or args.dry_run:
            return _fail("--resume takes the run's own scenarios, reps and LLM; "
                         "do not combine it with --scenario, --reps, --llm or --dry-run")
        meta_path = args.results_dir / args.resume / "run_meta.json"
        if not meta_path.exists():
            return _fail(f"no run {args.resume!r} in {args.results_dir}")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        ids = list(meta["scenarios"])
        missing = [i for i in ids if i not in scenarios]
        changed = [i for i in ids if i in scenarios and scenario_checksum(scenarios[i]) != meta["scenarios"][i]]
        if missing or changed:
            return _fail(f"cannot resume {args.resume}: scenario files missing {missing} or changed "
                         f"{changed} since the run started")
        scenarios = {i: scenarios[i] for i in ids}
        reps_override = meta.get("reps") or None
        llm_backend = meta["llm"]["backend"]
    else:
        if args.scenario:
            missing = sorted(set(args.scenario) - set(scenarios))
            if missing:
                return _fail(f"unknown scenario(s): {', '.join(missing)}")
            scenarios = {k: v for k, v in scenarios.items() if k in args.scenario}
        reps_override = args.reps
        llm_backend = args.llm or "fake"
    if not scenarios:
        return _fail(f"no scenario files in {args.scenarios_dir}")
    if args.dry_run:
        for s in scenarios.values():
            print(f"ok  {s.id}  {s.category:<11} {s.baseline:<15} {s.title}")
        return 0

    llm = LLMSettings(base_url=os.environ.get("LLM_BASE_URL", "http://localhost:11434"))
    if args.resume:
        writer = ResultsWriter(args.results_dir, args.resume)
        writer.resume()
        print(f"resume {args.resume} -> {writer.dir}")
    else:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        writer = ResultsWriter(args.results_dir, run_id)
        writer.start(list(scenarios.values()), reps=reps_override or 0, llm_backend=llm_backend, llm=llm,
                     max_minutes=args.max_minutes)
        print(f"run {run_id} -> {writer.dir}")
    done_runs, done_na = writer.done_keys()

    deadline = time.monotonic() + args.max_minutes * 60 if args.max_minutes else None
    stopped = False
    try:
        for s in scenarios.values():
            if s.baseline == "not_applicable":
                if s.id not in done_na:
                    writer.add_not_applicable(s)
                    print(f"{s.id}: not applicable ({s.not_applicable_reason})")
                continue
            for rep in range(1, (reps_override or s.reps) + 1):
                for conc in s.concurrency:
                    if (s.id, rep, conc) in done_runs:
                        continue
                    if deadline and time.monotonic() > deadline:
                        stopped = True
                        raise StopIteration
                    partial = rep_dir_for(writer.dir, s.id, conc, rep)
                    if partial.exists():      # left by an interrupted repetition
                        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        partial.rename(partial.with_name(f"{partial.name}.partial-{stamp}"))
                    outcomes = run_repetition(s, rep, writer.dir, concurrency=conc,
                                              llm_backend=llm_backend, llm_base_url=llm.base_url,
                                              debug_prompts=args.debug_prompts)
                    for o in outcomes:
                        ev = evaluate(s, o)
                        writer.add(s, o, ev)
                        print(f"{s.id} rep {rep} c{conc} slot {o.slot}: {o.status} "
                              f"completed={ev.task_completed} {o.latency_ms} ms")
    except StopIteration:
        print("time budget reached; stopping")
    except KeyboardInterrupt:
        stopped = True
        print(f"interrupted; processes stopped, finished rows kept "
              f"(carry on with: python -m runner --resume {writer.run_id})")
    finally:
        writer.finish(stopped_early=stopped)
    print(f"results: {writer.dir}")
    return 130 if stopped and deadline is None else 0


if __name__ == "__main__":
    sys.exit(main())
