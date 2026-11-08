"""Command line: python -m runner [options]

  --scenario ID      run only this scenario (repeatable); default: all
  --reps N           repetitions per scenario (overrides the file)
  --llm fake|ollama  LLM backend for the agents (default: fake)
  --max-minutes M    stop starting new repetitions after M minutes
  --resume RUN_ID    carry on an interrupted run in its own folder: skip every
                     scenario/rep already in its results.csv (same scenarios,
                     reps and LLM backend as the original run)
  --dry-run          only load and check the scenario files
  --mode direct|broker  MODE for every agent process (default direct, the baseline). Recorded in
                     run_meta.json. broker is accepted but the broker is not built yet: the wrappers answer
                     HTTP 501 / send_message raises, so every task ends in error. A run's mode is fixed;
                     --resume continues with the mode it started with
  --debug-prompts    write each planner and research prompt to the run's logs (off by default)
  --planner-prompt V run every scenario with planner prompt version V (v1 = the
                     frozen baseline prompt, v2 = the candidate); default: each
                     scenario's own planner_prompt, else the planner default (v2). The versions and
                     fingerprints used are recorded in run_meta.json; a run that
                     mixes versions is flagged "mixed" (a final baseline run
                     uses one version for all scenarios)

With --llm ollama the runner first makes one small warm-up call to the model
(and again before a later repetition if more than 4 minutes passed since the
last LLM call), so no task includes model loading. Warm-ups are recorded in
run_meta.json ("warmups") and never counted in task results; fake runs skip
them.

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
from runner.results import ResultsWriter, effective_planner_versions, scenario_checksum
from runner.run import rep_dir_for, run_repetition, run_scripted_repetition
from runner.scenarios import DEFAULT_SCENARIOS_DIR, REPO_ROOT, ScenarioError, load_scenarios
from runner.warmup import Warmup, WarmupFailed, make_warmup_client, warm_up_call

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
                   help="write each planner and research prompt to <rep>/logs/prompts/ (off by default)")
    p.add_argument("--mode", choices=["direct", "broker"],
                   help="MODE for the agent processes (default direct; broker is not implemented yet)")
    p.add_argument("--planner-prompt", choices=["v1", "v2"],
                   help="planner prompt version for every scenario (default: the scenario's own, else the planner default, v2)")
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
        if args.scenario or args.reps or args.llm or args.dry_run or args.planner_prompt or args.mode:
            return _fail("--resume takes the run's own scenarios, reps, LLM, planner prompt and mode; "
                         "do not combine it with --scenario, --reps, --llm, --planner-prompt, --mode or --dry-run")
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
        mode = meta.get("mode") or "direct"
        versions = meta.get("scenario_planner_prompt")     # absent in runs made before versions existed
    else:
        if args.scenario:
            missing = sorted(set(args.scenario) - set(scenarios))
            if missing:
                return _fail(f"unknown scenario(s): {', '.join(missing)}")
            scenarios = {k: v for k, v in scenarios.items() if k in args.scenario}
        reps_override = args.reps
        llm_backend = args.llm or "fake"
        mode = args.mode or "direct"
        versions = None
    if mode == "broker":
        # Scenarios that drive a local attacker (the scripted sender, or a compromised responder
        # run under a victim's name) assume direct agent-to-agent calls; routing them through a
        # broker needs the broker's address, which is undecided.
        def _local_attacker(s):
            return s.scripted is not None or any(a.impl == "malicious" for a in s.agents)
        refused = sorted(i for i, s in scenarios.items() if _local_attacker(s))
        if refused and args.scenario:
            return _fail(f"scripted and compromised-responder scenarios are not supported in broker mode yet: "
                         f"the broker address is undecided (refused: {', '.join(refused)}); nothing was run or scored")
        if refused:
            print(f"note: scripted and compromised-responder scenarios are not supported in broker mode yet: "
                  f"the broker address is undecided; skipping {', '.join(refused)} (not run, not scored)",
                  file=sys.stderr)
            scenarios = {i: s for i, s in scenarios.items() if i not in refused}
    if not scenarios:
        return _fail(f"no scenario files in {args.scenarios_dir}")
    if args.dry_run:
        for s in scenarios.values():
            print(f"ok  {s.id}  {s.category:<11} {s.baseline:<15} {s.title}")
        return 0

    # A live-model scenario is an applicable LLM entry task with no recorded fake replies (A3): the
    # fake backend has no script to drive the planner, so the run would only error on the first
    # decide and prove nothing. Refuse it clearly instead.
    if llm_backend == "fake":
        live_only = sorted(i for i, s in scenarios.items()
                           if s.baseline == "applicable" and s.entry is not None and not s.fake_llm)
        if live_only and args.scenario:
            return _fail(f"these scenarios need the live model (no fake_llm script): {', '.join(live_only)}; "
                         f"run them with --llm ollama. Nothing was run.")
        if live_only:
            print(f"note: {', '.join(live_only)} need the live model (no fake_llm script); "
                  f"skipping under --llm fake (run with --llm ollama)", file=sys.stderr)
            scenarios = {i: s for i, s in scenarios.items() if i not in live_only}
            if not scenarios:
                return _fail("nothing to run: every selected scenario needs the live model (--llm ollama)")

    llm = LLMSettings(base_url=os.environ.get("LLM_BASE_URL", "http://localhost:11434"))
    if versions is None:
        versions = effective_planner_versions(list(scenarios.values()), args.planner_prompt)
    if args.resume:
        writer = ResultsWriter(args.results_dir, args.resume)
        writer.resume()
        print(f"resume {args.resume} -> {writer.dir}")
    else:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        writer = ResultsWriter(args.results_dir, run_id)
        writer.start(list(scenarios.values()), reps=reps_override or 0, llm_backend=llm_backend, llm=llm,
                     max_minutes=args.max_minutes, planner_versions=versions, mode=mode)
        print(f"run {run_id} -> {writer.dir}")
        if mode != "direct":
            print(f"note: MODE={mode}; the broker is not implemented yet, so tasks that send a message will fail")
        if len(set(versions.values())) > 1:
            print(f"note: this run mixes planner prompt versions {dict(sorted(versions.items()))}; "
                  f"it is not a valid final baseline (use --planner-prompt)")
    done_runs, done_na = writer.done_keys()

    warmup = Warmup(llm_backend, lambda: warm_up_call(make_warmup_client(llm, writer.dir / "warmup_llm")))
    warmup_note = None if warmup.enabled else f"skipped: LLM backend is {llm_backend}"
    deadline = time.monotonic() + args.max_minutes * 60 if args.max_minutes else None
    stopped = False
    try:
        for s in scenarios.values():
            if s.baseline == "not_applicable":
                if s.id not in done_na:
                    writer.add_not_applicable(s)
                    print(f"{s.id}: not applicable ({s.not_applicable_reason})")
                continue
            if s.baseline == "not_executed":
                if s.id not in done_na:
                    writer.add_not_executed(s)
                    print(f"{s.id}: defined, not executed ({s.not_executed_reason})")
                continue
            for rep in range(1, (reps_override or s.reps) + 1):
                conc_levels = [1] if s.scripted is not None else s.concurrency
                for conc in conc_levels:
                    if (s.id, rep, conc) in done_runs:
                        continue
                    if deadline and time.monotonic() > deadline:
                        stopped = True
                        raise StopIteration
                    partial = rep_dir_for(writer.dir, s.id, conc, rep)
                    if partial.exists():      # left by an interrupted repetition
                        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        partial.rename(partial.with_name(f"{partial.name}.partial-{stamp}"))
                    if (done := warmup.before_scenario(s.id)):
                        print(f"warm-up before {s.id}: {done['duration_s']} s ({done['reason']}); "
                              f"not counted in any task")
                    if s.scripted is not None:
                        outcomes = run_scripted_repetition(
                            s, rep, writer.dir, llm_backend=llm_backend,
                            llm_base_url=llm.base_url, debug_prompts=args.debug_prompts,
                            mode=mode)
                    else:
                        outcomes = run_repetition(s, rep, writer.dir, concurrency=conc,
                                                  llm_backend=llm_backend, llm_base_url=llm.base_url,
                                                  debug_prompts=args.debug_prompts,
                                                  planner_prompt=versions.get(s.id), mode=mode)
                    warmup.note_repetition(outcomes)
                    for o in outcomes:
                        ev = evaluate(s, o)
                        writer.add(s, o, ev)
                        label = (f"attack_succeeded={ev.attack_succeeded}"
                                 if s.category == "attack"
                                 else f"completed={ev.task_completed}")
                        print(f"{s.id} rep {rep} c{conc} slot {o.slot}: {o.status} "
                              f"{label} {o.latency_ms} ms")
    except StopIteration:
        print("time budget reached; stopping")
    except WarmupFailed as exc:
        stopped = True
        print(f"warm-up failed ({exc}); stopping before any task is affected "
              f"(carry on later with: python -m runner --resume {writer.run_id})", file=sys.stderr)
    except KeyboardInterrupt:
        stopped = True
        print(f"interrupted; processes stopped, finished rows kept "
              f"(carry on with: python -m runner --resume {writer.run_id})")
    finally:
        writer.finish(stopped_early=stopped, warmups=warmup.records, warmup_note=warmup_note)
    print(f"results: {writer.dir}")
    return 130 if stopped and deadline is None else 0


if __name__ == "__main__":
    sys.exit(main())
