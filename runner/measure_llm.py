"""Warm planner-call measurement: python -m runner.measure_llm --calls 10

Makes one warm-up call, then N planner-sized calls on the live LLM (Ollama,
settings from the environment as for the agents: LLM_BASE_URL, LLM_MODEL,
LLM_NUM_CTX, ...). Each call sends the real (frozen) planner system prompt
and a first-step user prompt and asks for a planner decision; the task text
carries the call number, so the user part is new each time while the shared
system part can stay cached, as in a real run. Wall-clock time per call is
measured; median, min, max, spread (max - min) and mean are printed and
appended as one row to the "Warm planner call measurements" table in
docs/measurements.md (unless --no-write). Nothing is written if the LLM is
unreachable or every call fails.
"""

import argparse
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from agents.llm import LLMClient, LLMError, LLMSettings, OllamaLLM, load_llm_settings
from agents.planner import PlannerAgent, PlannerDecision, prompt_fingerprint
from runner.scenarios import REPO_ROOT

DEFAULT_DOC = REPO_ROOT / "docs" / "measurements.md"
DEFAULT_LOG_DIR = REPO_ROOT / "logs"
HEADING = "## Warm planner call measurements"
TABLE_HEADER = ("| Date (UTC) | Calls | Median | Min | Max | Spread (max-min) | Mean | Failed | "
                "Warm-up call | Model | num_ctx | Prompt SHA-256 |\n"
                "|---|---|---|---|---|---|---|---|---|---|---|---|")
TASK = "What is the total cost of Project X so far?"


def planner_prompts():
    """(system prompt, function call_number -> first-step user prompt) of the frozen planner."""
    planner = PlannerAgent(llm=None, sender=lambda **k: None)

    def user(i: int) -> str:
        state = {"task": f"{TASK} (measurement call {i})", "trace_id": "measure", "chain": ["user"],
                 "history": [], "steps": 0, "decision": None, "answer": None, "error": None}
        return planner._prompt(state)
    return planner.system, user


def measure(llm: LLMClient, calls: int) -> dict:
    system, user = planner_prompts()

    def one(i: int) -> float:
        started = time.perf_counter()
        llm.decide(purpose="measure.planner", system=system, prompt=user(i), schema=PlannerDecision)
        return time.perf_counter() - started

    warmup = one(0)          # raises if the LLM is unreachable: nothing gets recorded
    durations, failed = [], 0
    for i in range(1, calls + 1):
        try:
            durations.append(one(i))
        except LLMError:
            failed += 1
    return {"warmup_s": warmup, "durations_s": durations, "failed": failed, "calls": calls}


def stats(result: dict) -> dict:
    d = result["durations_s"]
    return {"median": statistics.median(d), "min": min(d), "max": max(d),
            "spread": max(d) - min(d), "mean": statistics.fmean(d)}


def record(doc: Path, result: dict, s: dict, settings: LLMSettings, fingerprint: str) -> str:
    row = (f"| {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} | {result['calls']} | "
           f"{s['median']:.1f} s | {s['min']:.1f} s | {s['max']:.1f} s | {s['spread']:.1f} s | "
           f"{s['mean']:.1f} s | {result['failed']} | {result['warmup_s']:.1f} s | {settings.model} | "
           f"{settings.num_ctx} | `{fingerprint[:12]}` |")
    text = doc.read_text(encoding="utf-8")
    if HEADING not in text:
        text = text.rstrip("\n") + (
            f"\n\n{HEADING}\n\nWritten by `python -m runner.measure_llm`: one warm-up call (not counted), "
            "then N planner-sized calls (frozen planner system prompt + a first-step user prompt, "
            "temperature 0). Wall-clock seconds per call.\n\n" + TABLE_HEADER + "\n")
    text = text.rstrip("\n") + "\n" + row + "\n"
    doc.write_text(text, encoding="utf-8")
    return row


def make_client(settings: LLMSettings, log_dir: Path) -> LLMClient:
    return OllamaLLM(settings, "measure", log_dir)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m runner.measure_llm",
                                description="Measure warm planner-sized LLM calls on the live LLM.")
    p.add_argument("--calls", type=int, default=10)
    p.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    p.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    p.add_argument("--no-write", action="store_true", help="print only; do not change the doc")
    args = p.parse_args(argv)
    if args.calls < 1:
        print("--calls must be at least 1", file=sys.stderr)
        return 2
    # Always the live LLM: an LLM_BACKEND=fake left in the shell is ignored.
    settings = load_llm_settings({k: v for k, v in os.environ.items() if k != "LLM_BACKEND"})
    llm = make_client(settings, args.log_dir)
    print(f"warm-up + {args.calls} calls to {settings.model} at {settings.base_url} ...")
    try:
        result = measure(llm, args.calls)
    except LLMError as exc:
        print(f"LLM not usable, nothing recorded: {exc}", file=sys.stderr)
        return 2
    if not result["durations_s"]:
        print(f"all {args.calls} calls failed; nothing recorded", file=sys.stderr)
        return 1
    s = stats(result)
    print(f"warm-up {result['warmup_s']:.1f} s; median {s['median']:.1f} s, min {s['min']:.1f} s, "
          f"max {s['max']:.1f} s, spread {s['spread']:.1f} s, mean {s['mean']:.1f} s, failed {result['failed']}")
    if not args.no_write:
        row = record(args.doc, result, s, settings, prompt_fingerprint())
        print(f"recorded in {args.doc}:\n{row}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
