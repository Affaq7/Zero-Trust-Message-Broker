"""Run one repetition of a scenario and collect what happened.

For each repetition: start the scenario's processes (fresh seed and fresh
mock world), send POST /task to the entry agent once per concurrent slot
(each with its own trace_id), wait up to the scenario timeout, then collect
the envelopes (wrapper logs), the ground truth (mock services) and the LLM
calls (by trace_id, so concurrent tasks never share calls) for each trace.
Processes are stopped afterwards.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from runner.processes import Testbed, TestbedConfig
from runner.scenarios import Scenario


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


@dataclass
class TaskOutcome:
    scenario_id: str
    rep: int
    concurrency: int
    slot: int
    trace_id: str
    started_at: str
    ended_at: str
    latency_ms: int
    status: str                                # completed | timeout | error
    task_status: str | None = None             # ok | error (from the agent)
    answer: str | None = None
    error: str | None = None
    envelopes: list[dict] = field(default_factory=list)
    ground_truth: list[dict] = field(default_factory=list)
    llm_calls: list[dict] = field(default_factory=list)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def collect_envelopes(log_dir: Path, trace_id: str) -> list[dict]:
    records = []
    for path in sorted(log_dir.glob("*.jsonl")):
        if path.name == "mocks.jsonl":
            continue
        records += [r for r in _read_jsonl(path) if r.get("envelope", {}).get("trace_id") == trace_id]
    return sorted(records, key=lambda r: r["logged_at"])


def collect_llm_calls(log_dir: Path, trace_id: str) -> list[dict]:
    calls = []
    for path in sorted((log_dir / "llm").glob("*.jsonl")):
        calls += [c for c in _read_jsonl(path) if c.get("trace_id") == trace_id]
    return sorted(calls, key=lambda c: c["logged_at"])


def _send_task(url: str, task: str, trace_id: str, timeout_s: int) -> tuple[str, dict | None, str | None]:
    try:
        r = httpx.post(f"{url}/task", json={"task": task, "trace_id": trace_id}, timeout=timeout_s)
    except httpx.TimeoutException:
        return "timeout", None, f"no answer within {timeout_s}s"
    except httpx.TransportError as exc:
        return "error", None, f"entry agent unreachable: {type(exc).__name__}"
    if r.status_code != 200:
        return "error", None, f"entry agent answered HTTP {r.status_code}"
    return "completed", r.json(), None


def run_repetition(scenario: Scenario, rep: int, run_dir: Path, *, concurrency: int = 1,
                   llm_backend: str = "fake", llm_base_url: str = "http://localhost:11434",
                   debug_prompts: bool = False) -> list[TaskOutcome]:
    if scenario.baseline != "applicable":
        raise ValueError(f"{scenario.id} is not applicable in direct mode; nothing to run")
    rep_dir = run_dir / f"{scenario.id}" / f"c{concurrency}" / f"rep{rep:02d}"
    config = TestbedConfig(
        agents=[a.model_dump() for a in scenario.agents], run_dir=rep_dir, seed=rep,
        llm_backend=llm_backend, fake_llm=scenario.fake_llm, llm_base_url=llm_base_url,
        debug_prompts=debug_prompts)
    log_dir = rep_dir / "logs"

    with Testbed(config) as tb:
        mocks_url = tb.url("mocks")
        httpx.post(f"{mocks_url}/reset", timeout=30).raise_for_status()
        entry_url = tb.url(scenario.entry.agent)

        def one(slot: int) -> TaskOutcome:
            trace_id = str(uuid4())
            started = utc_now()
            status, body, error = _send_task(entry_url, scenario.entry.task, trace_id, scenario.timeout_s)
            ended = utc_now()
            body = body or {}
            return TaskOutcome(
                scenario_id=scenario.id, rep=rep, concurrency=concurrency, slot=slot,
                trace_id=trace_id, started_at=iso(started), ended_at=iso(ended),
                latency_ms=round((ended - started).total_seconds() * 1000), status=status,
                task_status=body.get("status"), answer=body.get("answer"),
                error=error or body.get("error"))

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            outcomes = list(pool.map(one, range(concurrency)))

        for o in outcomes:
            gt = httpx.get(f"{mocks_url}/ground-truth", params={"trace_id": o.trace_id}, timeout=30)
            o.ground_truth = gt.json()["records"]

    for o in outcomes:
        o.envelopes = collect_envelopes(log_dir, o.trace_id)
        o.llm_calls = collect_llm_calls(log_dir, o.trace_id)
    return outcomes


def outcome_dict(o: TaskOutcome) -> dict[str, Any]:
    return dict(o.__dict__)
