"""Run one repetition of a scenario and collect what happened.

For each repetition: start the scenario's processes (fresh seed and fresh
mock world), send POST /task to the entry agent once per concurrent slot
(each with its own trace_id), wait up to the scenario timeout, then collect
the envelopes (wrapper logs), the ground truth (mock services) and the LLM
calls (by trace_id, so concurrent tasks never share calls) for each trace.
Scripted-attack scenarios skip POST /task; they launch agents/scripted.py as
a subprocess that sends its own raw requests and exits.
"""

import json
import os
import subprocess
import sys
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
    script_log: list[dict] = field(default_factory=list)
    # MODE=broker only: the broker's decision for every message of this trace, oldest first
    # (from GET /api/events), and what the broker ran with (from GET /health).
    broker_events: list[dict] = field(default_factory=list)
    broker_info: dict | None = None
    # MODE=broker with an expected_broker block: the evidence-based verdict (runner/broker_score.py).
    broker_score: dict | None = None


BROKER_EVENT_FIELDS = ("msg_id", "sender", "receiver", "action", "step", "decision", "reason_code",
                       "events", "forwarded")


def read_headers(read_token: str | None) -> dict[str, str]:
    """X-Read-Token for the broker's /api/state and /api/events (the run's own read token)."""
    return {"X-Read-Token": read_token or ""}


def collect_broker(broker_url: str, trace_ids: list[str],
                   read_token: str | None = None) -> tuple[dict, dict[str, list[dict]]]:
    """What the broker ran with, and its decisions per trace (decision + reason code, no payloads)."""
    health = httpx.get(f"{broker_url}/health", timeout=30).json()
    events = httpx.get(f"{broker_url}/api/events", params={"limit": 1000}, timeout=30,
                       headers=read_headers(read_token)).json()["events"]
    info = {"mode": "broker", "broker_real": health.get("real", []), "stubbed": health.get("stubbed", []),
            "modules": health.get("modules", {}), "ignored": health.get("ignored", {})}
    per_trace: dict[str, list[dict]] = {t: [] for t in trace_ids}
    for e in reversed(events):                                   # /api/events is newest first
        if e.get("kind") == "decision" and e.get("trace_id") in per_trace:
            per_trace[e["trace_id"]].append({k: e.get(k) for k in BROKER_EVENT_FIELDS})
    return info, per_trace


def _append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


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


def rep_dir_for(run_dir: Path, scenario_id: str, concurrency: int, rep: int) -> Path:
    return Path(run_dir) / scenario_id / f"c{concurrency}" / f"rep{rep:02d}"


def run_repetition(scenario: Scenario, rep: int, run_dir: Path, *, concurrency: int = 1,
                   llm_backend: str = "fake", llm_base_url: str = "http://localhost:11434",
                   debug_prompts: bool = False, planner_prompt: str | None = None,
                   mode: str = "direct", hold: bool = False) -> list[TaskOutcome]:
    """``planner_prompt`` (v1/v2) overrides the scenario's own planner_prompt;
    both unset means the planner's default version."""
    if not _runnable(scenario, mode):
        raise ValueError(f"{scenario.id} is not applicable in {mode} mode; nothing to run")
    rep_dir = rep_dir_for(run_dir, scenario.id, concurrency, rep)
    config = TestbedConfig(
        agents=[a.model_dump() for a in scenario.agents], run_dir=rep_dir, seed=rep,
        llm_backend=llm_backend, fake_llm=scenario.model_dump(mode="json")["fake_llm"], llm_base_url=llm_base_url,
        debug_prompts=debug_prompts, planner_prompt=planner_prompt or scenario.planner_prompt or "",
        mode=mode, hold=hold)
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

        if mode == "broker":
            info, per_trace = collect_broker(tb.url("broker"), [o.trace_id for o in outcomes], tb.read_token)
            for o in outcomes:
                o.broker_info, o.broker_events = info, per_trace[o.trace_id]
            # The broker's view of every agent at the end of the repetition (T, trust state,
            # quarantined, epoch), and its pending approvals; no payloads.
            state = httpx.get(f"{tb.url('broker')}/api/state", timeout=30,
                              headers=read_headers(tb.read_token)).json()
            (rep_dir / "broker_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    for o in outcomes:
        o.envelopes = collect_envelopes(log_dir, o.trace_id)
        o.llm_calls = collect_llm_calls(log_dir, o.trace_id)
        if mode == "broker":
            o.broker_score = _broker_score(scenario, o, log_dir, state)
    return outcomes


def _runnable(scenario: Scenario, mode: str) -> bool:
    return (scenario.broker_status() if mode == "broker" else scenario.baseline) == "applicable"


def _broker_score(scenario: Scenario, o: TaskOutcome, log_dir: Path, state: dict | None,
                  http_status: list[int] | None = None) -> dict | None:
    """The evidence-based verdict for one trace, or None without an expected_broker block."""
    if scenario.expected_broker is None:
        return None
    from runner.broker_score import score
    from runner.processes import SIGNING_PUB
    real = set((o.broker_info or {}).get("broker_real", []))
    return score(scenario.expected_broker, broker_events=o.broker_events, trace_ids=[o.trace_id],
                 log_dir=log_dir, audit_real="append" in real, public_key_path=SIGNING_PUB,
                 http_status=http_status, final_state=state)


def _admin_call(tb: Testbed, step: dict) -> tuple[int, Any]:
    """An operator call the runner makes with the run's admin token (never given to the attacker)."""
    kind = step["admin"]
    body = ({"agent": step["agent"], "reviewer": step["by"]} if kind == "release"
            else {"agent": step["agent"], "by": step["by"]})
    try:
        r = httpx.post(f"{tb.url('broker')}/admin/{kind}", json=body, timeout=30,
                       headers={"X-Admin-Token": tb.admin_token or ""})
    except httpx.TransportError as exc:
        return 0, f"broker unreachable: {type(exc).__name__}"
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def run_scripted_repetition(scenario: Scenario, rep: int, run_dir: Path, *,
                            llm_backend: str = "fake", llm_base_url: str = "http://localhost:11434",
                            debug_prompts: bool = False, mode: str = "direct",
                            hold: bool = False) -> list[TaskOutcome]:
    """Run one repetition of a scripted-attack scenario.

    Starts victim agents, launches agents/scripted.py as a subprocess, waits
    for it to finish, reads its log, and returns a single-element list of
    TaskOutcome (matching the signature of run_repetition).
    """
    if scenario.scripted is None:
        raise ValueError(f"{scenario.id} is not a scripted scenario")
    if not _runnable(scenario, mode):
        raise ValueError(f"{scenario.id} is not applicable in {mode} mode; nothing to run")
    rep_dir = rep_dir_for(run_dir, scenario.id, 1, rep)
    config = TestbedConfig(
        agents=[a.model_dump() for a in scenario.agents], run_dir=rep_dir, seed=rep,
        llm_backend=llm_backend, fake_llm=scenario.model_dump(mode="json")["fake_llm"],
        llm_base_url=llm_base_url, debug_prompts=debug_prompts, mode=mode, hold=hold)
    log_dir = rep_dir / "logs"
    script_log_path = rep_dir / "script_log.jsonl"
    script_config_path = rep_dir / "script_config.json"
    trace_id = str(uuid4())

    with Testbed(config) as tb:
        mocks_url = tb.url("mocks")
        httpx.post(f"{mocks_url}/reset", timeout=30).raise_for_status()

        agent_urls = {name: proc.url for name, proc in tb.procs.items() if name not in ("mocks", "broker")}
        base_cfg = {
            "agent_urls": agent_urls,
            "sender": scenario.scripted.sender,
            "sender_role": scenario.scripted.sender_role,
            "log_path": str(script_log_path),
            "trace_id": trace_id,
            "max_steps": 50,
        }
        if mode == "broker":
            # The attacker gets the broker's address and the run's credential files (a compromised
            # agent holds real credentials); never the admin token or the forwarding secret.
            base_cfg.update({"mode": "broker", "broker_url": tb.url("broker"),
                             "keys_dir": str(tb.secrets_dir / "keys")})
        steps = [s.model_dump(mode="json") for s in scenario.scripted.steps]
        script_config_path.parent.mkdir(parents=True, exist_ok=True)

        # Requests go to the scripted subprocess in runs; an admin step between them is made by
        # the runner itself. Step numbers stay global and the log is one file.
        started = utc_now()
        status, error, done = "completed", None, 0
        while done < len(steps) and status == "completed":
            if "admin" in steps[done]:
                if hold:          # demo: the quarantine stays on the dashboard until the operator goes on
                    s = steps[done]
                    tb._hold(f"next: admin {s['admin']} of {s['agent']} by {s['by']}; press Enter to make it")
                code, body = _admin_call(tb, steps[done])
                _append_jsonl(script_log_path, {"step": done, "admin": steps[done]["admin"],
                                                "agent": steps[done]["agent"], "by": steps[done]["by"],
                                                "http_status": code, "response_body": body,
                                                "logged_at": iso(utc_now())})
                done += 1
                continue
            end = done
            while end < len(steps) and "admin" not in steps[end]:
                end += 1
            cfg = {**base_cfg, "steps": steps[done:end], "first_step": done, "append": done > 0}
            script_config_path.write_text(json.dumps(cfg), encoding="utf-8")
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "agents.scripted", "--config", str(script_config_path)],
                    timeout=scenario.timeout_s, capture_output=True, text=True,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"})
                if result.returncode != 0:
                    status, error = "error", result.stderr.strip()
            except subprocess.TimeoutExpired:
                status = "timeout"
                error = f"scripted agent did not finish within {scenario.timeout_s}s"
            done = end
        ended = utc_now()

        gt_resp = httpx.get(f"{mocks_url}/ground-truth", timeout=30)
        ground_truth = gt_resp.json()["records"]
        broker_info, broker_events, state = None, [], None
        if mode == "broker":
            broker_info, per_trace = collect_broker(tb.url("broker"), [trace_id], tb.read_token)
            broker_events = per_trace[trace_id]
            state = httpx.get(f"{tb.url('broker')}/api/state", timeout=30,
                              headers=read_headers(tb.read_token)).json()
            (rep_dir / "broker_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    script_log = _read_jsonl(script_log_path)
    entries = [e for e in script_log if "step" in e]

    envelopes = collect_envelopes(log_dir, trace_id)

    o = TaskOutcome(
        scenario_id=scenario.id, rep=rep, concurrency=1, slot=0,
        trace_id=trace_id, started_at=iso(started), ended_at=iso(ended),
        latency_ms=round((ended - started).total_seconds() * 1000),
        status=status, error=error, envelopes=envelopes,
        ground_truth=ground_truth, script_log=entries)
    o.llm_calls = collect_llm_calls(log_dir, trace_id)      # as run_repetition does; llm_time_ms is derived from it
    if mode == "broker":
        o.broker_info, o.broker_events = broker_info, broker_events
        statuses = [e["http_status"] for e in entries if "admin" not in e]
        o.broker_score = _broker_score(scenario, o, log_dir, state, http_status=statuses)
    return [o]


def outcome_dict(o: TaskOutcome) -> dict[str, Any]:
    return dict(o.__dict__)
