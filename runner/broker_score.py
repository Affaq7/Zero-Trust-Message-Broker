"""Evidence-based scoring of a broker-mode repetition against a scenario's expected_broker.

The verdict never comes from the agent's final answer. It compares what the broker actually
did with what the scenario expects:

- the broker's decisions for the scenario's trace(s), from GET /api/events
  (broker_decisions.jsonl), in the order the broker finished them;
- the same decisions in the signed audit log, and its admin events (quarantine, release,
  revoke, restore); the audit log must verify (A4's verify_chain);
- the HTTP status of each scripted request, and who is quarantined at the end (/api/state).

``matched`` is True only when every expected item holds. Each failed check is listed in
``problems``. No payloads are read or written here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runner.scenarios import ExpectedBroker

AUDIT_FILE = "broker_audit.jsonl"


def _audit(audit_path: Path, trace_ids: set[str], public_key_path: Path) -> dict[str, Any]:
    from broker.audit.signing_key import load_public_key
    from broker.audit.verify import verify_chain

    lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    result = verify_chain(audit_path, load_public_key(public_key_path))
    return {
        "audit_ok": bool(result.ok),
        "audit_lines": len(lines),
        "audit_bad_line": result.bad_line,
        "audit_decisions": [[r["decision"], r.get("reason_code")] for r in lines
                            if r.get("kind") == "decision" and r.get("trace_id") in trace_ids],
        "audit_events": [r["kind"] for r in lines if r.get("kind") != "decision"],
    }


def score(expected: ExpectedBroker, *, broker_events: list[dict], trace_ids: list[str],
          log_dir: Path, audit_real: bool, public_key_path: Path,
          http_status: list[int] | None = None, final_state: dict | None = None) -> dict[str, Any]:
    actual = [[e.get("decision"), e.get("reason_code")] for e in broker_events]
    out: dict[str, Any] = {"expected_decision": expected.expected_decision, "decisions": actual,
                           "http_status": http_status, "problems": []}
    problems: list[str] = out["problems"]

    if expected.decisions is None:
        out["expected"] = None
        out["matched"] = None                       # not scored automatically (live model)
        return out
    want = [[d.decision, d.reason_code] for d in expected.decisions]
    out["expected"] = want
    if actual != want:
        problems.append(f"broker decisions {actual} != expected {want}")

    audit_path = Path(log_dir) / AUDIT_FILE
    if audit_real:
        if not audit_path.exists():
            problems.append("no audit log although the audit module is real")
        else:
            audit = _audit(audit_path, set(trace_ids), public_key_path)
            out.update(audit)
            if not audit["audit_ok"]:
                problems.append(f"audit log does not verify (line {audit['audit_bad_line']})")
            if audit["audit_decisions"] != want:
                problems.append(f"audit decisions {audit['audit_decisions']} != expected {want}")
            if audit["audit_events"] != list(expected.audit_events):
                problems.append(f"audit events {audit['audit_events']} != expected {list(expected.audit_events)}")
    elif expected.audit_events:
        problems.append("audit events expected but the audit module is a stub")

    if expected.http_status is not None and http_status != expected.http_status:
        problems.append(f"HTTP statuses {http_status} != expected {expected.http_status}")

    if expected.final_quarantined:
        agents = {a["agent"]: a for a in (final_state or {}).get("agents", [])}
        got = {name: agents.get(name, {}).get("quarantined") for name in expected.final_quarantined}
        out["final_quarantined"] = got
        if got != dict(expected.final_quarantined):
            problems.append(f"quarantined at the end {got} != expected {dict(expected.final_quarantined)}")

    out["matched"] = not problems
    return out
