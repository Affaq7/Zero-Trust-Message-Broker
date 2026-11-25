"""Example audit lines for docs/audit-log-examples.md (task A4, Amna).

The broker pipeline does not exist yet, so these entries are built by hand
from the scenarios (N1, A2, N3-style external mail, A1, A9, A10) and written by
the real A4 code with a throwaway key. Replace them with lines from a broker
run once Afaq's pipeline (F1) is on main.

    python -m broker.audit.examples      # prints the public key and the lines
"""

import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.audit.log import AuditLog, payload_hash
from broker.identity.keys import public_jwk

ACTIVE = {"T_before": 1.0, "T_after": 1.0, "state_before": "Active", "state_after": "Active"}


def _identity(agent: str, role: str) -> dict:
    return {"ok": True, "agent": agent, "role": role, "instance_id": f"{agent}-1", "epoch": 0,
            "reason_code": None}


def entries() -> list[dict]:
    """One decision line for each of the five decisions, plus A3 events."""
    return [
        {   # N1: planner asks the database for an aggregate
            "kind": "decision", "ts": "2026-11-25T19:00:00.000+00:00",
            "trace_id": "4f1c2a9e-0d6b-4b8e-9a51-2f7c1e0b6a11",
            "msg_id": "9b2e7c40-3f1a-4d2b-8c6e-5a9d0e1f2b31", "parent_msg_id": None,
            "msg_type": "request", "sender": "planner", "receiver": "database",
            "action": "db.query_aggregate", "resource": "db:project_costs",
            "payload_hash": payload_hash({"metric": "sum", "column": "cost",
                                          "filters": {"project": "Project X"}}),
            "identity": _identity("planner", "planner"), "trust": ACTIVE,
            "risk": dict(zip("RTDEPAS", "LLMLLML")), "compound_high": False,
            "decision": "ALLOW", "reason_code": "POLICY_ALLOW", "events": [], "redacted_fields": None,
        },
        {   # A2: the database's reply carries individual salaries; F3 cuts them
            "kind": "decision", "ts": "2026-11-25T19:00:01.000+00:00",
            "trace_id": "4f1c2a9e-0d6b-4b8e-9a51-2f7c1e0b6a11",
            "msg_id": "c3d4e5f6-1a2b-4c3d-9e8f-7a6b5c4d3e21",
            "parent_msg_id": "9b2e7c40-3f1a-4d2b-8c6e-5a9d0e1f2b31",
            "msg_type": "response", "sender": "database", "receiver": "planner",
            "action": "db.query_aggregate", "resource": "db:project_costs",
            "payload_hash": payload_hash({"status": "ok", "result": {"total": 184250},
                                          "rows": [{"name": "redacted", "salary": 0}]}),
            "identity": _identity("database", "database"),
            "trust": {"T_before": 1.0, "T_after": 0.9086, "state_before": "Active",
                      "state_after": "Active"},
            "risk": dict(zip("RTDEPAS", "LLMLLML")), "compound_high": False,
            "decision": "SANITIZE", "reason_code": None, "events": ["REPLY_SANITIZED"],
            "redacted_fields": ["rows"],
        },
        {   # external mail: Conditional action that needs a human
            "kind": "decision", "ts": "2026-11-25T19:00:02.000+00:00",
            "trace_id": "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c01",
            "msg_id": "0e1f2a3b-4c5d-4e6f-8a7b-9c0d1e2f3a41", "parent_msg_id": None,
            "msg_type": "request", "sender": "planner", "receiver": "tool",
            "action": "tool.send_email_external", "resource": "email:external",
            "payload_hash": payload_hash({"to": ["partner@example.com"], "subject": "Project X cost",
                                          "body": "Total so far: 184,250."}),
            "identity": _identity("planner", "planner"), "trust": ACTIVE,
            "risk": dict(zip("RTDEPAS", "HMMHMMH")), "compound_high": True,
            "decision": "HITL", "reason_code": "HITL_PENDING", "events": [], "redacted_fields": None,
        },
        {   # A1: research asks for rows, which only the planner may do
            "kind": "decision", "ts": "2026-11-25T19:00:03.000+00:00",
            "trace_id": "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d61",
            "msg_id": "5d6e7f80-9a1b-4c2d-8e3f-4a5b6c7d8e91", "parent_msg_id": None,
            "msg_type": "request", "sender": "research", "receiver": "database",
            "action": "db.query_rows", "resource": "db:employees",
            "payload_hash": payload_hash({"table": "employees", "columns": ["name", "salary"]}),
            "identity": _identity("research", "research"),
            "trust": {"T_before": 1.0, "T_after": 0.857, "state_before": "Active",
                      "state_after": "Active"},
            "risk": dict(zip("RTDEPAS", "LLHLMMM")), "compound_high": False,
            "decision": "DENY", "reason_code": "ROLE_NOT_ALLOWED",
            "events": ["INDIVIDUAL_DATA_REQUEST"], "redacted_fields": None,
        },
        {   # A9: the fifth denial in 60 s quarantines the agent (A3, V1)
            "kind": "quarantine", "ts": "2026-11-25T19:00:08.000+00:00", "agent": "research",
            "by": "broker", "reason_code": "DENIAL_RATE_EXCEEDED",
            "denials": [1764097204.0, 1764097205.0, 1764097206.0, 1764097207.0, 1764097208.0],
        },
        {   # A9: the next message from the quarantined agent
            "kind": "decision", "ts": "2026-11-25T19:00:09.000+00:00",
            "trace_id": "8c9d0e1f-2a3b-4c4d-9e5f-6a7b8c9d0e71",
            "msg_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c81", "parent_msg_id": None,
            "msg_type": "request", "sender": "research", "receiver": "database",
            "action": "db.query_rows", "resource": "db:payroll",
            "payload_hash": payload_hash({"table": "payroll", "columns": ["name", "bank_account"]}),
            "identity": _identity("research", "research"),
            "trust": {"T_before": 0.5996, "T_after": 0.5996, "state_before": "Restricted",
                      "state_after": "Restricted"},
            "risk": None, "compound_high": None,
            "decision": "QUARANTINE", "reason_code": "AGENT_QUARANTINED", "events": [],
            "redacted_fields": None,
        },
        {   # A9: a reviewer releases the agent
            "kind": "release", "ts": "2026-11-25T19:05:00.000+00:00", "agent": "research",
            "by": "kissa", "reason_code": None, "denials": None,
        },
        {   # A10: an operator revokes an agent mid-session
            "kind": "revoke", "ts": "2026-11-25T19:06:00.000+00:00", "agent": "tool",
            "by": "amna", "reason_code": None, "denials": None,
        },
    ]


def main() -> int:
    key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "broker_audit.jsonl"
        log = AuditLog(path, key)
        for e in entries():
            log.append(e)
        print(json.dumps(public_jwk(key.public_key())))
        print(path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
