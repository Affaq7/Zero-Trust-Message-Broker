"""Task A3 follow-up: a quarantine caused by the trust score (T below 0.40, A2) is
logged like a V1 quarantine, with reason TRUST_QUARANTINED, exactly once.

Covers the trust engine's on_quarantine hook, the defence manager's log line, and
the pipeline with real trust, defence and content modules: a responder whose
replies keep being cut ends up in the audit log and in the dashboard counter.
Fixed clock, in-memory audit recorder, no network.
"""

import json

import httpx
import pytest

from broker import stubs
from broker.audit.log import build_record
from broker.defence.quarantine import (
    AGENT_QUARANTINED, DENIAL_RATE_EXCEEDED, TRUST_QUARANTINED, DefenceManager,
)
from broker.pipeline import Broker, Modules
from broker.trust.risk import FACTORS
from broker.trust.trust import TrustEngine
from contracts import Envelope, make_response, new_request
from contracts.payloads import ResponsePayload

LOW = {f: "L" for f in FACTORS}


def drop_to_quarantine(trust, agent, limit=60):
    """DENY updates until the score puts `agent` in Quarantined; returns how many it took."""
    for n in range(1, limit + 1):
        if trust.update(agent, "DENY", LOW, False).state == "Quarantined":
            return n
    raise AssertionError(f"{agent} never reached Quarantined in {limit} updates")


def quarantine_lines(dm):
    return [e for e in dm.log() if e["kind"] == "quarantine"]


# --- the trust engine's hook -------------------------------------------------------

def test_hook_fires_once_on_entering_quarantined():
    trust, seen = TrustEngine(), []
    trust.on_quarantine(seen.append)
    drop_to_quarantine(trust, "database")
    assert seen == ["database"]
    for _ in range(5):                                   # stays Quarantined: no new call
        trust.update("database", "DENY", LOW, False)
    assert seen == ["database"]


def test_hook_fires_again_after_a_release():
    trust, seen = TrustEngine(), []
    trust.on_quarantine(seen.append)
    drop_to_quarantine(trust, "database")
    trust.release("database", "amna")
    drop_to_quarantine(trust, "database")
    assert seen == ["database", "database"]


def test_hook_is_not_called_for_other_states():
    trust, seen = TrustEngine(), []
    trust.on_quarantine(seen.append)
    for _ in range(5):                                   # Suspicious or Restricted, not Quarantined
        trust.update("planner", "DENY", LOW, False)
    assert trust.get("planner").state != "Quarantined"
    assert seen == []


def test_hook_needs_a_callable():
    with pytest.raises(ValueError):
        TrustEngine().on_quarantine("not callable")


# --- the defence manager's log line ---------------------------------------------------

def test_trust_drop_logs_one_trust_quarantined_line():
    trust = TrustEngine()
    dm = DefenceManager(trust=trust)
    drop_to_quarantine(trust, "database")
    assert dm.is_blocked("database")
    assert dm.check("database") == ("QUARANTINE", AGENT_QUARANTINED)
    lines = quarantine_lines(dm)
    assert lines == [{"kind": "quarantine", "agent": "database", "by": "broker",
                      "reason_code": TRUST_QUARANTINED, "ts": None, "denials": None}]
    build_record(lines[0])                               # A4 accepts it as it is


def test_no_second_line_while_quarantined():
    trust = TrustEngine()
    dm = DefenceManager(trust=trust)
    drop_to_quarantine(trust, "database")
    for t in range(10):                                  # denials of a blocked agent are not counted
        dm.record_decision("database", "DENY", float(t))
        trust.update("database", "DENY", LOW, False)
    assert len(quarantine_lines(dm)) == 1


def test_v1_first_then_trust_drop_keeps_the_v1_line_only():
    trust = TrustEngine()
    dm = DefenceManager(trust=trust)
    for t in range(5):
        dm.record_decision("malicious", "DENY", float(t))
    assert [e["reason_code"] for e in quarantine_lines(dm)] == [DENIAL_RATE_EXCEEDED]
    drop_to_quarantine(trust, "malicious")               # e.g. as a responder, while V1-blocked
    assert [e["reason_code"] for e in quarantine_lines(dm)] == [DENIAL_RATE_EXCEEDED]


def test_trust_drop_first_then_denials_do_not_add_a_v1_line():
    trust = TrustEngine()
    dm = DefenceManager(trust=trust)
    drop_to_quarantine(trust, "malicious")
    for t in range(5):
        dm.record_decision("malicious", "DENY", float(t))
    assert [e["reason_code"] for e in quarantine_lines(dm)] == [TRUST_QUARANTINED]


def test_release_then_a_new_drop_logs_again():
    trust = TrustEngine()
    dm = DefenceManager(trust=trust)
    drop_to_quarantine(trust, "database")
    dm.release("database", "amna", ts=10.0)
    assert not dm.is_blocked("database")
    drop_to_quarantine(trust, "database")
    assert [e["kind"] for e in dm.log()] == ["quarantine", "release", "quarantine"]
    assert [e["reason_code"] for e in quarantine_lines(dm)] == [TRUST_QUARANTINED] * 2


def test_v1_alone_is_unchanged():
    dm = DefenceManager(trust=TrustEngine())
    for t in range(5):
        dm.record_decision("malicious", "DENY", float(t))
    (line,) = quarantine_lines(dm)
    assert line["reason_code"] == DENIAL_RATE_EXCEEDED and line["denials"] == [0.0, 1.0, 2.0, 3.0, 4.0]


def test_a_trust_engine_without_the_hook_still_works():
    dm = DefenceManager(trust=stubs.TrustEngine())       # the stub has no on_quarantine
    for t in range(5):
        dm.record_decision("malicious", "DENY", float(t))
    assert dm.is_blocked("malicious")


# --- through the pipeline: a responder whose replies keep being cut -----------------------

class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class Recorder:
    """Stands in for audit append(): keeps every entry, returns a fake entry_hash."""

    def __init__(self):
        self.entries = []

    def __call__(self, entry):
        build_record(entry)                              # every line must pass A4's checks
        self.entries.append(entry)
        return f"{len(self.entries):064x}"


def leaky_database(request):
    """A compromised database: an aggregate reply that also carries a person column."""
    env = Envelope.model_validate_json(request.content)
    result = {"rows": [{"value": 184250, "employee_name": "someone"}]}
    return httpx.Response(200, content=make_response(env, ResponsePayload(status="ok", result=result))
                          .model_dump_json())


def aggregate_request(n):
    return json.loads(new_request(
        sender="planner", receiver="database", action="db.query_aggregate", resource="db:project_costs",
        payload={"metric": "sum", "column": "amount"}, chain_so_far=["user"],
        trace_id=f"trace-{n}").model_dump_json())


def test_pipeline_audits_the_trust_quarantine_of_a_responder():
    mods = Modules.with_real(["trust", "defence", "content", "risk"])
    assert isinstance(mods.defence, DefenceManager) and isinstance(mods.trust, TrustEngine)
    audit = Recorder()
    mods.append = audit
    clock = Clock()
    broker = Broker(mods, client=httpx.Client(transport=httpx.MockTransport(leaky_database)),
                    agent_urls={"database": "http://database.test"}, clock=clock)

    replies = []
    for n in range(40):
        replies.append(broker.handle(aggregate_request(n), {}))
        clock.t += 1
        if mods.trust.get("database").state == "Quarantined":
            break
    assert mods.trust.get("database").state == "Quarantined"
    assert all(r.decision == "SANITIZE" for r in replies)

    quarantines = [e for e in audit.entries if e.get("kind") == "quarantine"]
    assert len(quarantines) == 1
    q = quarantines[0]
    assert (q["agent"], q["by"], q["reason_code"]) == ("database", "broker", TRUST_QUARANTINED)
    assert isinstance(q["ts"], str) and q["ts"]          # the pipeline stamps the time
    # The quarantine line follows the decision line of the reply that caused it.
    assert audit.entries[-1] is q and audit.entries[-2]["decision"] == "SANITIZE"

    state = broker.state()
    assert state["counters"]["defence"]["quarantine"] == 1       # the dashboard counter
    database = next(a for a in state["agents"] if a["agent"] == "database")
    assert database["quarantined"] is True and database["trust_state"] == "Quarantined"
    events = broker.recent_events()
    assert any(e.get("kind") == "quarantine" and e.get("reason_code") == TRUST_QUARANTINED for e in events)

    for n in range(40, 45):                              # more cut replies: still one line
        broker.handle(aggregate_request(n), {})
    assert len([e for e in audit.entries if e.get("kind") == "quarantine"]) == 1
