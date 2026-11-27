"""Task A2 follow-up: a HITL decision (waiting for a human) is neutral for trust.

Before, HITL entered the agent's last-20 window as "not clean", and an approval
added nothing back, so a planner whose external emails were all approved still
fell to Suspicious after 9 of them. Now HITL does not enter the window; a
violation on the same message (injection cue, events) still lowers Ca. The
human's answer is recorded later by the pipeline (approved as ALLOW, rejected as
DENY, a timeout not at all; decided by Amna, 27 Nov), which these tests do by
calling update() the way the pipeline will.
"""

import json
import math

import httpx
import pytest

from broker.pipeline import Broker, Modules
from broker.policy.engine import PolicyResult
from broker.trust.risk import FACTORS, risk_vector
from broker.trust.trust import INJECTION_CUE, TrustEngine, default_settings
from contracts import new_request

LOW = {f: "L" for f in FACTORS}
EMAIL = risk_vector("tool.send_email_external")


def expected_T(Ba, Ca):
    w = default_settings()["weights"]
    return w["identity"] + w["behaviour"] * Ba + w["context"] * Ca


# --- the engine ------------------------------------------------------------------------

def test_hitl_keeps_the_score_and_the_state():
    e = TrustEngine()
    st = e.update("planner", "HITL", EMAIL, False)
    assert (st.T, st.state) == (pytest.approx(1.0), "Active")


def test_twenty_hitl_in_a_row_keep_a_normal_agent_active():
    e = TrustEngine()
    for _ in range(20):
        st = e.update("planner", "HITL", EMAIL, False)
    assert (st.T, st.state) == (pytest.approx(1.0), "Active")


def test_hitl_does_not_push_an_older_decision_out_of_the_window():
    e = TrustEngine()
    e.update("a", "SANITIZE", LOW, False)                   # one non-clean decision in the window
    for _ in range(25):
        e.update("a", "HITL", LOW, False)
    assert e.get("a").T == pytest.approx(expected_T(19 / 20, 1.0))  # still counted: HITL is not a message in Ba


def test_hitl_with_an_injection_cue_still_lowers_trust():
    lam, sev = default_settings()["lambda"], default_settings()["severity"][INJECTION_CUE]
    st = TrustEngine().update("planner", "HITL", EMAIL, True)
    assert st.T == pytest.approx(expected_T(1.0, math.exp(-lam * sev)))
    st = TrustEngine().update("planner", "HITL", EMAIL, False, events=[INJECTION_CUE])
    assert st.T == pytest.approx(expected_T(1.0, math.exp(-lam * sev)))


def test_hitl_is_kept_in_the_history():
    e = TrustEngine()
    e.update("planner", "HITL", EMAIL, False)
    (h,) = e.history("planner")
    assert (h["decision"], h["T_before"], h["T_after"]) == ("HITL", 1.0, 1.0)
    assert h["compound_high"] is True


def test_hitl_still_counts_down_a_v4_hold():
    e = TrustEngine()
    e.update("a", "ALLOW", LOW, False, events=["BURST_DETECTED"])
    for _ in range(default_settings()["burst_hold_messages"] - 1):
        assert e.update("a", "HITL", LOW, False).state == "Suspicious"
    assert e.update("a", "HITL", LOW, False).state == "Active"


def test_approval_later_counts_as_allow_and_rejection_as_deny():
    """What the pipeline will do after the human answers (Afaq's part 2)."""
    approved, rejected = TrustEngine(), TrustEngine()
    for e in (approved, rejected):
        e.update("planner", "SANITIZE", LOW, False)         # start below 1.0 so ALLOW shows
        e.update("planner", "HITL", EMAIL, False)
    before = approved.get("planner").T
    assert approved.update("planner", "ALLOW", EMAIL, False).T >= before
    assert rejected.update("planner", "DENY", EMAIL, False).T < before


# --- through the pipeline --------------------------------------------------------------

def needs_human(env, identity):
    return PolicyResult(verdict="ALLOW", action_class="Conditional", reason_code="NEEDS_APPROVAL",
                        needs_human=True)


def external_email(n):
    return json.loads(new_request(
        sender="planner", receiver="tool", action="tool.send_email_external", resource="email:external",
        payload={"to": ["partner@example.test"], "subject": f"s{n}", "body": "b"},
        chain_so_far=["user"], trace_id=f"trace-{n}").model_dump_json())


def test_pipeline_ten_external_emails_keep_the_planner_active():
    mods = Modules.with_real(["trust", "risk", "defence", "burst"])
    mods.evaluate_policy = needs_human
    assert isinstance(mods.trust, TrustEngine)
    broker = Broker(mods, client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))),
                    agent_urls={"tool": "http://tool.test"}, clock=lambda: 1000.0)
    outs = [broker.handle(external_email(n), {}) for n in range(10)]
    assert all(o.decision == "HITL" for o in outs)
    st = mods.trust.get("planner")
    assert (st.T, st.state) == (pytest.approx(1.0), "Active")
    assert len(broker.state()["pending_approvals"]) == 10
