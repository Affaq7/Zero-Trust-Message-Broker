"""Task A2: trust engine (broker/trust/trust.py), V4 rule (rules.py), simulation."""

import copy
import math
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from broker.trust.risk import FACTORS, risk_vector
from broker.trust.rules import BurstDetector
from broker.trust.trust import (
    BURST_DETECTED, INDIVIDUAL_DATA_REQUEST, INJECTION_CUE, REPLY_SANITIZED,
    SETTINGS_PATH, TrustEngine, TrustState, default_settings, load_settings,
)

REPO = Path(__file__).resolve().parents[2]
LOW = {f: "L" for f in FACTORS}
S = default_settings()


def expected_T(Ba: float, Ca: float) -> float:
    w = S["weights"]
    return w["identity"] + w["behaviour"] * Ba + w["context"] * Ca


def settings(**changes):
    s = copy.deepcopy(S)
    s.update(changes)
    return s


def write(tmp_path, data):
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


# --- settings ------------------------------------------------------------

def test_approved_starting_values():
    assert S["weights"] == {"identity": 0.20, "behaviour": 0.50, "context": 0.30}
    assert (S["window"], S["lambda"], S["eta"], S["hysteresis"]) == (20, 0.5, 0.05, 0.05)
    assert S["severity"] == {"DENY": 1.0, INDIVIDUAL_DATA_REQUEST: 1.0,
                             INJECTION_CUE: 0.5, REPLY_SANITIZED: 0.5}
    assert S["bands"] == {"active": 0.80, "suspicious": 0.60, "restricted": 0.40}
    assert S["release_T"] == 0.50
    assert S["burst_limit_per_trace"] == 10


def test_weights_must_sum_to_one(tmp_path):
    data = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8"))
    data["weights"]["identity"] = 0.3
    with pytest.raises(ValueError, match="weights"):
        load_settings(write(tmp_path, data))


def test_bands_must_be_ordered(tmp_path):
    data = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8"))
    data["bands"]["suspicious"] = 0.9
    with pytest.raises(ValueError, match="bands"):
        load_settings(write(tmp_path, data))


def test_release_T_must_be_restricted(tmp_path):
    data = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8"))
    data["release_T"] = 0.7
    with pytest.raises(ValueError, match="release_T"):
        load_settings(write(tmp_path, data))


# --- get and the formula ---------------------------------------------------

def test_new_agent_starts_active_at_one():
    st = TrustEngine().get("planner")
    assert isinstance(st, TrustState)
    assert st == TrustState(agent="planner", T=1.0, state="Active")


def test_agents_are_independent():
    e = TrustEngine()
    e.update("research", "DENY", LOW, False)
    assert e.get("planner").T == 1.0
    assert e.get("research").T < 1.0


def test_one_deny_follows_the_formula():
    st = TrustEngine().update("a", "DENY", LOW, False)
    assert st.T == pytest.approx(expected_T(19 / 20, math.exp(-0.5)))
    assert st.state == "Active"     # 0.857: one early DENY does not quarantine


def test_clean_message_recovers_ca():
    e = TrustEngine()
    e.update("a", "DENY", LOW, False)
    st = e.update("a", "ALLOW", LOW, False)
    Ca = math.exp(-0.5) + 0.05 * (1 - math.exp(-0.5))
    assert st.T == pytest.approx(expected_T(19 / 20, Ca))


def test_window_forgets_after_twenty():
    e = TrustEngine()
    e.update("a", "HITL", LOW, False)
    for _ in range(19):
        e.update("a", "ALLOW", LOW, False)
    assert e.get("a").T < 1.0
    e.update("a", "ALLOW", LOW, False)
    assert e.get("a").T == pytest.approx(1.0)


# --- counting (A-R2 and the five decisions) ----------------------------------

def test_hitl_and_sanitize_lower_ba_but_are_not_violations():
    for d in ("HITL", "SANITIZE"):
        st = TrustEngine().update("a", d, LOW, False)
        assert st.T == pytest.approx(expected_T(19 / 20, 1.0))


def test_reply_sanitized_is_a_half_violation():
    st = TrustEngine().update("database", "SANITIZE", LOW, False, events=[REPLY_SANITIZED])
    assert st.T == pytest.approx(expected_T(19 / 20, math.exp(-0.5 * 0.5)))


def test_injection_cue_severity_half():
    st = TrustEngine().update("a", "ALLOW", LOW, True)
    assert st.T == pytest.approx(expected_T(1.0, math.exp(-0.25)))


def test_injection_cue_flag_and_event_count_once():
    a = TrustEngine().update("a", "ALLOW", LOW, True, events=[INJECTION_CUE])
    b = TrustEngine().update("a", "ALLOW", LOW, True)
    assert a.T == b.T


def test_individual_data_request_severity_one():
    st = TrustEngine().update("a", "ALLOW", LOW, False, events=[INDIVIDUAL_DATA_REQUEST])
    assert st.T == pytest.approx(expected_T(1.0, math.exp(-0.5)))


def test_one_message_counts_once_with_the_highest_severity():
    st = TrustEngine().update("a", "DENY", LOW, True, events=[INDIVIDUAL_DATA_REQUEST, REPLY_SANITIZED])
    assert st.T == pytest.approx(expected_T(19 / 20, math.exp(-0.5 * 1.0)))


# --- states and hysteresis -----------------------------------------------------

def test_attacker_bands_in_order():
    e = TrustEngine()
    states = [e.update("x", "DENY", LOW, False).state for _ in range(13)]
    assert states[0] == "Active"
    assert states[1] == "Suspicious"
    assert "Restricted" in states
    assert states[-1] == "Quarantined"
    order = ["Active", "Suspicious", "Restricted", "Quarantined"]
    assert [order.index(s) for s in states] == sorted(order.index(s) for s in states)


def test_quarantined_is_sticky_until_release():
    e = TrustEngine()
    for _ in range(13):
        e.update("x", "DENY", LOW, False)
    for _ in range(40):
        st = e.update("x", "ALLOW", LOW, False)
    assert st.T > 0.8
    assert st.state == "Quarantined"


def test_climbing_needs_the_margin():
    e = TrustEngine()
    e.update("a", "DENY", LOW, False)
    e.update("a", "DENY", LOW, False)
    assert e.get("a").state == "Suspicious"
    seen = []
    for _ in range(40):
        st = e.update("a", "ALLOW", LOW, False)
        seen.append((st.T, st.state))
        if st.state == "Active":
            break
    assert st.state == "Active"
    assert st.T >= 0.85
    assert all(state == "Suspicious" for T, state in seen[:-1] if 0.80 <= T < 0.85)


def test_dropping_is_immediate():
    e = TrustEngine()
    st = e.update("a", "DENY", LOW, False)
    st = e.update("a", "DENY", LOW, False)
    assert st.T < 0.80 and st.state == "Suspicious"


# --- V4 burst ----------------------------------------------------------------

def test_burst_moves_to_suspicious_and_holds():
    e = TrustEngine()
    st = e.update("planner", "ALLOW", LOW, False, events=[BURST_DETECTED])
    assert st.T == pytest.approx(1.0)       # V4 does not lower T
    assert st.state == "Suspicious"
    states = [e.update("planner", "ALLOW", LOW, False).state for _ in range(S["burst_hold_messages"])]
    assert states[:-1] == ["Suspicious"] * (S["burst_hold_messages"] - 1)
    assert states[-1] == "Active"


def test_burst_detector_limit_per_agent_per_trace():
    d = BurstDetector()
    assert [d.observe("planner", "t1") for _ in range(10)] == [()] * 10
    assert d.observe("planner", "t1") == (BURST_DETECTED,)
    assert d.observe("planner", "t2") == ()
    assert d.observe("research", "t1") == ()
    d.forget("t1")
    assert d.observe("planner", "t1") == ()


def test_burst_detector_bad_limit():
    with pytest.raises(ValueError):
        BurstDetector(limit=0)


# --- release -------------------------------------------------------------------

def test_release_restarts_in_restricted_at_half():
    e = TrustEngine()
    for _ in range(13):
        e.update("x", "DENY", LOW, False)
    st = e.release("x", reviewer="kissa")
    assert (st.agent, st.state) == ("x", "Restricted")
    assert st.T == pytest.approx(0.50)
    assert e.history("x")[-1]["reviewer"] == "kissa"


def test_release_then_earns_its_way_up():
    e = TrustEngine()
    for _ in range(13):
        e.update("x", "DENY", LOW, False)
    e.release("x", reviewer="kissa")
    states = [e.update("x", "ALLOW", LOW, False).state for _ in range(20)]
    first_suspicious = states.index("Suspicious") + 1
    first_active = states.index("Active") + 1
    assert first_suspicious == 6      # T = 0.65 after 6 clean messages
    assert first_active == 14         # T = 0.85 after 14


def test_release_needs_a_reviewer():
    with pytest.raises(ValueError):
        TrustEngine().release("x", reviewer=" ")


# --- inputs, history, determinism ------------------------------------------------

@pytest.mark.parametrize("bad", [
    dict(decision="MAYBE"), dict(risk={}), dict(risk=dict(LOW, R="X")), dict(events=["NOPE"]),
])
def test_bad_input_is_rejected(bad):
    args = dict(agent="a", decision="ALLOW", risk=LOW, injection_cue=False) | bad
    with pytest.raises(ValueError):
        TrustEngine().update(**args)


def test_history_records_every_change():
    e = TrustEngine()
    e.update("a", "DENY", risk_vector("tool.send_email_external"), False)
    h = e.history("a")
    assert len(h) == 1
    assert h[0]["violations"] == ["DENY"]
    assert h[0]["severity"] == 1.0
    assert h[0]["compound_high"] is True
    assert h[0]["T_before"] == 1.0 and h[0]["T_after"] < 1.0
    assert h[0]["state_before"] == "Active"
    h[0]["T_after"] = 99
    assert e.history("a")[0]["T_after"] != 99


def test_deterministic():
    def run():
        e = TrustEngine()
        return [e.update("a", d, LOW, c).T for d, c in
                [("ALLOW", False), ("DENY", True), ("HITL", False), ("ALLOW", False)]]
    assert run() == run()


def test_other_settings_can_be_injected():
    e = TrustEngine(settings(**{"lambda": 1.0}))
    assert e.update("a", "ALLOW", LOW, False, events=[INDIVIDUAL_DATA_REQUEST]).T == pytest.approx(
        expected_T(1.0, math.exp(-1.0)))


# --- simulation (A2 done-when) ------------------------------------------------------

def test_simulation_good_stays_active_attacker_quarantined():
    out = subprocess.run([sys.executable, str(REPO / "scripts" / "simulate_trust.py")],
                         capture_output=True, text=True, check=True, cwd=REPO).stdout
    assert "good agent always Active: True" in out
    assert "attacker first Quarantined at message: 13" in out
