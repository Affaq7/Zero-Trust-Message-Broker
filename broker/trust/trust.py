"""Trust engine (task A2, Amna). Pipeline step 6, after the hard gates.

Keeps one trust score T per agent, in memory, and moves it with behaviour.

    T = 0.20 x Ia + 0.50 x Ba + 0.30 x Ca          (plan 4.3)

Ia  identity confidence: 1, because identity is verified (step 2) before this
    step runs; an unverified message never reaches the engine.
Ba  behaviour: share of ALLOW in the agent's last 20 decided messages. HITL
    (waiting for a human) is neutral: it does not enter the window, because the
    human's answer is still to come (the pipeline records it later: approved as
    ALLOW, rejected as DENY, a timeout not at all; decided by Amna, 27 Nov).
Ca  context compliance: Ca x e^(-lambda x R) after a violation, Ca + eta x (1 - Ca)
    after a clean message (plan 4.4, applied to Ca so the formula stays the one
    source of T; decided by Amna, 25 Nov).

States (plan 5): Active, Suspicious, Restricted, Quarantined, with hysteresis
when climbing. Quarantined is left only through release() (plan 5.1).
V1 (5 denials in 60 s) is not here: it belongs to A3 (broker/defence/quarantine.py).

Pure Python: no network, no model calls, deterministic for the same calls.
Settings and starting values: trust_settings.yaml (PROVISIONAL, A-R1).
Interface fixed on 25 Nov (context file, section 7), plus one optional
argument on update(): `events`, and one optional extra: on_quarantine(), which
lets the defence manager (A3) log a quarantine caused by the score itself.
"""

import math
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable, Literal

import yaml
from pydantic import BaseModel

from broker.trust.risk import FACTORS, LEVELS

SETTINGS_PATH = Path(__file__).with_name("trust_settings.yaml")

State = Literal["Active", "Suspicious", "Restricted", "Quarantined"]
DECISIONS = ("ALLOW", "SANITIZE", "HITL", "DENY", "QUARANTINE")

# Reason codes the engine accepts in `events` (docs/detection-design.md, section 4).
INJECTION_CUE = "INJECTION_CUE"                       # V3
BURST_DETECTED = "BURST_DETECTED"                     # V4
INDIVIDUAL_DATA_REQUEST = "INDIVIDUAL_DATA_REQUEST"   # V5
REPLY_SANITIZED = "REPLY_SANITIZED"                   # responder's reply was cut (A2)
EVENTS = (INJECTION_CUE, BURST_DETECTED, INDIVIDUAL_DATA_REQUEST, REPLY_SANITIZED)

# Tolerance for comparing T with a band edge (float rounding, e.g. 0.6499999).
_EPS = 1e-9

# Order of the states, safest first.
_ORDER: tuple[State, ...] = ("Active", "Suspicious", "Restricted", "Quarantined")


class TrustState(BaseModel):
    agent: str
    T: float
    state: State


# --- settings ----------------------------------------------------------------

def load_settings(path: Path = SETTINGS_PATH) -> dict:
    """Load and check trust_settings.yaml."""
    with open(path, encoding="utf-8") as f:
        s = yaml.safe_load(f)
    w = s["weights"]
    if set(w) != {"identity", "behaviour", "context"} or not math.isclose(sum(w.values()), 1.0):
        raise ValueError(f"weights need identity, behaviour, context summing to 1, got {w}")
    if set(s["severity"]) != {"DENY", INDIVIDUAL_DATA_REQUEST, INJECTION_CUE, REPLY_SANITIZED}:
        raise ValueError(f"severity needs DENY and the V3/V5/REPLY_SANITIZED codes, got {sorted(s['severity'])}")
    b = s["bands"]
    if not 0 < b["restricted"] < b["suspicious"] < b["active"] <= 1:
        raise ValueError(f"bands must be 0 < restricted < suspicious < active <= 1, got {b}")
    if not (isinstance(s["window"], int) and s["window"] >= 1):
        raise ValueError("window must be a whole number of at least 1")
    if not (isinstance(s["burst_hold_messages"], int) and s["burst_hold_messages"] >= 0):
        raise ValueError("burst_hold_messages must be a whole number of at least 0")
    if not (isinstance(s["burst_limit_per_trace"], int) and s["burst_limit_per_trace"] >= 1):
        raise ValueError("burst_limit_per_trace must be a whole number of at least 1")
    for key in ("eta", "hysteresis", "release_T"):
        if not 0 <= s[key] <= 1:
            raise ValueError(f"{key} must be in 0..1")
    if s["lambda"] < 0:
        raise ValueError("lambda must not be negative")
    if not b["restricted"] <= s["release_T"] < b["suspicious"]:
        raise ValueError("release_T must fall in the Restricted band")
    return s


@lru_cache(maxsize=1)
def default_settings() -> dict:
    return load_settings()


# --- per-agent record ----------------------------------------------------------

@dataclass
class _Agent:
    window: deque          # True = ALLOW, False = anything else
    Ca: float = 1.0
    state: State = "Active"
    hold: int = 0          # messages left in a V4 Suspicious hold
    history: list = field(default_factory=list)


class TrustEngine:
    """One trust score per agent, in memory (Redis is FYP-II)."""

    def __init__(self, settings: dict | None = None):
        self.s = settings if settings is not None else default_settings()
        self._agents: dict[str, _Agent] = {}
        self._quarantine_listeners: list[Callable[[str], None]] = []

    # --- interface (section 7) ---------------------------------------------

    def get(self, agent: str) -> TrustState:
        a = self._agent(agent)
        return TrustState(agent=agent, T=self._T(a), state=a.state)

    def update(self, agent: str, decision: str, risk: dict, injection_cue: bool,
               events: Iterable[str] = ()) -> TrustState:
        """Record one decision for `agent` and return its new trust state.

        decision       the broker's decision for this message (ALLOW, SANITIZE,
                       HITL, DENY, QUARANTINE). Only ALLOW counts as clean in Ba;
                       HITL is neutral (not added to Ba), but a violation on the
                       same message (injection cue, events) still lowers Ca.
        risk           the action's risk vector (A1). Not used in the score for
                       now; its compound high flag is kept in the history.
        injection_cue  a cue from K4 (request) or F3 (reply).
        events         optional reason codes: INDIVIDUAL_DATA_REQUEST (V5, from
                       F3's minimum_necessary), BURST_DETECTED (V4, from
                       rules.py), REPLY_SANITIZED (F3), INJECTION_CUE.
        """
        if decision not in DECISIONS:
            raise ValueError(f"unknown decision {decision!r}")
        _check_risk(risk)
        events = tuple(events)
        unknown = set(events) - set(EVENTS)
        if unknown:
            raise ValueError(f"unknown event codes {sorted(unknown)}")

        a = self._agent(agent)
        T_before, state_before = self._T(a), a.state

        violations = [e for e in events if e != BURST_DETECTED]
        if injection_cue and INJECTION_CUE not in violations:
            violations.append(INJECTION_CUE)
        if decision == "DENY":
            violations.append("DENY")
        sev = self.s["severity"]
        severity = max((sev[v] for v in violations), default=0.0)   # count once

        if decision != "HITL":                      # HITL: neutral until a human decides
            a.window.append(decision == "ALLOW")
        if severity > 0:
            a.Ca *= math.exp(-self.s["lambda"] * severity)
        elif decision == "ALLOW":
            a.Ca += self.s["eta"] * (1.0 - a.Ca)

        if a.hold > 0:
            a.hold -= 1
        if BURST_DETECTED in events:
            a.hold = self.s["burst_hold_messages"]
        a.state = self._next_state(a)

        T_after = self._T(a)
        entered_quarantine = state_before != "Quarantined" and a.state == "Quarantined"
        a.history.append({
            "seq": len(a.history) + 1, "event": "update", "decision": decision,
            "violations": sorted(set(violations)), "events": list(events),
            "severity": severity, "compound_high": sum(1 for f in FACTORS if risk[f] == "H") >= 2,
            "T_before": T_before, "T_after": T_after,
            "state_before": state_before, "state_after": a.state,
        })
        if entered_quarantine:
            for listener in list(self._quarantine_listeners):
                listener(agent)
        return TrustState(agent=agent, T=T_after, state=a.state)

    def release(self, agent: str, reviewer: str) -> TrustState:
        """Authorised release (plan 5.1). The agent restarts in Restricted at
        release_T and earns its way up: Ca back to 1, and the window filled with
        non-ALLOW entries so that T is exactly release_T."""
        if not reviewer or not reviewer.strip():
            raise ValueError("release needs a reviewer name")
        a = self._agent(agent)
        T_before, state_before = self._T(a), a.state
        w = self.s["weights"]
        a.Ca = 1.0
        allow_share = (self.s["release_T"] - w["identity"] - w["context"]) / w["behaviour"]
        n = self.s["window"]
        allows = round(max(0.0, allow_share) * n)
        a.window = deque([True] * allows + [False] * (n - allows), maxlen=n)
        a.state = "Restricted"
        a.hold = 0
        T_after = self._T(a)
        a.history.append({
            "seq": len(a.history) + 1, "event": "release", "reviewer": reviewer,
            "T_before": T_before, "T_after": T_after,
            "state_before": state_before, "state_after": a.state,
        })
        return TrustState(agent=agent, T=T_after, state=a.state)

    # --- extras ------------------------------------------------------------

    def on_quarantine(self, listener: Callable[[str], None]) -> None:
        """Call `listener(agent)` once each time an update() moves an agent into
        Quarantined (not again while it stays there; again after a release).
        The defence manager (A3) uses it to log the quarantine (TRUST_QUARANTINED)."""
        if not callable(listener):
            raise ValueError("listener must be callable")
        self._quarantine_listeners.append(listener)

    def history(self, agent: str) -> list[dict]:
        """Every score change for `agent`, oldest first (plan 4.4). A copy."""
        return [dict(h) for h in self._agent(agent).history]

    # --- internals ---------------------------------------------------------

    def _agent(self, agent: str) -> _Agent:
        if not agent:
            raise ValueError("agent name is empty")
        if agent not in self._agents:
            n = self.s["window"]
            self._agents[agent] = _Agent(window=deque([True] * n, maxlen=n))
        return self._agents[agent]

    def _T(self, a: _Agent) -> float:
        w = self.s["weights"]
        Ba = sum(a.window) / len(a.window)
        return w["identity"] * 1.0 + w["behaviour"] * Ba + w["context"] * a.Ca

    def _band(self, T: float) -> State:
        b = self.s["bands"]
        if T >= b["active"] - _EPS:
            return "Active"
        if T >= b["suspicious"] - _EPS:
            return "Suspicious"
        if T >= b["restricted"] - _EPS:
            return "Restricted"
        return "Quarantined"

    def _next_state(self, a: _Agent) -> State:
        if a.state == "Quarantined":
            return "Quarantined"                    # only release() leaves it
        T = self._T(a)
        target = self._band(T)
        cur = _ORDER.index(a.state)
        new = _ORDER.index(target)
        if new < cur:                               # climbing: needs the margin
            edges = {"Active": "active", "Suspicious": "suspicious", "Restricted": "restricted"}
            new = cur
            for i in range(cur - 1, -1, -1):
                if T >= self.s["bands"][edges[_ORDER[i]]] + self.s["hysteresis"] - _EPS:
                    new = i
                else:
                    break
        if a.hold > 0:                              # V4 hold: no better than Suspicious
            new = max(new, _ORDER.index("Suspicious"))
        return _ORDER[new]


def _check_risk(risk: object) -> None:
    if not isinstance(risk, dict) or set(risk) != set(FACTORS) or any(v not in LEVELS for v in risk.values()):
        raise ValueError(f"risk must have the factors {FACTORS} with values {LEVELS}, got {risk!r}")
