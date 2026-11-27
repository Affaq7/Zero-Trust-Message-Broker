"""Quarantine (task A3, Amna). Pipeline step 3, and rule V1.

DefenceManager keeps, per agent, the times of its recent DENY decisions. When
`deny_limit` denials (5) fall within `window_seconds` (60 s), the agent is
quarantined (V1, docs/detection-design.md; scenario A9): every later message
gets decision QUARANTINE with reason AGENT_QUARANTINED, and nothing is
forwarded. The trigger itself is logged as DENIAL_RATE_EXCEEDED.

An agent is also blocked when the trust engine (A2) has it in Quarantined.
That quarantine is logged too, once, when the score enters Quarantined, with
reason TRUST_QUARANTINED (the trust engine's on_quarantine hook; it covers a
responder whose replies keep being cut, which never sends a request itself).
release() is the only way out: it needs an allowed reviewer, clears the V1
block, calls TrustEngine.release (restart in Restricted at 0.50) and logs who
released it and when.

Only denials where identity was verified count: the pipeline calls
record_decision only after step 2 passes, and a call with no agent (an identity
failure has agent=None) is ignored, so forged messages cannot quarantine the
real agent.

Pure Python, in memory, deterministic: the caller passes the broker's clock as
`ts` (seconds). Interface fixed on 25 Nov (context file, section 7).
"""

from collections import deque
from functools import lru_cache
from pathlib import Path

import yaml

from broker.trust.trust import TrustEngine

SETTINGS_PATH = Path(__file__).with_name("defence_settings.yaml")

AGENT_QUARANTINED = "AGENT_QUARANTINED"
DENIAL_RATE_EXCEEDED = "DENIAL_RATE_EXCEEDED"
TRUST_QUARANTINED = "TRUST_QUARANTINED"


def load_settings(path: Path = SETTINGS_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        s = yaml.safe_load(f)
    if not (isinstance(s.get("deny_limit"), int) and s["deny_limit"] >= 1):
        raise ValueError("deny_limit must be a whole number of at least 1")
    if not (isinstance(s.get("window_seconds"), (int, float)) and s["window_seconds"] > 0):
        raise ValueError("window_seconds must be a positive number")
    reviewers = s.get("reviewers")
    if not (isinstance(reviewers, list) and reviewers and all(isinstance(r, str) and r for r in reviewers)):
        raise ValueError("reviewers must be a non-empty list of names")
    return s


@lru_cache(maxsize=1)
def default_settings() -> dict:
    return load_settings()


class DefenceManager:
    """V1 sliding window, the step 3 block, and authorised release."""

    def __init__(self, trust: TrustEngine | None = None, settings: dict | None = None):
        self.s = settings if settings is not None else default_settings()
        self.trust = trust
        self._denials: dict[str, deque] = {}
        self._blocked: set[str] = set()
        self._log: list[dict] = []
        hook = getattr(trust, "on_quarantine", None)
        if callable(hook):                      # the real engine; a stub may not have it
            hook(self._trust_quarantined)

    # --- interface (section 7) ---------------------------------------------

    def record_decision(self, agent: str, decision: str, ts: float) -> None:
        """Record one decision for a verified agent. Only DENY counts for V1.
        An agent that is already quarantined (by V1 or by its trust score) is not
        counted, so one quarantine gets one log line."""
        if not agent or decision != "DENY" or self.is_blocked(agent):
            return
        window = self._denials.setdefault(agent, deque())
        window.append(ts)
        while window and ts - window[0] > self.s["window_seconds"]:
            window.popleft()
        if len(window) >= self.s["deny_limit"]:
            self._blocked.add(agent)
            self._log.append({"kind": "quarantine", "agent": agent, "by": "broker",
                              "reason_code": DENIAL_RATE_EXCEEDED, "ts": ts, "denials": list(window)})
            window.clear()

    def is_blocked(self, agent: str) -> bool:
        """True when the agent is quarantined, by V1 or by its trust score (A2)."""
        if not agent:
            return False
        if agent in self._blocked:
            return True
        return self.trust is not None and self.trust.get(agent).state == "Quarantined"

    def release(self, agent: str, reviewer: str, ts: float | None = None) -> None:
        """Authorised release (plan 5.1). Raises PermissionError for a reviewer
        who is not allowed, ValueError for an agent that is not quarantined.
        Logs the reviewer and time."""
        if reviewer not in self.s["reviewers"]:
            raise PermissionError(f"reviewer {reviewer!r} may not release agents")
        if not agent:
            raise ValueError("agent name is empty")
        if not self.is_blocked(agent):
            raise ValueError(f"{agent!r} is not quarantined")
        self._blocked.discard(agent)
        self._denials.pop(agent, None)
        if self.trust is not None:
            self.trust.release(agent, reviewer)
        self._log.append({"kind": "release", "agent": agent, "by": reviewer, "ts": ts})

    # --- extras ------------------------------------------------------------

    def _trust_quarantined(self, agent: str) -> None:
        """The trust engine moved `agent` into Quarantined: log it once. An agent
        already blocked by V1 has its quarantine line already. The engine has no
        clock, so ts is None; the pipeline stamps the time when it audits the line."""
        if not agent or agent in self._blocked:
            return
        self._log.append({"kind": "quarantine", "agent": agent, "by": "broker",
                          "reason_code": TRUST_QUARANTINED, "ts": None, "denials": None})

    def check(self, agent: str) -> tuple[str, str] | None:
        """Step 3: ("QUARANTINE", "AGENT_QUARANTINED") for a blocked agent, else None."""
        return ("QUARANTINE", AGENT_QUARANTINED) if self.is_blocked(agent) else None

    def log(self) -> list[dict]:
        """Quarantine and release events, oldest first. A copy. Each entry uses the
        A4 audit field names (kind, agent, by, reason_code, ts, denials), so it can
        be passed to broker.audit.log.append() as it is."""
        return [dict(e) for e in self._log]
