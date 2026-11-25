"""Rule-based violation checks that belong to Amna's side (A-R2, docs/detection-design.md).

Only V4 lives here. V1 is A3 (broker/defence/quarantine.py); V2 is Kissa's
policy step; V3 comes from K4 and F3 as `injection_cue`; V5 comes from Afaq's
F3 `minimum_necessary`. The results go to TrustEngine.update(events=...).

Pure Python, in memory, deterministic.
"""

from collections import Counter

from broker.trust.trust import BURST_DETECTED, default_settings


class BurstDetector:
    """V4: more than `limit` requests from one agent within one task (trace_id).

    Limit: trace_id is set by the sender, so an agent that starts a new trace
    for every message is not seen here (docs/detection-design.md, section 1).
    """

    def __init__(self, limit: int | None = None):
        self.limit = limit if limit is not None else default_settings()["burst_limit_per_trace"]
        if self.limit < 1:
            raise ValueError("limit must be at least 1")
        self._counts: Counter = Counter()

    def observe(self, sender: str, trace_id: str) -> tuple[str, ...]:
        """Count one request; return (BURST_DETECTED,) when it is over the limit."""
        key = (sender, trace_id)
        self._counts[key] += 1
        return (BURST_DETECTED,) if self._counts[key] > self.limit else ()

    def forget(self, trace_id: str) -> None:
        """Drop the counts of a finished task."""
        for key in [k for k in self._counts if k[1] == trace_id]:
            del self._counts[key]
