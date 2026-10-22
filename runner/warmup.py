"""Warm-up before live runs, so no measured task includes model loading.

With --llm ollama the runner makes one tiny call to the model before the
first scenario that runs, and again before a later scenario when more than
IDLE_LIMIT_S have passed since the last LLM call (Ollama may have unloaded
the model). Agents and the runner share one Ollama server, so loading the
model once serves every agent. Warm-ups are recorded in run_meta.json
("warmups") and logged under <run>/warmup_llm/ without a trace_id, so they
are never counted in any task's results. Fake-LLM runs skip them.
"""

import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from agents.llm import LLMClient, LLMError, LLMSettings, OllamaLLM

IDLE_LIMIT_S = 240   # 4 minutes


class WarmupReply(BaseModel):
    ok: bool


class WarmupFailed(RuntimeError):
    pass


def warm_up_call(llm: LLMClient) -> float:
    """One tiny JSON call; returns its wall-clock duration in seconds."""
    started = time.perf_counter()
    llm.decide(purpose="runner.warmup", system="Reply with JSON only.",
               prompt='Reply with {"ok": true}.', schema=WarmupReply)
    return time.perf_counter() - started


def make_warmup_client(settings: LLMSettings, log_dir: Path) -> LLMClient:
    return OllamaLLM(settings, "warmup", log_dir)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


class Warmup:
    """Decides when to warm up and records each warm-up (only for the live LLM)."""

    def __init__(self, backend: str, call: Callable[[], float] | None,
                 clock: Callable[[], float] = time.time, idle_limit_s: float = IDLE_LIMIT_S):
        self.enabled = backend == "ollama"
        self.call = call
        self.clock = clock
        self.idle_limit_s = idle_limit_s
        self.last_llm_activity: float | None = None
        self.records: list[dict] = []

    def before_scenario(self, scenario_id: str) -> dict | None:
        """Warm up if needed; returns the record, or None if no warm-up was needed."""
        if not self.enabled:
            return None
        now = self.clock()
        if self.last_llm_activity is not None and now - self.last_llm_activity <= self.idle_limit_s:
            return None
        reason = ("first scenario of this run" if self.last_llm_activity is None
                  else f"{now - self.last_llm_activity:.0f} s since the last LLM call")
        record = {"at": _iso(now), "before_scenario": scenario_id, "reason": reason}
        try:
            record.update(duration_s=round(self.call(), 1), ok=True)
        except LLMError as exc:
            record.update(duration_s=None, ok=False, error=f"{type(exc).__name__}: {exc}"[:300])
            self.records.append(record)
            raise WarmupFailed(record["error"]) from None
        self.records.append(record)
        self.last_llm_activity = self.clock()
        return record

    def note_repetition(self, outcomes) -> None:
        """Remember the time of the last LLM call made during a repetition."""
        times = [_epoch(c["logged_at"]) for o in outcomes for c in o.llm_calls]
        self.last_llm_activity = max(times) if times else self.clock()
