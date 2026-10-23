"""Research agent (LangGraph): answers a question from the sources it is given.

Serves research.lookup (called by the planner). The planner names the sources
(file:/... or http(s) URLs); the research agent does not search. It reads up
to max_sources of them through the tool agent (file.read_internal or
web.fetch_page; deterministic, no LLM), then makes ONE LLM call that answers
from what it read. The model may instead ask for one extra action (at most
RESEARCH_MAX_STEPS actions in total, default 4) and then answers.

The planner waits for this reply for at most one send_message() hop (60 s),
so the work is kept to reads plus one LLM call in the normal case.

Graph: read_sources -> decide -> (act -> decide)* -> end.

The research agent applies no policy of its own: it reads whatever source the
planner names and returns whatever the model answers. The catalog says which
actions the research role may call; the broker enforces that, not this code.
"""

import json
import os
import threading
from collections.abc import Callable
from typing import Any, TypedDict

from pydantic import BaseModel, Field, ValidationError

from agents.telemetry import disable_telemetry

disable_telemetry()

from langgraph.graph import END, StateGraph  # noqa: E402

from agents.llm import LLMClient, LLMError, make_llm  # noqa: E402
from contracts import Envelope  # noqa: E402
from contracts.catalog import get_catalog  # noqa: E402
from contracts.payloads import ResearchLookupPayload, ResponsePayload  # noqa: E402
from wrapper.runtime import current_runtime  # noqa: E402
from wrapper.send import SendError, send_message  # noqa: E402

DEFAULT_MAX_STEPS = 4          # actions in total: source reads + extra actions
MAX_EXTRA_ACTIONS = 1
MAX_OBSERVATION_CHARS = 1500   # what one read or action shows the model
MAX_ANSWER_CHARS = 500
READ_MAX_BYTES = 4000
READ_MAX_CHARS = 4000
TOOL = "tool"
LOOKUP_ACTION = "research.lookup"
FILE_ACTION = "file.read_internal"
WEB_ACTION = "web.fetch_page"

Sender = Callable[..., Envelope]


class ResearchDecision(BaseModel):
    done: bool
    answer: str | None = None
    action: str | None = None
    resource: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=500)


class ResearchState(TypedDict):
    query: str
    trace_id: str
    chain: list[str]
    sources: list[str]
    reads: list[dict[str, Any]]      # {"source", "ok", "text"}
    extra: list[dict[str, Any]]      # {"action", "resource", "outcome"}
    decision: ResearchDecision | None
    answer: str | None
    error: str | None


def research_actions() -> dict[str, str]:
    """action -> served_by, for every action the research role may call (catalog),
    except those served by the planner: research never calls back into the
    agent that is waiting for its reply (planner.request is not built)."""
    catalog = get_catalog()
    return {a.name: a.served_by for a in catalog.actions
            if catalog.is_allowed("research", a.name) and a.served_by and a.served_by != "planner"}


def read_request(source: str) -> tuple[str, str, dict[str, Any]] | None:
    """(action, resource, payload) that reads a source, or None if it is neither
    a file: nor an http(s) source."""
    if source.startswith("file:"):
        return FILE_ACTION, source, {"max_bytes": READ_MAX_BYTES}
    if source.lower().startswith(("http://", "https://")):
        return WEB_ACTION, source, {"max_chars": READ_MAX_CHARS}
    return None


def render_result(result: Any) -> str:
    """One successful reply as the model sees it: the text of a file or page as
    returned (HTML stays raw), anything else as JSON; cut to MAX_OBSERVATION_CHARS."""
    if isinstance(result, dict) and isinstance(result.get("content"), str):
        text = result["content"]
    else:
        text = json.dumps(result, ensure_ascii=False)
    return text[:MAX_OBSERVATION_CHARS]


SYSTEM = (
    "You are the research agent of Zephyr Corp. You answer a question using only the "
    "source texts you are shown. Reply with JSON only.\n"
    'To answer: {"done": true, "answer": "<short answer that includes the figures or '
    'statements you found>"}.\n'
    "If the sources do not contain the answer, say so in the answer."
)
CHOOSE_NEXT = 'Answer the question from the sources above: {"done": true, "answer": "..."}.'
STEP_LIMIT = "You have used all your steps. Answer now from the sources above."


class ResearchAgent:
    def __init__(self, llm: LLMClient, sender: Sender | None = None, max_steps: int | None = None):
        self.llm = llm
        self.sender = sender or self._send
        self.max_steps = max_steps or int(os.environ.get("RESEARCH_MAX_STEPS", DEFAULT_MAX_STEPS))
        self.actions = research_actions()
        self.system = SYSTEM
        self.graph = self._build()

    # --- graph -----------------------------------------------------------------

    def _build(self):
        g = StateGraph(ResearchState)
        g.add_node("read_sources", self._read_sources)
        g.add_node("decide", self._decide)
        g.add_node("act", self._act)
        g.set_entry_point("read_sources")
        g.add_conditional_edges("read_sources", self._route, {"act": "decide", "end": END})
        g.add_conditional_edges("decide", self._route, {"act": "act", "end": END})
        g.add_edge("act", "decide")
        return g.compile()

    @staticmethod
    def _route(state: ResearchState) -> str:
        if state["answer"] is not None or state["error"] is not None:
            return "end"
        return "act"

    def _steps(self, state: ResearchState) -> int:
        return len(state["reads"]) + len(state["extra"])

    def _may_act(self, state: ResearchState) -> bool:
        return len(state["extra"]) < MAX_EXTRA_ACTIONS and self._steps(state) < self.max_steps

    def _send_step(self, state: ResearchState, action: str, resource: str,
                   payload: dict[str, Any]) -> tuple[bool, str]:
        """Send one action; (ok, text). Text is the observation or the error."""
        receiver = self.actions.get(action)
        if receiver is None:
            return False, f"{action!r} is not an available action"
        try:
            reply = self.sender(receiver=receiver, action=action, resource=resource, payload=payload,
                                chain_so_far=state["chain"], trace_id=state["trace_id"])
        except (SendError, ValueError) as exc:
            return False, str(exc)[:MAX_OBSERVATION_CHARS]
        if reply.payload.get("status") != "ok":
            return False, str(reply.payload.get("error") or "the request failed")[:MAX_OBSERVATION_CHARS]
        return True, render_result(reply.payload.get("result"))

    def _read_sources(self, state: ResearchState) -> dict:
        reads = []
        for source in state["sources"]:
            request = read_request(source)
            if request is None:
                reads.append({"source": source, "ok": False,
                              "text": "unsupported source (use file:/... or an http(s) URL)"})
                continue
            ok, text = self._send_step(state, *request)
            reads.append({"source": source, "ok": ok, "text": text})
        if not any(r["ok"] for r in reads):
            failures = "; ".join(f"{r['source']}: {r['text']}" for r in reads)
            return {"reads": reads, "error": f"no source could be read ({failures})"[:500]}
        return {"reads": reads}

    def _prompt(self, state: ResearchState) -> str:
        parts = [f"Question: {state['query']}"]
        for i, r in enumerate(state["reads"], start=1):
            body = r["text"] if r["ok"] else f"COULD NOT BE READ: {r['text']}"
            parts.append(f"Source {i} ({r['source']}):\n{body}")
        for e in state["extra"]:
            parts.append(f"Extra step: {e['action']} on {e['resource']} -> {e['outcome']}")
        parts.append(CHOOSE_NEXT if self._may_act(state) else STEP_LIMIT)
        return "\n".join(parts)

    def _decide(self, state: ResearchState) -> dict:
        try:
            decision = self.llm.decide(purpose="research.decide", system=self.system,
                                       prompt=self._prompt(state), schema=ResearchDecision)
        except LLMError as exc:
            return {"error": f"research LLM failed: {exc}"[:500]}
        if decision.done:
            return {"answer": (decision.answer or "")[:MAX_ANSWER_CHARS], "decision": decision}
        if not self._may_act(state):
            return {"error": "no answer within the step limit"}
        return {"decision": decision}

    def _act(self, state: ResearchState) -> dict:
        d = state["decision"]
        action, resource = d.action or "", d.resource or ""
        if not resource:
            outcome = f"ERROR: {action!r} needs a resource"
        else:
            ok, text = self._send_step(state, action, resource, d.payload)
            outcome = f"OK. {text}" if ok else f"ERROR: {text}"
        return {"extra": [*state["extra"], {"action": action, "resource": resource, "outcome": outcome}]}

    # --- entry point -------------------------------------------------------------

    def lookup(self, env: Envelope) -> ResponsePayload:
        try:
            req = ResearchLookupPayload.model_validate(env.payload)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first["loc"]) or "payload"
            return ResponsePayload(status="error", error=f"invalid {LOOKUP_ACTION} payload: {where}: {first['msg']}"[:500])
        if not req.sources:
            return ResponsePayload(status="error",
                                   error=f"{LOOKUP_ACTION} needs at least one source; none were given")
        state = self.graph.invoke(
            {"query": req.query, "trace_id": env.trace_id, "chain": list(env.delegation_chain),
             "sources": req.sources[:req.max_sources], "reads": [], "extra": [], "decision": None,
             "answer": None, "error": None},
            {"recursion_limit": 2 * self.max_steps + 6},
        )
        if state["error"] is not None:
            return ResponsePayload(status="error", error=state["error"])
        return ResponsePayload(status="ok", result={
            "answer": state["answer"],
            "sources_read": [r["source"] for r in state["reads"] if r["ok"]],
            "sources_failed": [r["source"] for r in state["reads"] if not r["ok"]],
        })

    def handle(self, env: Envelope) -> ResponsePayload:
        if env.action != LOOKUP_ACTION:
            return ResponsePayload(status="error", error=f"research agent cannot perform {env.action!r}")
        return self.lookup(env)

    @staticmethod
    def _send(**kwargs) -> Envelope:
        rt = current_runtime()
        return send_message(token=rt.token_for(kwargs["receiver"]), **kwargs)


_default: ResearchAgent | None = None
_lock = threading.Lock()


def handle(env: Envelope) -> ResponsePayload:
    """Wrapper entry point: one ResearchAgent per process, built from the environment."""
    global _default
    with _lock:
        if _default is None:
            _default = ResearchAgent(make_llm(current_runtime().agent_name))
    return _default.handle(env)
