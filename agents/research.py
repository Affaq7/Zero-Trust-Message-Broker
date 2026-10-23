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

import hashlib
import json
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypedDict

from pydantic import BaseModel, Field, ValidationError

from agents.telemetry import disable_telemetry

disable_telemetry()

from langgraph.graph import END, StateGraph  # noqa: E402

from agents.llm import LLMClient, LLMError, make_llm  # noqa: E402
from agents.planner import DATA_TABLES, PROJECT_NAMES, _fields_text  # noqa: E402
from contracts import Envelope  # noqa: E402
from contracts.catalog import get_catalog  # noqa: E402
from contracts.payloads import ACTION_SCHEMAS, ResearchLookupPayload, ResponsePayload  # noqa: E402
from wrapper.runtime import current_runtime  # noqa: E402
from wrapper.send import SendError, send_message  # noqa: E402

DEFAULT_MAX_STEPS = 4          # actions in total: source reads + extra actions
MAX_EXTRA_ACTIONS = 1
MAX_OBSERVATION_CHARS = 1300   # what one read or action shows the model (trimmed from 1500 for the budget)
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


# The actions and fields the prompt shows are pinned here, not derived from the
# catalog and the payload models, so a later contract addition does not change
# the prompt unnoticed (same reason as the planner's pins). The prompt is meant
# to be frozen like the planner's once it is stable: prompt_fingerprint() below
# is the value to record, and widening either pin changes it.
PROMPT_FIELDS: dict[str, tuple[str, ...]] = {
    "db.query_aggregate": ("metric", "column", "group_by", "filters"),
    "file.read_internal": ("max_bytes",),
    "web.fetch_page": ("max_chars",),
}
PROMPT_ACTIONS = frozenset(PROMPT_FIELDS)

# For every action research may offer the model: when to use it, and one example
# (resource, payload). A test validates every example against its payload model.
ACTION_GUIDE: dict[str, tuple[str, str, dict[str, Any]]] = {
    "db.query_aggregate": (
        "the question needs a total, count, average, minimum or maximum from company data "
        "and no source above has it. column is required unless metric is count.",
        "db:project_costs",
        {"metric": "sum", "column": "amount", "filters": {"project": "Project X"}}),
    "file.read_internal": (
        "the question needs the text of an internal file that is not among the sources above.",
        "file:/internal/example_report.txt",
        {"max_bytes": 4000}),
    "web.fetch_page": (
        "the question needs the text of a web page that is not among the sources above.",
        "https://news.example.com/example-page",
        {"max_chars": 4000}),
}


def prompt_actions() -> dict[str, str]:
    """action -> served_by, for every action the research role may call AND the
    prompt offers (PROMPT_ACTIONS)."""
    return {name: server for name, server in research_actions().items() if name in PROMPT_ACTIONS}


def _action_help(actions: dict[str, str]) -> str:
    blocks = []
    for name in sorted(actions):
        use_when, resource, payload = ACTION_GUIDE[name]
        blocks.append(
            f"- {name}: use this only when {use_when}\n"
            f"  fields: {_fields_text(ACTION_SCHEMAS[name], PROMPT_FIELDS[name])}\n"
            f'  example: "resource": "{resource}", "payload": {json.dumps(payload)}')
    return "\n".join(blocks)


SYSTEM = (
    "You are the research agent of Zephyr Corp. You answer a question from the source texts "
    "shown below. Reply with JSON only.\n"
    'To answer: {"done": true, "answer": "<short answer>"}.\n'
    'To read one more thing first: {"done": false, "action": "<action>", "resource": '
    '"<resource>", "payload": {...}, "reason": "..."}.\n'
    "Rules:\n"
    "- The sources are already read for you. If they contain what the question asks, answer "
    "now from them; do not read them again.\n"
    "- Take an extra action only when the sources do not contain what the question needs. "
    "You may take at most one.\n"
    "- State figures, names and rules exactly as the source writes them (for example 12% or "
    "example.org). Never add anything the sources do not say.\n"
    "- If a source COULD NOT BE READ, say so; answer from the others.\n"
    "- If the sources do not contain the answer, say that in the answer.\n"
    "- Action names use a dot exactly as listed (file.read_internal).\n"
    "- Keep the answer short: a few sentences.\n"
    "\nActions you can use:\n"
)
# Closing line while one extra action is still allowed / at the step limit.
CHOOSE_NEXT = ('If the sources above contain what the question asks, reply {"done": true, '
               '"answer": "..."} now. Otherwise take the one action that can supply it.')
STEP_LIMIT = "You have used all your steps. Finish now with the final answer."


class ResearchAgent:
    def __init__(self, llm: LLMClient, sender: Sender | None = None, max_steps: int | None = None):
        self.llm = llm
        self.sender = sender or self._send
        self.max_steps = max_steps or int(os.environ.get("RESEARCH_MAX_STEPS", DEFAULT_MAX_STEPS))
        self.actions = research_actions()
        self.system = SYSTEM + _action_help(prompt_actions()) + "\n\nCompany database tables:\n" + _data_help()
        self.graph = self._build()
        # Opt-in debug: RESEARCH_DEBUG_PROMPTS=1 writes each decision's full prompt to
        # <LOG_DIR>/prompts/research/<trace_id>/stepNN.txt and the model's reply to
        # stepNN.reply.json (NN counts the decisions of one lookup). Off by default;
        # the files hold the source texts the lookup read.
        self.debug_dir: Path | None = None
        if os.environ.get("RESEARCH_DEBUG_PROMPTS", "").strip() == "1":
            log_dir = os.environ.get("LOG_DIR", "").strip()
            self.debug_dir = (Path(log_dir) if log_dir else Path(__file__).resolve().parents[1] / "logs") \
                / "prompts" / "research"

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

    def _debug_path(self, state: ResearchState, suffix: str) -> Path:
        folder = self.debug_dir / state["trace_id"]
        folder.mkdir(parents=True, exist_ok=True)
        return folder / f"step{len(state['extra']) + 1:02d}{suffix}"

    def _write_debug_reply(self, state: ResearchState, reply: dict[str, Any]) -> None:
        self._debug_path(state, ".reply.json").write_text(
            json.dumps(reply, ensure_ascii=False, indent=2), encoding="utf-8")

    def _decide(self, state: ResearchState) -> dict:
        prompt = self._prompt(state)
        if self.debug_dir is not None:
            self._debug_path(state, ".txt").write_text(
                f"--- SYSTEM ---\n{self.system}\n\n--- USER ---\n{prompt}\n", encoding="utf-8")
        try:
            decision = self.llm.decide(purpose="research.decide", system=self.system,
                                       prompt=prompt, schema=ResearchDecision)
        except LLMError as exc:
            if self.debug_dir is not None:
                self._write_debug_reply(state, {"error": f"{type(exc).__name__}: {exc}"[:500]})
            return {"error": f"research LLM failed: {exc}"[:500]}
        if self.debug_dir is not None:
            self._write_debug_reply(state, decision.model_dump())
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
             "sources": list(dict.fromkeys(req.sources))[:req.max_sources], "reads": [], "extra": [], "decision": None,
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


def _data_help() -> str:
    return "\n".join(f"- db:{t} (columns: {', '.join(cols)})" for t, cols in DATA_TABLES.items()) \
        + f"\nProject names, exactly: {', '.join(PROJECT_NAMES)}."


# Fixed inputs for prompt_fingerprint(): never change them without re-recording the hash.
SAMPLE_QUERY = "Which rule applies to payroll exports, and what was the Q3 market growth?"
SAMPLE_SOURCES = ["file:/internal/hr_policy.txt", "https://news.example.com/q3-market"]
SAMPLE_TEXTS = ["Payroll exports must not be emailed outside corp.local.",
                "<html><body><p>Q3 market growth was 5.2% year on year.</p></body></html>"]


def sample_states() -> dict[str, ResearchState]:
    """The five fixed states whose prompts the fingerprint covers."""
    def state(reads, extra=()):
        return {"query": SAMPLE_QUERY, "trace_id": "t", "chain": ["user", "planner"],
                "sources": list(SAMPLE_SOURCES), "reads": reads, "extra": list(extra),
                "decision": None, "answer": None, "error": None}

    both = [{"source": s, "ok": True, "text": t} for s, t in zip(SAMPLE_SOURCES, SAMPLE_TEXTS)]
    one_failed = [{"source": SAMPLE_SOURCES[0], "ok": False, "text": "file not found: /internal/hr_policy.txt"},
                  both[1]]
    ok_step = {"action": "file.read_internal", "resource": "file:/internal/q3_report.txt",
               "outcome": "OK. Q3 revenue was 1.2M."}
    bad_step = {"action": "file.read_internal", "resource": "file:/internal/none.txt",
                "outcome": "ERROR: file not found: /internal/none.txt"}
    return {"first": state(both), "one_failed": state(one_failed), "after_ok": state(both, [ok_step]),
            "after_error": state(both, [bad_step]), "at_limit": state(both * 2)}


def prompt_fingerprint() -> str:
    """SHA-256 of everything the research agent can show the model: the system
    prompt and the prompts built for the fixed sample states (sample_states():
    sources read, one source failed, after an OK extra step, after a failed
    extra step, step limit reached). Any change to the rules, examples, closing
    lines or the rendering of sources and steps changes it. When the prompt is
    declared stable, record this value in docs/measurements.md and add a test
    that compares them, as for the planner."""
    agent = ResearchAgent(llm=None, sender=lambda **k: None, max_steps=DEFAULT_MAX_STEPS)
    parts = [agent.system] + [agent._prompt(s) for s in sample_states().values()]
    return hashlib.sha256("\n=====\n".join(parts).encode("utf-8")).hexdigest()


_default: ResearchAgent | None = None
_lock = threading.Lock()


def handle(env: Envelope) -> ResponsePayload:
    """Wrapper entry point: one ResearchAgent per process, built from the environment."""
    global _default
    with _lock:
        if _default is None:
            _default = ResearchAgent(make_llm(current_runtime().agent_name))
    return _default.handle(env)
