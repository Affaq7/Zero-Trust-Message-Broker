"""Database agent (CrewAI): runs structured queries on the mock database.

The query itself is deterministic: the request's resource and payload go to
the mock services' /db endpoints (the LLM never writes SQL, M10). For reads,
a CrewAI task then writes a short summary for the requester; the reply holds
the rows as the database returned them plus that summary. Updates need no
LLM. Unknown actions and service errors become error replies.
"""

import json
import threading

from pydantic import BaseModel, Field

from agents.llm import LLMClient, LLMError, make_llm
from agents.mocks_client import MockServiceError, MocksClient
from contracts import Envelope
from contracts.payloads import ResponsePayload
from wrapper.runtime import current_runtime

READ_ACTIONS = {"db.query_aggregate": "/db/query_aggregate", "db.query_rows": "/db/query_rows"}
WRITE_ACTIONS = {"db.update_records": "/db/update_records"}
MAX_ROWS_IN_PROMPT = 20
MAX_ROWS_CHARS = 4000


class DbSummary(BaseModel):
    summary: str = Field(max_length=1000)


class DatabaseAgent:
    def __init__(self, llm: LLMClient, mocks: MocksClient):
        self.llm = llm
        self.mocks = mocks

    def handle(self, env: Envelope) -> ResponsePayload:
        try:
            if env.action in WRITE_ACTIONS:
                result = self.mocks.call(WRITE_ACTIONS[env.action], env.resource, env.payload, env.trace_id)
                return ResponsePayload(status="ok", result={
                    **result, "summary": f"Updated {result['rows_affected']} row(s)."})
            if env.action in READ_ACTIONS:
                result = self.mocks.call(READ_ACTIONS[env.action], env.resource, env.payload, env.trace_id)
                summary = self._summarise(env, result["rows"])
                return ResponsePayload(status="ok", result={"rows": result["rows"], "summary": summary})
        except (MockServiceError, LLMError) as exc:
            return ResponsePayload(status="error", error=str(exc)[:500])
        return ResponsePayload(status="error", error=f"database agent cannot perform {env.action!r}")

    def _summarise(self, env: Envelope, rows: list[dict]) -> str:
        from agents.crew_llm import run_crew_task  # imports CrewAI only when needed

        shown = json.dumps(rows[:MAX_ROWS_IN_PROMPT], ensure_ascii=False)[:MAX_ROWS_CHARS]
        draft = run_crew_task(
            self.llm, purpose="database.summarise",
            role="Database assistant",
            goal="Explain query results briefly and accurately to the agent that asked.",
            backstory="You answer data questions for Zephyr Corp's internal agents.",
            description=(
                f"Another agent ran {env.action} on {env.resource} with these parameters: "
                f"{json.dumps(env.payload, ensure_ascii=False)}.\n"
                f"The database returned {len(rows)} row(s). First rows:\n{shown}\n\n"
                "Write a short summary of the result for that agent."
            ),
            expected_output="A short summary of the query result.",
            schema=DbSummary,
        )
        return draft.summary


def preload() -> None:
    """Import CrewAI at process start-up so the first task does not pay for it."""
    import agents.crew_llm  # noqa: F401


_default: DatabaseAgent | None = None
_lock = threading.Lock()


def handle(env: Envelope) -> ResponsePayload:
    """Wrapper entry point: one DatabaseAgent per process, built from the environment."""
    global _default
    with _lock:
        if _default is None:
            _default = DatabaseAgent(make_llm(current_runtime().agent_name), MocksClient())
    return _default.handle(env)
