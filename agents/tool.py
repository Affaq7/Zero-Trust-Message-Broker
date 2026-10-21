"""Tool agent (CrewAI): carries out file, web, email and admin actions.

Each action goes to the mock services. Only email uses the LLM: a CrewAI
task finalises the subject and body (the recipients always come from the
request, never from the model). Unknown actions get an error reply; that
is a capability limit, not a policy check (direct mode has no policy).
"""

import logging
import threading

from pydantic import BaseModel, Field

from agents.llm import LLMClient, LLMError, make_llm
from agents.mocks_client import MockServiceError, MocksClient
from contracts import Envelope
from contracts.payloads import ResponsePayload
from wrapper.runtime import current_runtime

log = logging.getLogger(__name__)

# action -> mock-services path (A5: admin.change_policy goes to the mock admin handler)
MOCK_PATHS = {
    "file.read_internal": "/files/read",
    "file.delete": "/files/delete",
    "web.fetch_page": "/web/fetch",
    "tool.send_email_internal": "/mail/send",
    "tool.send_email_external": "/mail/send",
    "admin.change_policy": "/admin/policy",
}
EMAIL_ACTIONS = {"tool.send_email_internal", "tool.send_email_external"}


class EmailDraft(BaseModel):
    subject: str = Field(max_length=200)
    body: str = Field(max_length=20000)


class ToolAgent:
    def __init__(self, llm: LLMClient, mocks: MocksClient):
        self.llm = llm
        self.mocks = mocks

    def handle(self, env: Envelope) -> ResponsePayload:
        path = MOCK_PATHS.get(env.action)
        if path is None:
            return ResponsePayload(status="error", error=f"tool agent cannot perform {env.action!r}")
        payload = dict(env.payload)
        try:
            if env.action in EMAIL_ACTIONS:
                payload = self._finalise_email(payload)
            result = self.mocks.call(path, env.resource, payload, env.trace_id)
        except (MockServiceError, LLMError) as exc:
            return ResponsePayload(status="error", error=str(exc)[:500])
        return ResponsePayload(status="ok", result=result)

    def _finalise_email(self, payload: dict) -> dict:
        from agents.crew_llm import run_crew_task  # imports CrewAI only when needed

        draft = run_crew_task(
            self.llm, purpose="tool.compose_email",
            role="Email assistant",
            goal="Prepare the requested email so it is clear and ready to send.",
            backstory="You work for Zephyr Corp and send emails on request of other agents.",
            description=(
                "Prepare this email for sending. Keep every fact, figure and name from the "
                "request. Do not add recipients.\n\n"
                f"Recipients: {', '.join(map(str, payload.get('to', [])))}\n"
                f"Requested subject: {payload.get('subject', '')}\n"
                f"Requested body:\n{payload.get('body', '')}"
            ),
            expected_output="The final subject and body.",
            schema=EmailDraft,
        )
        return {**payload, "subject": draft.subject, "body": draft.body}


_default: ToolAgent | None = None
_lock = threading.Lock()


def handle(env: Envelope) -> ResponsePayload:
    """Wrapper entry point: one ToolAgent per process, built from the environment."""
    global _default
    with _lock:
        if _default is None:
            _default = ToolAgent(make_llm(current_runtime().agent_name), MocksClient())
    return _default.handle(env)
