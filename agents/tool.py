"""Tool agent (CrewAI): carries out file, web, email and admin actions.

Files, web pages and policy changes go to the mock services. Email goes to
the mailer agent as a mail.deliver message (send_message()); the tool never
calls the mail sink itself, so the delivery step is a message a broker can
see. Only email uses the LLM: a CrewAI task finalises the subject and body
(the recipients always come from the request, never from the model). Unknown
actions get an error reply; that is a capability limit, not a policy check
(direct mode has no policy).

The mail.deliver message carries only to, cc, bcc, subject and body. Fields
that belong to the request itself (for example a justification) stay here.
"""

import logging
import threading
from collections.abc import Callable

from pydantic import BaseModel, Field

from agents.llm import LLMClient, LLMError, make_llm
from agents.mocks_client import MockServiceError, MocksClient
from contracts import Envelope
from contracts.envelope import EnvelopeRuleError
from contracts.payloads import ResponsePayload, normalize_address
from wrapper.runtime import current_runtime
from wrapper.send import SendError, send_message

log = logging.getLogger(__name__)

# action -> mock-services path (A5: admin.change_policy goes to the mock admin handler)
MOCK_PATHS = {
    "file.read_internal": "/files/read",
    "file.delete": "/files/delete",
    "web.fetch_page": "/web/fetch",
    "admin.change_policy": "/admin/policy",
}
EMAIL_ACTIONS = {"tool.send_email_internal", "tool.send_email_external"}
MAILER = "mailer"
MAIL_DELIVER = "mail.deliver"
MAIL_RESOURCE = "mail:outbound"

Sender = Callable[..., Envelope]


def _addresses(value):
    """Normalise a recipient list with the contract's helper (strip, lowercase).
    Anything that is not a list of text is passed on untouched, so the
    receiving side refuses it and names the field."""
    if not isinstance(value, list):
        return value
    return [normalize_address(a) if isinstance(a, str) else a for a in value]


class EmailDraft(BaseModel):
    subject: str = Field(max_length=200)
    body: str = Field(max_length=20000)


class ToolAgent:
    def __init__(self, llm: LLMClient, mocks: MocksClient, sender: Sender | None = None):
        self.llm = llm
        self.mocks = mocks
        self.sender = sender or self._send

    def handle(self, env: Envelope) -> ResponsePayload:
        if env.action in EMAIL_ACTIONS:
            return self._send_email(env)
        path = MOCK_PATHS.get(env.action)
        if path is None:
            return ResponsePayload(status="error", error=f"tool agent cannot perform {env.action!r}")
        try:
            result = self.mocks.call(path, env.resource, dict(env.payload), env.trace_id)
        except (MockServiceError, LLMError) as exc:
            return ResponsePayload(status="error", error=str(exc)[:500])
        return ResponsePayload(status="ok", result=result)

    # --- email: draft with the LLM, deliver through the mailer ------------------

    def _send_email(self, env: Envelope) -> ResponsePayload:
        try:
            draft = self._finalise_email(dict(env.payload))
            # Always state all three recipient lists, so the message is the complete
            # final delivery; a missing "to"/subject/body is left missing for the sink to refuse.
            deliver = {k: draft[k] for k in ("subject", "body") if k in draft}
            if "to" in draft:
                deliver["to"] = _addresses(draft["to"])
            deliver["cc"] = _addresses(draft.get("cc", []))
            deliver["bcc"] = _addresses(draft.get("bcc", []))
            reply = self.sender(receiver=MAILER, action=MAIL_DELIVER, resource=MAIL_RESOURCE,
                                payload=deliver, chain_so_far=list(env.delegation_chain),
                                trace_id=env.trace_id)
        except LLMError as exc:
            return ResponsePayload(status="error", error=str(exc)[:500])
        except EnvelopeRuleError as exc:
            return ResponsePayload(status="error", error=f"cannot send {MAIL_DELIVER}: {exc}"[:500])
        except SendError as exc:
            return ResponsePayload(status="error", error=f"mailer: {exc}"[:500])
        answer = reply.payload
        if answer.get("status") != "ok":
            return ResponsePayload(status="error", error=str(answer.get("error") or "mailer failed")[:500])
        return ResponsePayload(status="ok", result=answer.get("result"))

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

    @staticmethod
    def _send(**kwargs) -> Envelope:
        rt = current_runtime()
        return send_message(token=rt.token_for(kwargs["receiver"]), **kwargs)


def preload() -> None:
    """Import CrewAI at process start-up so the first task does not pay for it."""
    import agents.crew_llm  # noqa: F401


_default: ToolAgent | None = None
_lock = threading.Lock()


def handle(env: Envelope) -> ResponsePayload:
    """Wrapper entry point: one ToolAgent per process, built from the environment."""
    global _default
    with _lock:
        if _default is None:
            _default = ToolAgent(make_llm(current_runtime().agent_name), MocksClient())
    return _default.handle(env)
