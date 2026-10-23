"""Mailer agent: serves mail.deliver, deterministic, no LLM.

The tool agent sends a mail.deliver envelope here instead of calling the mock
mail sink. The mailer is the only thing that calls the sink (POST /mail/send,
resource "mail:outbound"). It does exactly two things:

1. It accepts mail.deliver only from the senders the catalog allows for it
   (today: the tool agent). Any other sender, and any other action, gets an
   error reply and nothing reaches the sink.
2. It passes the envelope's resource and payload to the sink unchanged. The
   sink validates them (mail.deliver schema, recipients normalised), delivers
   to every address in to, cc and bcc, and records the attempt: delivered or
   failed, with the recipients. The sink never knows the intended recipients;
   the scenario file does.

Limits, stated plainly: the sender check reads the envelope's ``sender``
field. In direct mode nothing verifies that field (tokens are not checked),
so an impostor that sends as "tool" passes; identity checking is the
broker's job. This rule is the mailer's own, not the wrapper's: the wrapper
still applies no access rules in direct mode.
"""

import threading

from agents.mocks_client import MockServiceError, MocksClient
from contracts import Envelope
from contracts.catalog import get_catalog
from contracts.payloads import ResponsePayload

ACTION = "mail.deliver"
SINK_PATH = "/mail/send"


class MailerAgent:
    def __init__(self, mocks: MocksClient):
        self.mocks = mocks

    @staticmethod
    def allowed_senders() -> tuple[str, ...]:
        return get_catalog().get(ACTION).allowed_roles

    def handle(self, env: Envelope) -> ResponsePayload:
        if env.action != ACTION:
            return ResponsePayload(status="error", error=f"mailer serves only {ACTION}, not {env.action!r}")
        allowed = self.allowed_senders()
        if env.sender not in allowed:
            return ResponsePayload(
                status="error",
                error=f"{ACTION} is accepted only from {', '.join(allowed)}, not from {env.sender!r}")
        try:
            result = self.mocks.call(SINK_PATH, env.resource, dict(env.payload), env.trace_id)
        except MockServiceError as exc:
            return ResponsePayload(status="error", error=str(exc)[:500])
        return ResponsePayload(status="ok", result=result)


_default: MailerAgent | None = None
_lock = threading.Lock()


def handle(env: Envelope) -> ResponsePayload:
    """Wrapper entry point: one MailerAgent per process, built from the environment."""
    global _default
    with _lock:
        if _default is None:
            _default = MailerAgent(MocksClient())
    return _default.handle(env)
