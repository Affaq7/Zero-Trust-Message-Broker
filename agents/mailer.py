"""Mailer agent: serves mail.deliver, deterministic, no LLM.

The tool agent sends a mail.deliver envelope here instead of calling the mock
mail sink. The mailer is the only thing that calls the sink (POST /mail/send).
It passes the envelope's resource and payload to the sink unchanged and
returns the sink's answer. The sink validates them (mail.deliver schema,
recipients normalised), delivers to every address in to, cc and bcc, and
records the attempt: delivered or failed, with the recipients. The sink never
knows the intended recipients; the scenario file does.

No access rule lives here. The catalog says only the tool agent may call
mail.deliver; enforcing that is the broker's job. In direct mode (the
baseline) the mailer, like the wrapper in front of every other agent, accepts
the message from whoever sent it. The one thing it refuses is an action it
cannot perform (anything but mail.deliver), a capability limit like the tool
agent's, not a policy check.
"""

import threading

from agents.mocks_client import MockServiceError, MocksClient
from contracts import Envelope
from contracts.payloads import ResponsePayload

ACTION = "mail.deliver"
SINK_PATH = "/mail/send"


class MailerAgent:
    def __init__(self, mocks: MocksClient):
        self.mocks = mocks

    def handle(self, env: Envelope) -> ResponsePayload:
        if env.action != ACTION:
            return ResponsePayload(status="error", error=f"mailer serves only {ACTION}, not {env.action!r}")
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
