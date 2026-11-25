"""send_message(): how an agent sends a request and gets the response.

The sender is this process's AGENT_NAME. MODE and where a request goes come
only from the operator-set environment (MODE, AGENT_URLS, BROKER_URL), read at
call time; nothing in a message can change where it goes or which mode is used.

MODE=direct (the baseline, unchanged): the request goes straight to the
receiver's wrapper; the caller's token goes in the Authorization header and the
PROOF STUB in X-Agent-Proof.

MODE=broker: every request goes to the broker (BROKER_URL/message). It carries
the agent's issued token (AGENT_CREDENTIALS, docs/identity-spec.md section 2) and
a per-message proof signed with the instance's own key (make_proof, section 3).
Without issued credentials nothing is sent. A broker refusal (decision DENY,
QUARANTINE or HITL) raises BrokerDecisionError, a SendError, so every agent
handles it like any failed step; a SANITIZE reply is returned as a normal reply.

Tokens and proofs are never logged, and errors never include headers.
"""

import os
from collections.abc import Mapping
from typing import Any

import httpx
from pydantic import ValidationError

from contracts import Envelope, new_request
from contracts.catalog import get_catalog
from contracts.tokens import PROOF_HEADER, make_proof_stub
from wrapper.config import Settings, load_settings

DEFAULT_TIMEOUT_SECONDS = 60.0
REFUSALS = ("DENY", "QUARANTINE", "HITL")


class SendError(RuntimeError):
    """Base class for send_message() failures."""


class UnknownReceiverError(SendError):
    """AGENT_URLS has no URL for the receiver."""


class ReceiverUnreachableError(SendError):
    """Connection failed or timed out."""


class BadResponseError(SendError):
    """The receiver answered, but not with a matching response envelope."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class BrokerNotConfiguredError(SendError):
    """MODE=broker, but BROKER_URL or the agent's issued credentials are missing."""


class BrokerDecisionError(SendError):
    """The broker refused the request (DENY, QUARANTINE or HITL). Carries the reply."""

    def __init__(self, reply: Envelope):
        super().__init__(f"broker {reply.decision}: {reply.reason_code or 'no reason code'}")
        self.reply = reply
        self.decision = reply.decision
        self.reason_code = reply.reason_code


def send_message(
    *,
    receiver: str,
    action: str,
    resource: str,
    payload: dict[str, Any],
    chain_so_far: list[str],
    token: str,
    trace_id: str | None = None,
    environ: Mapping[str, str] = os.environ,
    client: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    credentials: Any = None,
) -> Envelope:
    """Build a request with new_request(), send it, return the response envelope.

    ``chain_so_far`` is the delegation chain this agent received (["user"]
    for the first hop); pass ``trace_id`` to continue the caller's trace.
    ``client`` lets tests inject an in-process transport. ``credentials``
    (MODE=broker only) overrides the issued credentials of this process.
    """
    settings = load_settings(environ)
    if settings.mode == "broker":
        return _send_via_broker(settings, environ, client, timeout, credentials, receiver=receiver,
                                action=action, resource=resource, payload=payload,
                                chain_so_far=chain_so_far, trace_id=trace_id)
    request = new_request(
        sender=settings.agent_name, receiver=receiver, action=action,
        resource=resource, payload=payload, chain_so_far=chain_so_far,
        trace_id=trace_id,
    )
    base_url = settings.agent_urls.get(receiver)
    if base_url is None:
        raise UnknownReceiverError(f"no URL for receiver {receiver!r} in AGENT_URLS")
    url = f"{base_url}/message"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        PROOF_HEADER: make_proof_stub(request),  # PROOF STUB
    }
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        resp = http.post(url, content=request.model_dump_json(), headers=headers)
    except httpx.TransportError as exc:
        raise ReceiverUnreachableError(
            f"{receiver!r} at {url} unreachable: {type(exc).__name__}") from None
    finally:
        if owns_client:
            http.close()
    return _check_response(request, resp, receiver)


def _check_response(request: Envelope, resp: httpx.Response, receiver: str) -> Envelope:
    if resp.status_code != 200:
        raise BadResponseError(f"{receiver!r} answered HTTP {resp.status_code}", resp.status_code)
    try:
        env = Envelope.model_validate_json(resp.content)
    except ValidationError:
        raise BadResponseError(f"{receiver!r} did not return a valid envelope", 200) from None
    if env.msg_type != "response" or env.parent_msg_id != request.msg_id:
        raise BadResponseError(f"{receiver!r} returned an envelope that does not answer "
                               f"msg {request.msg_id}", 200)
    return env


# --- MODE=broker ------------------------------------------------------------------------------

def _broker_credentials(settings: Settings, environ: Mapping[str, str], given: Any):
    """This process's issued credentials (a FileCredentials); never the throwaway stub."""
    from wrapper.credentials import CredentialsError, FileCredentials, load_credentials

    creds = given
    if creds is None:
        try:
            from wrapper.runtime import current_runtime
            creds = current_runtime().credentials            # loaded once at wrapper start-up
        except RuntimeError:
            creds = None                                     # called outside an agent call
    if creds is None:
        role = settings.agent_role or (settings.agent_name if settings.agent_name in get_catalog().roles
                                       else None)
        if role is None:
            raise BrokerNotConfiguredError(f"MODE=broker: {settings.agent_name!r} has no role, so it has "
                                           "no issued credentials; nothing was sent")
        try:
            creds = load_credentials(settings.agent_name, role, environ)
        except CredentialsError as exc:
            raise BrokerNotConfiguredError(f"MODE=broker: cannot load issued credentials ({exc}); "
                                           "nothing was sent") from None
    if not isinstance(creds, FileCredentials) or creds.sub != settings.agent_name:
        raise BrokerNotConfiguredError("MODE=broker needs issued credentials: set AGENT_CREDENTIALS "
                                       "(and AGENT_KEYS_DIR) for this agent; nothing was sent")
    return creds


def _send_via_broker(settings: Settings, environ: Mapping[str, str], client: httpx.Client | None,
                     timeout: float, credentials: Any, *, receiver: str, **request_fields) -> Envelope:
    from broker.identity.client import make_proof     # imported here: direct mode never needs it

    if not settings.broker_url:
        raise BrokerNotConfiguredError("MODE=broker needs BROKER_URL; nothing was sent")
    creds = _broker_credentials(settings, environ, credentials)
    request = new_request(sender=settings.agent_name, receiver=receiver, **request_fields)
    url = f"{settings.broker_url}/message"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {creds.token}",
        PROOF_HEADER: make_proof(request, creds.token, creds.private_key),
    }
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        resp = http.post(url, content=request.model_dump_json(), headers=headers)
    except httpx.TransportError as exc:
        raise ReceiverUnreachableError(f"broker at {url} unreachable: {type(exc).__name__}") from None
    finally:
        if owns_client:
            http.close()
    reply = _check_response(request, resp, "broker")
    if reply.decision in REFUSALS:
        raise BrokerDecisionError(reply)
    return reply
