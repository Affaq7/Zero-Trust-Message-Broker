"""send_message(): how an agent sends a request and gets the response.

The sender is this process's AGENT_NAME. MODE and the receiver's URL come
only from the operator-set environment (MODE, AGENT_URLS), read at call time;
nothing in a message can change where it goes or which mode is used.

The caller's token goes in the Authorization header and the PROOF STUB in
X-Agent-Proof. Neither is logged, and errors never include headers.
"""

import os
from collections.abc import Mapping
from typing import Any

import httpx
from pydantic import ValidationError

from contracts import Envelope, new_request
from contracts.tokens import PROOF_HEADER, make_proof_stub
from wrapper.config import load_settings

DEFAULT_TIMEOUT_SECONDS = 60.0


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


class BrokerModeNotImplementedError(NotImplementedError):
    pass


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
) -> Envelope:
    """Build a request with new_request(), send it, return the response envelope.

    ``chain_so_far`` is the delegation chain this agent received (["user"]
    for the first hop); pass ``trace_id`` to continue the caller's trace.
    ``client`` lets tests inject an in-process transport.
    """
    settings = load_settings(environ)
    if settings.mode == "broker":
        raise BrokerModeNotImplementedError("MODE=broker is not implemented yet")

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
