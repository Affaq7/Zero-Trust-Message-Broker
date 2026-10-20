"""The interface every agent implements.

An agent gets the parsed request envelope and returns the response payload.
The wrapper builds the response envelope with make_response(). Agents are
plain (blocking) functions; the wrapper runs them in a worker thread.
"""

from collections.abc import Callable

from contracts import Envelope
from contracts.payloads import ResponsePayload

AgentFn = Callable[[Envelope], ResponsePayload]
