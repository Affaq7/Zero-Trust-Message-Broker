"""How agents reach the mock services (the "world"): plain HTTP, not envelopes.

MOCKS_URL is operator-set (default http://127.0.0.1:8090). The envelope's
trace_id goes along as X-Trace-Id so ground truth can be matched to a run.
"""

import os
import re
from typing import Any

import httpx

DEFAULT_MOCKS_URL = "http://127.0.0.1:8090"
DEFAULT_TIMEOUT_SECONDS = 30.0


class MockServiceError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


MAX_PROBLEMS = 6


def describe_error(body: dict) -> str:
    """Error text for the requesting agent. For an invalid payload it names each
    offending field and the reason, never the values that were sent."""
    error = str(body.get("error") or "")
    details = body.get("details")
    if error != "invalid payload" or not isinstance(details, list):
        return error
    problems = []
    for d in details[:MAX_PROBLEMS]:
        field = ".".join(str(p) for p in d.get("loc", []) if not isinstance(p, int)) or "payload"
        reason = str(d.get("msg", "invalid"))
        if d.get("type") == "value_error":       # custom checks may quote the value
            reason = re.sub(r"\s+", " ", re.sub(r"'[^']*'", "", reason)).strip()
        problems.append(f"{field}: {reason}")
    return "invalid payload: " + "; ".join(problems)


class MocksClient:
    def __init__(self, base_url: str | None = None, client: httpx.Client | None = None):
        url = base_url or os.environ.get("MOCKS_URL", "").strip() or DEFAULT_MOCKS_URL
        self.base_url = url.rstrip("/")
        self._client = client or httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS)

    def call(self, path: str, resource: str, payload: dict[str, Any], trace_id: str) -> dict:
        try:
            resp = self._client.post(f"{self.base_url}{path}",
                                     json={"resource": resource, "payload": payload},
                                     headers={"X-Trace-Id": trace_id})
        except httpx.TransportError as exc:
            raise MockServiceError(f"mock services unreachable: {type(exc).__name__}") from None
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code != 200:
            raise MockServiceError(describe_error(body) or f"HTTP {resp.status_code}", resp.status_code)
        return body
