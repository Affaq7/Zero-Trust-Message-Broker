"""How agents reach the mock services (the "world"): plain HTTP, not envelopes.

MOCKS_URL is operator-set (default http://127.0.0.1:8090). The envelope's
trace_id goes along as X-Trace-Id so ground truth can be matched to a run.
"""

import os
from typing import Any

import httpx

DEFAULT_MOCKS_URL = "http://127.0.0.1:8090"
DEFAULT_TIMEOUT_SECONDS = 30.0


class MockServiceError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


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
            raise MockServiceError(str(body.get("error") or f"HTTP {resp.status_code}"), resp.status_code)
        return body
