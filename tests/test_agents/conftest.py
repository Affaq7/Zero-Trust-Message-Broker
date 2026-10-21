import json

import httpx
import pytest
from fastapi.testclient import TestClient

from agents.llm import FakeLLM, LLMSettings
from agents.mocks_client import MocksClient
from mocks.app import create_app as create_mocks_app
from mocks.config import MockSettings


@pytest.fixture
def mocks(tmp_path):
    """Mock-services app with a fresh seed, on an in-process test client."""
    settings = MockSettings(runtime_dir=tmp_path / "rt", log_dir=tmp_path / "logs")
    return TestClient(create_mocks_app(settings))


@pytest.fixture
def mocks_client(mocks):
    """MocksClient whose requests are served by the in-process mock app."""
    def route(request):
        r = mocks.request(request.method, request.url.path, content=request.read(),
                          headers=dict(request.headers))
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)
    return MocksClient("http://mocks.test", client=httpx.Client(transport=httpx.MockTransport(route)))


@pytest.fixture
def truth(mocks):
    """truth(**filters) -> ground-truth records from the mock app."""
    def _truth(**params):
        return mocks.get("/ground-truth", params=params).json()["records"]
    return _truth


@pytest.fixture
def fake_llm(tmp_path):
    """fake_llm(agent, script) -> FakeLLM that logs to tmp_path/llm/<agent>.jsonl."""
    def _make(agent, script):
        return FakeLLM(LLMSettings(backend="fake"), agent, tmp_path, script=script)
    return _make


@pytest.fixture
def llm_calls(tmp_path):
    """llm_calls(agent) -> the LLM call-log lines written so far."""
    def _calls(agent):
        path = tmp_path / "llm" / f"{agent}.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return _calls
