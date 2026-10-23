import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

import agents.mailer as mailer_module
from agents.llm import FakeLLM, LLMSettings
from agents.mailer import MailerAgent
from agents.mocks_client import MocksClient
from mocks.app import create_app as create_mocks_app
from mocks.config import MockSettings
from wrapper.app import create_app as create_wrapper_app
from wrapper.config import Settings
from wrapper.send import send_message


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
def recording_mocks(mocks):
    """A separate MocksClient for the agent under test that records every path it calls."""
    paths = []

    def route(request):
        paths.append(request.url.path)
        r = mocks.request(request.method, request.url.path, content=request.read(),
                          headers=dict(request.headers))
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)
    client = MocksClient("http://mocks.test", client=httpx.Client(transport=httpx.MockTransport(route)))
    return SimpleNamespace(client=client, paths=paths)


@pytest.fixture
def mail_path(tmp_path, mocks_client, monkeypatch):
    """The mailer behind a real wrapper, in-process, as the tool agent reaches it.

    .send(**kwargs) is send_message() as the tool agent (AGENT_NAME=tool) would call it;
    .requests are the HTTP requests that reached the mailer; .app is the mailer wrapper.
    The mailer talks to the mock sink through ``mocks_client``.
    """
    monkeypatch.setattr(mailer_module, "_default", MailerAgent(mocks_client))
    app = TestClient(create_wrapper_app(Settings(mode="direct", agent_name="mailer", log_dir=tmp_path)))
    requests = []

    def route(request):
        requests.append(request)
        r = app.request(request.method, request.url.path, content=request.read(),
                        headers=dict(request.headers))
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)
    http = httpx.Client(transport=httpx.MockTransport(route))
    environ = {"MODE": "direct", "AGENT_NAME": "tool", "AGENT_URLS": "mailer=http://mailer.test"}

    def send(**kwargs):
        return send_message(token="stub-token-for-tests", environ=environ, client=http, **kwargs)
    return SimpleNamespace(send=send, requests=requests, app=app, client=http, environ=environ)


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
