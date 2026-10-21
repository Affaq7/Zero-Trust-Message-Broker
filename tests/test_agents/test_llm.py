"""M2 step 6: LLM layer (Ollama over mock transports) and the fake backend."""

import json

import httpx
import pytest
from pydantic import BaseModel

from agents.llm import (
    TEMPERATURE,
    ContextWindowError,
    FakeLLM,
    LLMConfigError,
    LLMOutputError,
    LLMSettings,
    LLMTimeoutError,
    LLMUnavailableError,
    OllamaLLM,
    estimate_tokens,
    load_llm_settings,
    make_llm,
)
from agents.telemetry import OFF, disable_telemetry


class Choice(BaseModel):
    action: str
    reason: str


def ollama_reply(content, prompt_eval_count=50, eval_count=10):
    body = {"message": {"role": "assistant", "content": content},
            "prompt_eval_count": prompt_eval_count, "eval_count": eval_count,
            "total_duration": 2_000_000_000, "load_duration": 1_000_000}
    return httpx.Response(200, json=body)


class Recorder:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request):
        self.requests.append(json.loads(request.content))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def ollama(tmp_path, handler, **settings):
    s = LLMSettings(**settings)
    return OllamaLLM(s, "planner", tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)))


def ask(llm, prompt="Pick an action.", system="You are a planner."):
    return llm.decide(purpose="planner.plan", system=system, prompt=prompt, schema=Choice)


def log_lines(tmp_path, agent="planner"):
    path = tmp_path / "llm" / f"{agent}.jsonl"
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]


# --- settings ----------------------------------------------------------------------

def test_default_settings():
    s = load_llm_settings({})
    assert (s.backend, s.model, s.base_url, s.num_ctx, s.num_predict, s.seed) == (
        "ollama", "llama3:8b", "http://localhost:11434", 4096, 256, 0)
    assert s.ollama_options() == {"temperature": 0.0, "seed": 0, "num_ctx": 4096, "num_predict": 256}
    assert TEMPERATURE == 0.0


def test_settings_from_environment(tmp_path):
    s = load_llm_settings({"LLM_SEED": "7", "LLM_NUM_CTX": "8192", "LLM_NUM_PREDICT": "128",
                           "LLM_TIMEOUT_S": "30", "LLM_BASE_URL": "http://127.0.0.1:11434/",
                           "LLM_BACKEND": "fake", "LLM_FAKE_SCRIPT": str(tmp_path / "s.json")})
    assert (s.seed, s.num_ctx, s.num_predict, s.timeout_s, s.base_url, s.backend) == (
        7, 8192, 128, 30.0, "http://127.0.0.1:11434", "fake")


@pytest.mark.parametrize("env", [
    {"LLM_BACKEND": "openai"},
    {"LLM_BACKEND": "fake"},                         # needs a script
    {"LLM_NUM_CTX": "lots"},
    {"LLM_NUM_CTX": "100"},
    {"LLM_NUM_PREDICT": "0"},
    {"LLM_NUM_CTX": "1024", "LLM_NUM_PREDICT": "1024"},
    {"LLM_SEED": "-1"},
    {"LLM_TIMEOUT_S": "0"},
    {"LLM_TIMEOUT_S": "soon"},
])
def test_bad_settings_rejected(env):
    with pytest.raises(LLMConfigError):
        load_llm_settings(env)


# --- Ollama request and reply ------------------------------------------------------

def test_request_body_and_parsed_decision(tmp_path):
    rec = Recorder(ollama_reply('{"action": "db.query_aggregate", "reason": "totals"}'))
    out = ask(ollama(tmp_path, rec, seed=3))
    assert out == Choice(action="db.query_aggregate", reason="totals")
    body = rec.requests[0]
    assert body["model"] == "llama3:8b" and body["stream"] is False
    assert body["options"] == {"temperature": 0.0, "seed": 3, "num_ctx": 4096, "num_predict": 256}
    assert body["format"] == Choice.model_json_schema()
    assert body["keep_alive"] == "60m"
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


def test_invalid_reply_retried_once(tmp_path):
    rec = Recorder(ollama_reply("not json"), ollama_reply('{"action": "a", "reason": "b"}'))
    assert ask(ollama(tmp_path, rec)).action == "a"
    assert len(rec.requests) == 2
    assert rec.requests[1]["messages"][-2] == {"role": "assistant", "content": "not json"}
    assert log_lines(tmp_path)[-1]["attempts"] == 2


def test_invalid_twice_raises(tmp_path):
    rec = Recorder(ollama_reply('{"action": 1}'), ollama_reply('{"wrong": true}'))
    with pytest.raises(LLMOutputError):
        ask(ollama(tmp_path, rec))
    assert log_lines(tmp_path)[-1]["ok"] is False


def _boom(exc):
    def handler(request):
        raise exc("x", request=request)
    return handler


@pytest.mark.parametrize("handler, error", [
    (_boom(httpx.ReadTimeout), LLMTimeoutError),
    (_boom(httpx.ConnectError), LLMUnavailableError),
    (lambda r: httpx.Response(404, json={"error": "model 'llama3:8b' not found"}), LLMUnavailableError),
])
def test_transport_failures(tmp_path, handler, error):
    with pytest.raises(error):
        ask(ollama(tmp_path, handler))


# --- context window guard ------------------------------------------------------------

def test_long_prompt_refused_before_sending(tmp_path):
    def never(request):
        raise AssertionError("must not reach Ollama")
    with pytest.raises(ContextWindowError, match="num_ctx 4096"):
        ask(ollama(tmp_path, never), prompt="x" * 12000)
    assert log_lines(tmp_path)[-1]["error"] == "ContextWindowError"


def test_guard_counts_output_cap(tmp_path):
    rec = Recorder(ollama_reply('{"action": "a", "reason": "b"}'))
    prompt = "x" * (3 * 3900)          # 3900 + 16 overhead + 256 cap = 4172 > 4096; with cap 64: 3980
    with pytest.raises(ContextWindowError):
        ask(ollama(tmp_path, rec), prompt=prompt, system="")
    assert ask(ollama(tmp_path, rec, num_predict=64), prompt=prompt, system="").action == "a"


def test_ollama_token_count_checked_after_reply(tmp_path):
    rec = Recorder(ollama_reply('{"action": "a", "reason": "b"}', prompt_eval_count=3900))
    with pytest.raises(ContextWindowError, match="Ollama counted 3900"):
        ask(ollama(tmp_path, rec))


def test_estimate_is_conservative():
    assert estimate_tokens("abc" * 100) == 100 + 8
    assert estimate_tokens("", "") == 16


# --- call log ----------------------------------------------------------------------

def test_call_log_has_stats_but_no_prompt_text(tmp_path):
    rec = Recorder(ollama_reply('{"action": "a", "reason": "b"}', prompt_eval_count=42, eval_count=9))
    ask(ollama(tmp_path, rec, seed=5), prompt="SECRET-PROMPT-TEXT 900-11-1113")
    line = log_lines(tmp_path)[-1]
    assert line["purpose"] == "planner.plan" and line["seed"] == 5 and line["ok"] is True
    assert line["prompt_eval_count"] == 42 and line["eval_count"] == 9
    assert line["ollama_total_ms"] == 2000 and "duration_ms" in line
    text = (tmp_path / "llm" / "planner.jsonl").read_text(encoding="utf-8")
    assert "SECRET-PROMPT-TEXT" not in text and "900-11-1113" not in text


# --- fake backend ----------------------------------------------------------------------

def fake(tmp_path, script, **settings):
    return FakeLLM(LLMSettings(backend="fake", **settings), "planner", tmp_path, script=script)


def test_fake_replies_in_order(tmp_path):
    llm = fake(tmp_path, {"planner.plan": [{"action": "a", "reason": "1"}, {"action": "b", "reason": "2"}]})
    assert [ask(llm).action, ask(llm).action] == ["a", "b"]
    with pytest.raises(LLMOutputError, match="no \\(more\\) replies"):
        ask(llm)


def test_fake_validates_and_retries_like_ollama(tmp_path):
    llm = fake(tmp_path, {"planner.plan": ["garbage", {"action": "ok", "reason": "r"}]})
    assert ask(llm).action == "ok"
    llm = fake(tmp_path, {"planner.plan": [{"nope": 1}, {"nope": 2}]})
    with pytest.raises(LLMOutputError):
        ask(llm)


def test_fake_applies_context_guard(tmp_path):
    llm = fake(tmp_path, {"planner.plan": [{"action": "a", "reason": "b"}]})
    with pytest.raises(ContextWindowError):
        ask(llm, prompt="y" * 20000)


def test_make_llm_from_environment(tmp_path, monkeypatch):
    script = tmp_path / "dir with space" / "script.json"
    script.parent.mkdir()
    script.write_text(json.dumps({"planner.plan": [{"action": "a", "reason": "b"}]}), encoding="utf-8")
    monkeypatch.setenv("LLM_BACKEND", "fake")
    monkeypatch.setenv("LLM_FAKE_SCRIPT", str(script))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    llm = make_llm("planner")
    assert isinstance(llm, FakeLLM)
    assert ask(llm).action == "a"
    assert (tmp_path / "logs" / "llm" / "planner.jsonl").exists()


def test_make_llm_defaults_to_ollama(tmp_path):
    assert isinstance(make_llm("tool", settings=LLMSettings(), log_dir=tmp_path), OllamaLLM)


# --- telemetry -------------------------------------------------------------------------

def test_disable_telemetry_overrides_existing_values():
    env = {"CREWAI_DISABLE_TELEMETRY": "false", "LANGCHAIN_TRACING_V2": "true", "OTHER": "x"}
    disable_telemetry(env)
    assert env["CREWAI_DISABLE_TELEMETRY"] == "true"
    assert env["LANGCHAIN_TRACING_V2"] == "false"
    assert env["OTEL_SDK_DISABLED"] == "true"
    assert env["ANONYMIZED_TELEMETRY"] == "False"
    assert env["OTHER"] == "x"
    assert all(env[k] == v for k, v in OFF.items())
