"""LLM layer shared by all agents: one JSON decision per call.

llama3:8b has no native tool calling, so an agent asks the model for a small
JSON object that must fit a Pydantic schema, and ordinary code then acts on
it. Backends:

- "ollama": Ollama /api/chat with temperature 0, a fixed seed, an explicit
  num_ctx and an output cap. Ollama would silently drop the start of a
  prompt that does not fit the window, so this layer refuses such prompts.
- "fake":   scripted replies per purpose, for tests and pipeline checks.

Every call is logged to logs/llm/<agent>.jsonl: timings, token counts and a
prompt hash, never the prompt text. Settings come from the environment.
"""

import hashlib
import json
import math
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

Backend = Literal["ollama", "fake"]
TEMPERATURE = 0.0          # fixed by project decision
CHARS_PER_TOKEN = 3        # conservative: English averages ~4 chars per llama3 token
MESSAGE_OVERHEAD_TOKENS = 8
REPO_ROOT = Path(__file__).resolve().parents[1]


class LLMError(RuntimeError):
    pass


class LLMConfigError(LLMError):
    pass


class ContextWindowError(LLMError):
    """Prompt plus output cap would not fit in num_ctx."""


class LLMUnavailableError(LLMError):
    """Ollama not reachable, or it answered with an HTTP error."""


class LLMTimeoutError(LLMError):
    pass


class LLMOutputError(LLMError):
    """The model's reply was not valid JSON for the schema (after one retry)."""


@dataclass(frozen=True)
class LLMSettings:
    backend: Backend = "ollama"
    base_url: str = "http://localhost:11434"
    model: str = "llama3:8b"
    seed: int = 0
    num_ctx: int = 4096
    num_predict: int = 256
    timeout_s: float = 180.0
    keep_alive: str = "60m"
    fake_script: Path | None = None

    def ollama_options(self) -> dict[str, Any]:
        return {"temperature": TEMPERATURE, "seed": self.seed,
                "num_ctx": self.num_ctx, "num_predict": self.num_predict}


def _int(environ, name, default, minimum):
    raw = environ.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        raise LLMConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise LLMConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def load_llm_settings(environ: Mapping[str, str] = os.environ) -> LLMSettings:
    backend = environ.get("LLM_BACKEND", "ollama").strip() or "ollama"
    if backend not in ("ollama", "fake"):
        raise LLMConfigError(f"LLM_BACKEND must be ollama or fake, got {backend!r}")
    num_ctx = _int(environ, "LLM_NUM_CTX", 4096, 256)
    num_predict = _int(environ, "LLM_NUM_PREDICT", 256, 1)
    if num_predict >= num_ctx:
        raise LLMConfigError("LLM_NUM_PREDICT must be smaller than LLM_NUM_CTX")
    timeout_raw = environ.get("LLM_TIMEOUT_S", "").strip()
    try:
        timeout = float(timeout_raw) if timeout_raw else 180.0
    except ValueError:
        raise LLMConfigError(f"LLM_TIMEOUT_S must be a number, got {timeout_raw!r}") from None
    if timeout <= 0:
        raise LLMConfigError("LLM_TIMEOUT_S must be > 0")
    script = environ.get("LLM_FAKE_SCRIPT", "").strip()
    if backend == "fake" and not script:
        raise LLMConfigError("LLM_BACKEND=fake needs LLM_FAKE_SCRIPT (a JSON file)")
    return LLMSettings(
        backend=backend,
        base_url=(environ.get("LLM_BASE_URL", "").strip() or "http://localhost:11434").rstrip("/"),
        model=environ.get("LLM_MODEL", "").strip() or "llama3:8b",
        seed=_int(environ, "LLM_SEED", 0, 0),
        num_ctx=num_ctx, num_predict=num_predict, timeout_s=timeout,
        fake_script=Path(script) if script else None,
    )


def estimate_tokens(*texts: str) -> int:
    """Upper-bound token estimate (no tokenizer available offline)."""
    return sum(math.ceil(len(t) / CHARS_PER_TOKEN) + MESSAGE_OVERHEAD_TOKENS for t in texts)


class LLMCallLog:
    """logs/llm/<agent>.jsonl: one line per call, no prompt text."""

    def __init__(self, log_dir: Path, agent_name: str):
        self.path = Path(log_dir) / "llm" / f"{agent_name}.jsonl"
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> None:
        record = {"logged_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **record}
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")


class LLMClient:
    """Base class: guard, validation, one retry, call log. Backends implement _chat()."""

    def __init__(self, settings: LLMSettings, agent_name: str, log_dir: Path):
        self.settings = settings
        self.agent_name = agent_name
        self.log = LLMCallLog(log_dir, agent_name)

    def decide(self, *, purpose: str, system: str, prompt: str, schema: type[T]) -> T:
        """Ask for one JSON object fitting ``schema``; raise LLMError subclasses on failure."""
        s = self.settings
        estimate = estimate_tokens(system, prompt)
        record: dict[str, Any] = {
            "agent": self.agent_name, "purpose": purpose, "backend": s.backend, "model": s.model,
            "seed": s.seed, "num_ctx": s.num_ctx, "num_predict": s.num_predict,
            "prompt_chars": len(system) + len(prompt), "est_prompt_tokens": estimate,
            "prompt_sha256": hashlib.sha256((system + "\x00" + prompt).encode("utf-8")).hexdigest(),
        }
        started = time.perf_counter()
        try:
            if estimate + s.num_predict > s.num_ctx:
                raise ContextWindowError(
                    f"{purpose}: about {estimate} prompt tokens + {s.num_predict} output "
                    f"> num_ctx {s.num_ctx}; shorten the prompt")
            messages = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
            result, attempts, stats = self._decide_with_retry(purpose, messages, schema)
            record.update(stats, attempts=attempts, ok=True)
            return result
        except LLMError as exc:
            record.update(ok=False, error=type(exc).__name__, message=str(exc)[:300])
            raise
        finally:
            record["duration_ms"] = round((time.perf_counter() - started) * 1000)
            self.log.append(record)

    def _decide_with_retry(self, purpose, messages, schema):
        stats: dict[str, Any] = {}
        for attempt in (1, 2):
            raw, stats = self._chat(purpose, messages, schema)
            try:
                return schema.model_validate(json.loads(raw)), attempt, stats
            except (json.JSONDecodeError, ValidationError) as exc:
                if attempt == 2:
                    raise LLMOutputError(f"{purpose}: invalid reply after retry: {exc}") from None
                messages = [*messages, {"role": "assistant", "content": raw},
                            {"role": "user", "content": "That reply was not valid. Reply again "
                             "with only one JSON object that fits the required format."}]
        raise AssertionError("unreachable")

    def _chat(self, purpose: str, messages: list[dict], schema: type[BaseModel]) -> tuple[str, dict]:
        raise NotImplementedError


class OllamaLLM(LLMClient):
    def __init__(self, settings, agent_name, log_dir, client: httpx.Client | None = None):
        super().__init__(settings, agent_name, log_dir)
        self._client = client or httpx.Client(timeout=settings.timeout_s)

    def _chat(self, purpose, messages, schema):
        s = self.settings
        body = {"model": s.model, "messages": messages, "stream": False,
                "format": schema.model_json_schema(), "options": s.ollama_options(),
                "keep_alive": s.keep_alive}
        try:
            resp = self._client.post(f"{s.base_url}/api/chat", json=body)
        except httpx.TimeoutException:
            raise LLMTimeoutError(f"{purpose}: no reply from Ollama within {s.timeout_s}s") from None
        except httpx.TransportError as exc:
            raise LLMUnavailableError(f"{purpose}: Ollama unreachable at {s.base_url}: "
                                      f"{type(exc).__name__}") from None
        if resp.status_code != 200:
            raise LLMUnavailableError(f"{purpose}: Ollama answered HTTP {resp.status_code}: "
                                      f"{resp.text[:200]}")
        data = resp.json()
        stats = {"prompt_eval_count": data.get("prompt_eval_count"),
                 "eval_count": data.get("eval_count"),
                 "ollama_total_ms": round(data.get("total_duration", 0) / 1e6),
                 "ollama_load_ms": round(data.get("load_duration", 0) / 1e6)}
        used = (data.get("prompt_eval_count") or 0) + s.num_predict
        if used > s.num_ctx:
            raise ContextWindowError(f"{purpose}: Ollama counted {data.get('prompt_eval_count')} "
                                     f"prompt tokens + {s.num_predict} output > num_ctx {s.num_ctx}")
        return data["message"]["content"], stats


class FakeLLM(LLMClient):
    """Scripted replies per purpose, in one of two forms:

    - a list: {"<purpose>": [reply, reply, ...]}, consumed in order;
    - rules: {"<purpose>": {"rules": [{"if_prompt_contains": "...", "reply": ...}],
      "default": reply}}. Rules are not consumed: the first rule whose text
      occurs in the prompt wins, else the default. This keeps replies right
      when several tasks share one agent process concurrently.

    A reply is a JSON object (dict) or a raw string (to test invalid output).
    """

    def __init__(self, settings, agent_name, log_dir, script: dict[str, Any] | None = None):
        super().__init__(settings, agent_name, log_dir)
        if script is None:
            if settings.fake_script is None:
                raise LLMConfigError("FakeLLM needs a script")
            script = json.loads(Path(settings.fake_script).read_text(encoding="utf-8"))
        self._script = {k: (dict(v) if isinstance(v, dict) else list(v)) for k, v in script.items()}
        self._lock = threading.Lock()

    def _chat(self, purpose, messages, schema):
        entry = self._script.get(purpose)
        if isinstance(entry, dict):
            prompt = "\n".join(m["content"] for m in messages)
            reply = next((r["reply"] for r in entry.get("rules", [])
                          if r["if_prompt_contains"] in prompt), entry.get("default"))
            if reply is None:
                raise LLMOutputError(f"fake script has no rule or default for {purpose!r}")
        else:
            with self._lock:
                if not entry:
                    raise LLMOutputError(f"fake script has no (more) replies for {purpose!r}")
                reply = entry.pop(0)
        raw = reply if isinstance(reply, str) else json.dumps(reply)
        return raw, {"prompt_eval_count": None, "eval_count": None}


def make_llm(agent_name: str, *, settings: LLMSettings | None = None,
             log_dir: Path | None = None) -> LLMClient:
    settings = settings or load_llm_settings()
    log_dir = log_dir or Path(os.environ.get("LOG_DIR", "").strip() or REPO_ROOT / "logs")
    if settings.backend == "fake":
        return FakeLLM(settings, agent_name, log_dir)
    return OllamaLLM(settings, agent_name, log_dir)
