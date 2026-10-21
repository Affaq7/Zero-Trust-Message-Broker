"""Optional live test against a running Ollama (llama3:8b). Skipped by default.

Run (from the repo root, with Ollama started):
  $env:RUN_OLLAMA_TESTS = "1"
  & ".\\.venv\\Scripts\\python.exe" -m pytest -m ollama -v -s
"""

import os
import time

import pytest
from pydantic import BaseModel

from agents.llm import load_llm_settings, make_llm

pytestmark = [
    pytest.mark.ollama,
    pytest.mark.skipif(os.environ.get("RUN_OLLAMA_TESTS") != "1",
                       reason="set RUN_OLLAMA_TESTS=1 and start Ollama to run"),
]


class Decision(BaseModel):
    action: str
    reason: str


def test_live_json_decision(tmp_path):
    llm = make_llm("live-test", settings=load_llm_settings(), log_dir=tmp_path)
    started = time.perf_counter()
    out = llm.decide(
        purpose="live.smoke",
        system="You choose one action for a company assistant. Reply in JSON.",
        prompt="The user asks for the total salary cost. Choose action "
               "'db.query_aggregate' or 'tool.send_email_internal', with a short reason.",
        schema=Decision,
    )
    elapsed = time.perf_counter() - started
    print(f"\nlive decision in {elapsed:.1f}s: {out}")
    assert out.action in {"db.query_aggregate", "tool.send_email_internal"}
    log = (tmp_path / "llm" / "live-test.jsonl").read_text(encoding="utf-8")
    assert '"ok": true' in log
