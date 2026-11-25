"""Step 8: the files used for the manual curl.exe test."""

import json
import subprocess
import sys
from pathlib import Path

import jwt
from fastapi.testclient import TestClient

from contracts import Envelope, rule_violations
from contracts.tokens import TokenClaims, algorithm_allowed
from wrapper.app import create_app
from wrapper.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = REPO_ROOT / "examples" / "dummy_request.json"
SCRIPT = REPO_ROOT / "scripts" / "print_stub_token.py"


def run_script(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          cwd=REPO_ROOT, capture_output=True, text=True)


def test_example_request_is_a_valid_rule_abiding_envelope():
    env = Envelope.model_validate_json(EXAMPLE.read_bytes())
    assert env.receiver == "dummy"
    assert rule_violations(env) == []


def test_example_request_accepted_by_dummy_wrapper(tmp_path):
    c = TestClient(create_app(Settings(mode="direct", agent_name="dummy", log_dir=tmp_path)))
    r = c.post("/message", content=EXAMPLE.read_bytes(),
               headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert r.json()["parent_msg_id"] == json.loads(EXAMPLE.read_text())["msg_id"]


def test_stub_token_script_prints_one_valid_eddsa_token():
    result = run_script()
    assert result.returncode == 0, result.stderr
    token = result.stdout.strip()
    assert result.stdout.count("\n") == 1          # exactly one line, for $token = ...
    assert algorithm_allowed(token)
    assert jwt.get_unverified_header(token)["typ"] == "JWT"
    claims = TokenClaims.model_validate(jwt.decode(token, options={"verify_signature": False}))
    assert (claims.sub, claims.role, claims.aud) == ("planner", "planner", "dummy")
    assert claims.exp - claims.iat == 300


def test_stub_token_options_and_fresh_key_each_run():
    a = run_script("--sub", "research", "--role", "research", "--aud", "tool").stdout.strip()
    b = run_script("--sub", "research", "--role", "research", "--aud", "tool").stdout.strip()
    ca, cb = (jwt.decode(t, options={"verify_signature": False}) for t in (a, b))
    assert (ca["sub"], ca["aud"]) == ("research", "tool")
    assert ca["jti"] != cb["jti"]
    assert ca["cnf"]["jkt"] != cb["cnf"]["jkt"]    # new throwaway key every run


def test_stub_token_rejects_unknown_role():
    result = run_script("--role", "malicious")
    assert result.returncode == 2
    assert result.stdout == ""


def test_stub_token_script_writes_no_files(tmp_path):
    before = {p for p in REPO_ROOT.rglob("*") if ".venv" not in p.parts and ".git" not in p.parts}
    run_script()
    after = {p for p in REPO_ROOT.rglob("*") if ".venv" not in p.parts and ".git" not in p.parts}
    assert not {p for p in after - before if "__pycache__" not in p.parts}
    assert (REPO_ROOT / "keys") in before or not (REPO_ROOT / "keys").exists()  # issued keys (K1) may exist
