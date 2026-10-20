"""Step 7: JSONL message log of every request and response."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from contracts import Envelope
from wrapper.app import create_app
from wrapper.config import DEFAULT_LOG_DIR, Settings, load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
TOKEN = "eyJhbGciOiJFZERTQSJ9.TOKEN-MARKER-123.c2ln"
PROOF = "PROOF-MARKER-456"


def request_dict(**overrides):
    data = {
        "schema_version": "0.2", "msg_id": "m-1", "trace_id": "t-1",
        "parent_msg_id": None, "msg_type": "request", "sender": "planner",
        "receiver": "dummy", "action": "db.query_aggregate", "resource": "db:sales",
        "payload": {"metric": "count"}, "delegation_chain": ["user", "planner"],
        "timestamp": "2026-10-21T10:00:00Z",
    }
    data.update(overrides)
    return data


@pytest.fixture
def log_dir(tmp_path):
    return tmp_path / "dir with space" / "logs"


@pytest.fixture
def client(log_dir):
    return TestClient(create_app(Settings(mode="direct", agent_name="dummy", log_dir=log_dir)))


def post(client, body):
    return client.post(
        "/message", content=json.dumps(body),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {TOKEN}", "X-Agent-Proof": PROOF},
    )


def read_log(log_dir):
    path = log_dir / "dummy.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_request_and_response_logged_as_full_envelopes(client, log_dir):
    r = post(client, request_dict())
    records = read_log(log_dir)
    assert [rec["direction"] for rec in records] == ["in", "out"]
    assert all(rec["logged_by"] == "dummy" for rec in records)
    assert all(rec["logged_at"].endswith("Z") for rec in records)
    assert Envelope.model_validate(records[0]["envelope"]) == Envelope.model_validate(request_dict())
    assert records[1]["envelope"] == r.json()


def test_each_line_has_only_the_agreed_keys(client, log_dir):
    post(client, request_dict())
    for rec in read_log(log_dir):
        assert set(rec) == {"logged_at", "logged_by", "direction", "envelope"}


def test_token_and_proof_never_logged(client, log_dir):
    post(client, request_dict())
    text = (log_dir / "dummy.jsonl").read_text(encoding="utf-8")
    for secret in (TOKEN, "TOKEN-MARKER-123", PROOF, "Authorization", "Bearer"):
        assert secret not in text


def test_labels_and_trust_scores_cannot_reach_the_log(client, log_dir):
    r = post(client, request_dict(scenario_label="A3", trust_score=0.2))
    assert r.status_code == 422
    assert read_log(log_dir) == []


def test_messages_appended_in_order(client, log_dir):
    for i in range(3):
        post(client, request_dict(msg_id=f"m-{i}"))
    ins = [rec["envelope"]["msg_id"] for rec in read_log(log_dir) if rec["direction"] == "in"]
    assert ins == ["m-0", "m-1", "m-2"]
    assert len(read_log(log_dir)) == 6


def test_misdirected_request_logged_without_response(client, log_dir):
    post(client, request_dict(receiver="database"))
    assert [rec["direction"] for rec in read_log(log_dir)] == ["in"]


def test_broker_mode_writes_nothing(log_dir):
    c = TestClient(create_app(Settings(mode="broker", agent_name="dummy", log_dir=log_dir)))
    assert post(c, request_dict()).status_code == 501
    assert read_log(log_dir) == []


def test_log_dir_created_lazily(log_dir):
    create_app(Settings(mode="direct", agent_name="dummy", log_dir=log_dir))
    assert not log_dir.exists()


def test_log_dir_from_environment(tmp_path):
    s = load_settings({"MODE": "direct", "AGENT_NAME": "dummy", "LOG_DIR": str(tmp_path)})
    assert s.log_dir == tmp_path
    assert load_settings({"MODE": "direct", "AGENT_NAME": "dummy"}).log_dir == DEFAULT_LOG_DIR


def test_default_log_dir_is_gitignored():
    assert DEFAULT_LOG_DIR == REPO_ROOT / "logs"
    assert "logs/" in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
