"""F2-A: runner helpers for --mode broker (per-run keys, process environment, results fields).

No processes are started here except the credentials script; the end-to-end broker run is
in test_mode_option.py. The real keys/ folder is never written."""

import json
import sys
import types
from pathlib import Path

import pytest

import runner.run as run_module
from runner.processes import (
    REPO_ROOT,
    Testbed,
    TestbedConfig,
    default_broker_real,
    issue_run_credentials,
)
from runner.results import broker_decision_cell

AGENTS = [{"name": "planner"}, {"name": "database"}]


def test_default_broker_real_adds_defence_and_audit_only_when_they_exist(monkeypatch):
    assert default_broker_real()[:5] == ["identity", "policy", "risk", "trust", "burst"]
    for name in ("broker.defence.quarantine", "broker.audit.log"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    assert default_broker_real() == ["identity", "policy", "risk", "trust", "burst", "defence", "audit"]


def test_run_credentials_go_to_a_new_folder_and_never_overwrite(tmp_path):
    out = tmp_path / "keys"
    issue_run_credentials(sys.executable, out)
    assert sorted(p.stem for p in out.glob("*.json")) == ["database", "mailer", "planner", "research",
                                                         "research-2", "research-stolen", "tool"]
    with pytest.raises(RuntimeError, match="already exist"):
        issue_run_credentials(sys.executable, out)                     # the script refuses to overwrite
    with pytest.raises(RuntimeError, match="must not go into keys/"):
        issue_run_credentials(sys.executable, REPO_ROOT / "keys")


def test_broker_mode_environment(tmp_path):
    tb = Testbed(TestbedConfig(agents=AGENTS, run_dir=tmp_path, mode="broker", broker_real=["identity", "policy"]))
    tb._plan()
    try:
        keys = tb.secrets_dir / "keys"
        assert keys.is_dir() and REPO_ROOT not in keys.resolve().parents      # outside the repo
        broker = tb.procs["broker"]
        assert broker.app == "broker.app:app"
        assert broker.env["BROKER_REAL"] == "identity,policy" and broker.env["BROKER_KEYS_DIR"] == str(keys)
        assert len(broker.env["BROKER_ADMIN_TOKEN"]) >= 32 and broker.env["BROKER_SIGNING_KEY"] == ""
        assert broker.env["AGENT_URLS"] == tb.procs["planner"].env["AGENT_URLS"]
        for name in ("planner", "database"):
            env = tb.procs[name].env
            assert (env["MODE"], env["BROKER_URL"], env["AGENT_CREDENTIALS"], env["AGENT_KEYS_DIR"]) == (
                "broker", broker.url, name, str(keys))
            assert "BROKER_ADMIN_TOKEN" not in env                          # agents never get the admin token
    finally:
        tb.stop()
    assert not keys.exists()                                                # the run's keys are removed


def test_direct_mode_environment_has_no_broker_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("BROKER_URL", "http://leak.test")                    # the operator's shell must not leak in
    tb = Testbed(TestbedConfig(agents=AGENTS, run_dir=tmp_path))
    tb._plan()
    assert "broker" not in tb.procs and tb.secrets_dir is None
    for p in tb.procs.values():
        assert not any(k.startswith("BROKER_") for k in p.env)
        assert "AGENT_CREDENTIALS" not in p.env and "AGENT_KEYS_DIR" not in p.env


def test_broker_decision_cell():
    events = [{"decision": "ALLOW", "reason_code": "POLICY_ALLOW"},
              {"decision": "DENY", "reason_code": "DELEGATION_EXCEEDS_DELEGATOR"}]
    assert broker_decision_cell(events) == "ALLOW:POLICY_ALLOW; DENY:DELEGATION_EXCEEDS_DELEGATOR"


def test_collect_broker_keeps_decisions_per_trace_oldest_first(monkeypatch):
    class Resp:
        def __init__(self, data):
            self.data = data

        def json(self):
            return self.data

    health = {"real": ["verify_identity"], "stubbed": ["append"], "modules": {"identity": "real"}, "ignored": {}}
    events = [  # newest first, as /api/events returns them
        {"kind": "decision", "trace_id": "t1", "msg_id": "m2", "decision": "DENY", "reason_code": "X", "payload": "no"},
        {"kind": "release", "agent": "planner"},
        {"kind": "decision", "trace_id": "other", "msg_id": "m9", "decision": "ALLOW"},
        {"kind": "decision", "trace_id": "t1", "msg_id": "m1", "decision": "ALLOW", "reason_code": "POLICY_ALLOW"},
    ]
    monkeypatch.setattr(run_module.httpx, "get",
                        lambda url, **kw: Resp(health if url.endswith("/health") else {"events": events}))
    info, per_trace = run_module.collect_broker("http://broker.test", ["t1"])
    assert info == {"mode": "broker", "broker_real": ["verify_identity"], "stubbed": ["append"],
                    "modules": {"identity": "real"}, "ignored": {}}
    assert [(e["msg_id"], e["decision"]) for e in per_trace["t1"]] == [("m1", "ALLOW"), ("m2", "DENY")]
    assert "payload" not in per_trace["t1"][1]
