"""F2-B: attack scenarios in broker mode (scenario model, scripted sender's broker path,
evidence-based scoring, the forwarding secret) and one end-to-end broker run (A9)."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from runner.broker_score import score
from runner.processes import REPO_ROOT, Testbed, TestbedConfig
from runner.scenarios import ExpectedBroker, Scenario, load_scenarios

STEP = {"receiver": "database", "action": "db.query_rows", "resource": "db:employees",
        "payload": {"columns": ["id"], "limit": 1}}


def scenario(**over):
    data = {"id": "X9", "title": "t", "category": "attack", "baseline": "not_applicable",
            "not_applicable_reason": "needs the broker for this", "agents": [{"name": "database"}],
            "scripted": {"sender": "research", "sender_role": "research", "steps": [STEP]},
            "expected_broker": {"expected_decision": "DENY (ROLE_NOT_ALLOWED)",
                                "decisions": [{"decision": "DENY", "reason_code": "ROLE_NOT_ALLOWED"}]}}
    data.update(over)
    return Scenario.model_validate(data)


# --- scenario model ------------------------------------------------------------------------------

def test_broker_status_comes_from_expected_broker():
    s = scenario()
    assert (s.baseline, s.broker_status()) == ("not_applicable", "applicable")
    plain = scenario(expected_broker=None)
    assert plain.broker_status() == "not_applicable"


def test_admin_steps_only_in_broker_scenarios():
    admin = {"admin": "release", "agent": "research", "by": "kissa"}
    assert scenario(scripted={"sender": "research", "sender_role": "research", "steps": [STEP, admin]})
    with pytest.raises(ValidationError, match="admin step"):
        scenario(expected_broker=None, scripted={"sender": "research", "sender_role": "research",
                                                 "steps": [STEP, admin]})
    with pytest.raises(ValidationError):
        scenario(scripted={"sender": "research", "sender_role": "research",
                           "steps": [{"admin": "delete_everything", "agent": "x", "by": "y"}]})


def test_reissued_tokens_need_an_epoch_and_only_they_do():
    ok = {**STEP, "token": "reissued", "token_epoch": 1}
    assert scenario(scripted={"sender": "research", "sender_role": "research", "steps": [ok]})
    for bad in ({**STEP, "token": "reissued"}, {**STEP, "token_epoch": 1}):
        with pytest.raises(ValidationError, match="token_epoch"):
            scenario(scripted={"sender": "research", "sender_role": "research", "steps": [bad]})


def test_not_run_statuses_need_a_reason():
    with pytest.raises(ValidationError, match="needs a reason"):
        ExpectedBroker(status="pending_f3", expected_decision="x")
    assert ExpectedBroker(status="pending_f3", reason="F3", expected_decision="x")


def test_encoded_scenarios_in_broker_mode():
    s = load_scenarios()
    run = sorted(k for k, v in s.items() if k.startswith("A") and v.broker_status() == "applicable")
    assert run == ["A1", "A10", "A12", "A13", "A14", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9"]
    assert [k for k, v in s.items() if v.broker_status() == "pending_f3"] == []        # F3 is in
    assert s["A11"].broker_status() == "not_applicable"
    assert s["A3"].expected_broker.decisions is None                 # live model: not scored automatically
    for sid in ("A9", "A10", "A12", "A14"):                          # direct mode is unchanged
        assert s[sid].baseline == "not_applicable"


# --- scoring --------------------------------------------------------------------------------------

def expected(**over):
    data = {"expected_decision": "x", "decisions": [{"decision": "DENY", "reason_code": "ROLE_NOT_ALLOWED"}]}
    data.update(over)
    return ExpectedBroker.model_validate(data)


DENY = [{"decision": "DENY", "reason_code": "ROLE_NOT_ALLOWED"}]


def test_score_matches_on_the_broker_decisions():
    out = score(expected(), broker_events=DENY, trace_ids=["t"], log_dir=Path("."), audit_real=False,
                public_key_path=Path("x"))
    assert out["matched"] is True and out["problems"] == []


@pytest.mark.parametrize("events, http, final, problem", [
    ([{"decision": "ALLOW", "reason_code": "POLICY_ALLOW"}], None, None, "broker decisions"),
    (DENY, [500], None, "HTTP statuses"),
    (DENY, None, {"agents": [{"agent": "research", "quarantined": True}]}, "quarantined at the end"),
])
def test_score_lists_every_mismatch(events, http, final, problem):
    exp = expected(http_status=[200], final_quarantined={"research": False})
    out = score(exp, broker_events=events, trace_ids=["t"], log_dir=Path("."), audit_real=False,
                public_key_path=Path("x"), http_status=http or [200],
                final_state=final or {"agents": [{"agent": "research", "quarantined": False}]})
    assert out["matched"] is False and any(problem in p for p in out["problems"])


def test_score_needs_the_audit_log_when_audit_is_real(tmp_path):
    out = score(expected(), broker_events=DENY, trace_ids=["t"], log_dir=tmp_path, audit_real=True,
                public_key_path=tmp_path / "k.pub")
    assert out["matched"] is False and "no audit log" in out["problems"][0]


def test_score_checks_audit_decisions_events_and_signature(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from broker.audit.log import AuditLog
    from broker.identity.keys import public_jwk
    key = Ed25519PrivateKey.generate()
    pub = tmp_path / "k.pub"
    pub.write_text(json.dumps(public_jwk(key.public_key())), encoding="utf-8")
    log = AuditLog(tmp_path / "broker_audit.jsonl", key)
    log.append({"kind": "decision", "trace_id": "t", "msg_id": "m", "sender": "research", "receiver": "database",
                "action": "db.query_rows", "decision": "DENY", "reason_code": "ROLE_NOT_ALLOWED"})
    log.append({"kind": "release", "agent": "research", "by": "kissa"})
    ok = score(expected(audit_events=["release"]), broker_events=DENY, trace_ids=["t"], log_dir=tmp_path,
               audit_real=True, public_key_path=pub)
    assert ok["matched"] is True and ok["audit_ok"] is True and ok["audit_events"] == ["release"]
    wrong = score(expected(audit_events=["quarantine", "release"]), broker_events=DENY, trace_ids=["t"],
                  log_dir=tmp_path, audit_real=True, public_key_path=pub)
    assert wrong["matched"] is False and "audit events" in wrong["problems"][0]
    data = bytearray((tmp_path / "broker_audit.jsonl").read_bytes())
    data[data.index(b'"DENY"') + 4] = ord("X")                           # one byte changed
    (tmp_path / "broker_audit.jsonl").write_bytes(bytes(data))
    bad = score(expected(audit_events=["release"]), broker_events=DENY, trace_ids=["t"], log_dir=tmp_path,
                audit_real=True, public_key_path=pub)
    assert bad["matched"] is False and any("does not verify" in p for p in bad["problems"])


def test_live_model_scenarios_are_not_scored_automatically():
    out = score(expected(decisions=None), broker_events=[], trace_ids=["t"], log_dir=Path("."),
                audit_real=True, public_key_path=Path("x"))
    assert out["matched"] is None and out["expected"] is None


# --- the scripted sender's broker path, checked by Kissa's real verifier --------------------------

@pytest.fixture
def keys(tmp_path):
    spec = importlib.util.spec_from_file_location("issue_credentials_attacks",
                                                  REPO_ROOT / "scripts" / "issue_credentials.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path / "run-keys"
    module.write_set(out, module.credential_set(), force=False)
    return out


def envelope(sender="research"):
    from contracts import new_request
    return json.loads(new_request(sender=sender, receiver="tool", action="file.read_internal",
                                  resource="file:/internal/q3_report.txt", payload={},
                                  chain_so_far=["user"]).model_dump_json())


@pytest.mark.parametrize("step, code", [
    ({"token": "valid"}, None),
    ({"token": "expired"}, "TOKEN_EXPIRED"),
    ({"token": "stolen"}, "PROOF_KEY_MISMATCH"),
    ({"token": "missing"}, "TOKEN_MISSING"),
    ({"token": "reissued", "token_epoch": 1}, "STALE_EPOCH"),          # registry epoch is still 0
])
def test_broker_token_modes(keys, step, code):
    from agents.scripted import _broker_auth
    from broker.identity.registry import AgentRegistry
    from broker.identity.verify import IdentityVerifier
    from contracts import Envelope
    env = envelope()
    headers = _broker_auth(step, env, "research", keys)
    result = IdentityVerifier(AgentRegistry.from_credentials_dir(keys)).verify(headers, Envelope.model_validate(env))
    assert result.reason_code == code and result.ok is (code is None)


def test_a_reissued_token_for_a_revoked_agent_is_refused(keys):
    from agents.scripted import _broker_auth
    from broker.identity.registry import AgentRegistry
    from broker.identity.verify import IdentityVerifier
    from contracts import Envelope
    registry = AgentRegistry.from_credentials_dir(keys)
    registry.revoke("research")                                          # epoch 0 -> 1, status revoked
    verifier = IdentityVerifier(registry)
    env = envelope()
    new = verifier.verify(_broker_auth({"token": "reissued", "token_epoch": 1}, env, "research", keys),
                          Envelope.model_validate(env))
    assert new.reason_code == "AGENT_REVOKED"
    registry.restore("research")
    env = envelope()
    assert verifier.verify(_broker_auth({"token": "reissued", "token_epoch": 1}, env, "research", keys),
                           Envelope.model_validate(env)).ok


# --- the forwarding secret ------------------------------------------------------------------------

def test_the_forwarding_secret_reaches_the_broker_and_agents_only(tmp_path):
    tb = Testbed(TestbedConfig(agents=[{"name": "database"}], run_dir=tmp_path, mode="broker",
                               broker_real=["identity"]))
    tb._plan()
    try:
        secret = tb.forward_token
        assert secret and len(secret) >= 32 and secret != tb.admin_token
        assert tb.procs["broker"].env["BROKER_FORWARD_TOKEN"] == secret
        assert tb.procs["database"].env["BROKER_FORWARD_TOKEN"] == secret
        assert "BROKER_FORWARD_TOKEN" not in tb.procs["mocks"].env
    finally:
        tb.stop()


def test_direct_mode_has_no_forwarding_secret(tmp_path):
    tb = Testbed(TestbedConfig(agents=[{"name": "database"}], run_dir=tmp_path))
    tb._plan()
    assert tb.forward_token is None and all("BROKER_FORWARD_TOKEN" not in p.env for p in tb.procs.values())


# --- end to end: A9 through a real broker ---------------------------------------------------------

def test_a9_end_to_end_and_no_secret_is_written(tmp_path, monkeypatch):
    import runner.processes as processes
    from runner.__main__ import main
    markers = iter(["ADMIN-MARKER-PLACEHOLDER-0001", "FORWARD-MARKER-PLACEHOLDER-0002"])
    monkeypatch.setattr(processes.secrets, "token_urlsafe", lambda n: next(markers))
    results = tmp_path / "results"
    assert main(["--results-dir", str(results), "--mode", "broker", "--llm", "fake", "--reps", "1",
                 "--scenario", "A9"]) == 0
    [run] = list(results.iterdir())
    [s] = [json.loads(line) for line in (run / "broker_score.jsonl").read_text(encoding="utf-8").splitlines()]
    assert s["matched"] is True and s["audit_ok"] is True and s["audit_events"] == ["quarantine", "release"]
    assert s["decisions"][-1] == ["QUARANTINE", "AGENT_QUARANTINED"]
    text = "".join(p.read_text(encoding="utf-8", errors="replace") for p in run.rglob("*") if p.is_file())
    assert "ADMIN-MARKER" not in text and "FORWARD-MARKER" not in text      # never in results or logs
    # The attacker's config (part of the text above) has the broker's address and the run's keys
    # folder, and no admin step: the runner makes the release call itself.
    script_cfg = json.loads(next(run.rglob("script_config.json")).read_text(encoding="utf-8"))
    assert {"broker_url", "keys_dir"} <= set(script_cfg) and all("admin" not in s for s in script_cfg["steps"])
