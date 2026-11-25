"""Task A3: quarantine (broker/defence/quarantine.py) and revocation (revocation.py).

Done-when: A9 (5 denials in 60 s, then QUARANTINE / AGENT_QUARANTINED, release
restores access) and A10 (revoke, then AGENT_REVOKED; restore without a new
token, then STALE_EPOCH, per docs/identity-spec.md).
"""

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.defence import revocation
from broker.defence.quarantine import (
    AGENT_QUARANTINED, DENIAL_RATE_EXCEEDED, DefenceManager, default_settings, load_settings,
)
from broker.identity.registry import AgentRegistry, UnknownAgentError
from broker.trust.risk import FACTORS
from broker.trust.trust import TrustEngine

LOW = {f: "L" for f in FACTORS}


def deny(dm, agent, times):
    for t in times:
        dm.record_decision(agent, "DENY", t)


# --- settings ---------------------------------------------------------------

def test_approved_settings():
    s = default_settings()
    assert (s["deny_limit"], s["window_seconds"]) == (5, 60)
    assert s["reviewers"] == ["amna", "kissa", "afaq"]


@pytest.mark.parametrize("change", [{"deny_limit": 0}, {"window_seconds": 0}, {"reviewers": []}])
def test_bad_settings_rejected(tmp_path, change):
    import yaml
    s = copy.deepcopy(default_settings()) | change
    p = tmp_path / "d.yaml"
    p.write_text(yaml.safe_dump(s), encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(p)


# --- A9: V1 sliding window ---------------------------------------------------------

def test_a9_fifth_denial_quarantines_and_sixth_message_gets_quarantine():
    dm = DefenceManager()
    deny(dm, "malicious", [0, 1, 2, 3])
    assert not dm.is_blocked("malicious")
    assert dm.check("malicious") is None
    dm.record_decision("malicious", "DENY", 4)
    assert dm.is_blocked("malicious")
    assert dm.check("malicious") == ("QUARANTINE", AGENT_QUARANTINED)
    entry = dm.log()[-1]
    assert entry["kind"] == "quarantine" and entry["reason_code"] == DENIAL_RATE_EXCEEDED
    assert entry["by"] == "broker"
    assert entry["denials"] == [0, 1, 2, 3, 4]


def test_window_edge_sixty_seconds_counts():
    dm = DefenceManager()
    deny(dm, "a", [0, 15, 30, 45, 60])
    assert dm.is_blocked("a")


def test_denials_older_than_the_window_drop_out():
    dm = DefenceManager()
    deny(dm, "a", [0, 15, 30, 45, 60.5])
    assert not dm.is_blocked("a")
    dm.record_decision("a", "DENY", 61)
    assert dm.is_blocked("a")      # 15, 30, 45, 60.5, 61


def test_only_deny_counts():
    dm = DefenceManager()
    for d in ("ALLOW", "SANITIZE", "HITL", "QUARANTINE"):
        for t in range(10):
            dm.record_decision("a", d, t)
    assert not dm.is_blocked("a")


def test_agents_are_counted_separately():
    dm = DefenceManager()
    for t in range(5):
        dm.record_decision("research" if t % 2 else "tool", "DENY", t)
    assert not dm.is_blocked("research") and not dm.is_blocked("tool")


@pytest.mark.parametrize("agent", [None, ""])
def test_unverified_identity_never_counts(agent):
    # Kissa: an identity failure has agent=None; forged messages "from research"
    # must not quarantine the real research agent.
    dm = DefenceManager()
    deny(dm, agent, range(10))
    assert not dm.is_blocked("research")
    assert not dm.is_blocked(agent)
    assert dm.log() == []


def test_settings_are_configurable():
    dm = DefenceManager(settings=default_settings() | {"deny_limit": 2, "window_seconds": 10})
    deny(dm, "a", [0, 11])
    assert not dm.is_blocked("a")
    dm.record_decision("a", "DENY", 12)
    assert dm.is_blocked("a")


# --- release -------------------------------------------------------------------

def test_a9_release_restores_access_and_logs_reviewer():
    dm = DefenceManager()
    deny(dm, "malicious", range(5))
    dm.release("malicious", reviewer="kissa", ts=100)
    assert not dm.is_blocked("malicious")
    assert dm.check("malicious") is None
    assert dm.log()[-1] == {"kind": "release", "agent": "malicious", "by": "kissa", "ts": 100}


def test_after_release_the_window_starts_empty():
    dm = DefenceManager()
    deny(dm, "a", range(5))
    dm.release("a", reviewer="amna")
    deny(dm, "a", [10, 11, 12, 13])
    assert not dm.is_blocked("a")


def test_release_needs_an_allowed_reviewer():
    dm = DefenceManager()
    deny(dm, "a", range(5))
    with pytest.raises(PermissionError):
        dm.release("a", reviewer="malicious")
    assert dm.is_blocked("a")


def test_release_of_an_agent_that_is_not_quarantined_is_refused():
    with pytest.raises(ValueError):
        DefenceManager().release("planner", reviewer="amna")


# --- link with the trust engine (A2) ----------------------------------------------

def quarantined_by_trust(engine, agent):
    for _ in range(13):
        engine.update(agent, "DENY", LOW, False)
    assert engine.get(agent).state == "Quarantined"


def test_trust_quarantine_also_blocks():
    trust = TrustEngine()
    dm = DefenceManager(trust=trust)
    quarantined_by_trust(trust, "x")
    assert dm.is_blocked("x")
    assert dm.check("x") == ("QUARANTINE", AGENT_QUARANTINED)


def test_release_also_releases_the_trust_engine():
    trust = TrustEngine()
    dm = DefenceManager(trust=trust)
    quarantined_by_trust(trust, "x")
    dm.release("x", reviewer="afaq")
    st = trust.get("x")
    assert (st.state, round(st.T, 6)) == ("Restricted", 0.5)
    assert trust.history("x")[-1]["reviewer"] == "afaq"
    assert not dm.is_blocked("x")


def test_v1_block_without_low_trust_still_restarts_in_restricted():
    trust = TrustEngine()
    dm = DefenceManager(trust=trust)
    deny(dm, "x", range(5))            # V1 only; the trust engine saw nothing
    assert trust.get("x").state == "Active"
    assert dm.is_blocked("x")
    dm.release("x", reviewer="amna")
    assert trust.get("x").state == "Restricted"


# --- A10: revocation through Kissa's registry ----------------------------------------

def registry_with(*agents):
    reg = AgentRegistry()
    for name in agents:
        reg.add_instance(name, name, f"{name}-1", Ed25519PrivateKey.generate().public_key())
    return reg


def identity_code(reg, agent, token_epoch):
    """Stand-in for the registry part of Kissa's verify_identity (checks 21 to 23
    in docs/identity-spec.md) until broker/identity/verify.py is on main."""
    r = reg.get(agent)
    if r.status == "revoked":
        return "AGENT_REVOKED"
    if r.status == "suspended":
        return "AGENT_SUSPENDED"
    if token_epoch != r.epoch:
        return "STALE_EPOCH"
    return None


@pytest.fixture
def reg():
    r = registry_with("research", "planner")
    revocation.set_registry(r)
    yield r
    revocation.set_registry(None)


def test_a10_revoke_then_first_message_is_refused(reg):
    token_epoch = reg.get("research").epoch
    assert identity_code(reg, "research", token_epoch) is None
    revocation.revoke("research")
    assert reg.get("research").status == "revoked"
    assert reg.get("research").epoch == token_epoch + 1
    assert identity_code(reg, "research", token_epoch) == "AGENT_REVOKED"


def test_a10_restore_without_new_token_is_stale_epoch(reg):
    old = reg.get("research").epoch
    revocation.revoke("research")
    revocation.restore("research")
    assert reg.get("research").status == "active"
    assert reg.get("research").epoch == old + 1
    assert identity_code(reg, "research", old) == "STALE_EPOCH"
    assert identity_code(reg, "research", old + 1) is None     # a new token works


def test_revoke_only_touches_that_agent(reg):
    revocation.revoke("research")
    assert reg.get("planner").status == "active" and reg.get("planner").epoch == 0


def test_revoke_unknown_agent_raises(reg):
    with pytest.raises(UnknownAgentError):
        revocation.revoke("nobody")


def test_revoke_without_a_registry_fails_loudly():
    revocation.set_registry(None)
    with pytest.raises(RuntimeError):
        revocation.revoke("research")
