"""K1: agent registry (broker/identity/registry.py) and key helpers."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity.keys import (
    jwk_thumbprint,
    private_key_from_text,
    private_key_to_text,
    public_jwk,
    public_key_from_jwk,
)
from broker.identity.registry import AgentRegistry, RegistryError, UnknownAgentError
from wrapper.credentials import jwk_thumbprint as wrapper_thumbprint


def new_key():
    return Ed25519PrivateKey.generate()


def registry_with(*agents: str) -> AgentRegistry:
    reg = AgentRegistry()
    for name in agents:
        reg.add_instance(name, name, f"{name}-1", new_key().public_key())
    return reg


# --- key helpers ----------------------------------------------------------------

def test_thumbprint_matches_the_wrapper_stub():
    key = new_key().public_key()
    assert jwk_thumbprint(key) == wrapper_thumbprint(key)
    assert len(jwk_thumbprint(key)) == 43


def test_public_jwk_round_trip():
    key = new_key().public_key()
    jwk = public_jwk(key)
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519"
    assert jwk_thumbprint(public_key_from_jwk(jwk)) == jwk_thumbprint(key)


def test_private_key_text_round_trip():
    key = new_key()
    again = private_key_from_text(private_key_to_text(key))
    assert jwk_thumbprint(again.public_key()) == jwk_thumbprint(key.public_key())


@pytest.mark.parametrize("jwk", [
    {"kty": "EC", "crv": "Ed25519", "x": "AAAA"},
    {"kty": "OKP", "crv": "X25519", "x": "AAAA"},
    {"kty": "OKP", "crv": "Ed25519"},
    {"kty": "OKP", "crv": "Ed25519", "x": "too-short"},
])
def test_public_key_from_bad_jwk_raises(jwk):
    with pytest.raises(ValueError):
        public_key_from_jwk(jwk)


# --- registration -----------------------------------------------------------------

def test_new_agent_is_active_with_epoch_zero():
    rec = registry_with("planner").get("planner")
    assert (rec.agent_uri, rec.role, rec.status, rec.epoch) == ("planner", "planner", "active", 0)
    assert [i.instance_id for i in rec.instances] == ["planner-1"]


def test_second_instance_has_its_own_key():
    reg = registry_with("research")
    key2 = new_key().public_key()
    rec = reg.add_instance("research", "research", "research-2", key2)
    assert [i.instance_id for i in rec.instances] == ["research-1", "research-2"]
    assert rec.instance_by_jkt(jwk_thumbprint(key2)).instance_id == "research-2"
    assert rec.instance_by_jkt("x" * 43) is None


def test_same_instance_and_key_twice_is_a_no_op():
    reg = AgentRegistry()
    key = new_key().public_key()
    reg.add_instance("research", "research", "research-1", key)
    rec = reg.add_instance("research", "research", "research-1", key)
    assert len(rec.instances) == 1


@pytest.mark.parametrize("agent, role, error", [
    ("nobody", "planner", "unknown agent"),
    ("planner", "admin", "unknown role"),
])
def test_unknown_agent_or_role_rejected(agent, role, error):
    with pytest.raises(RegistryError, match=error):
        AgentRegistry().add_instance(agent, role, "x-1", new_key().public_key())


def test_same_instance_id_with_a_different_key_rejected():
    reg = registry_with("research")
    with pytest.raises(RegistryError, match="different key"):
        reg.add_instance("research", "research", "research-1", new_key().public_key())


def test_role_change_for_a_known_agent_rejected():
    reg = registry_with("research")
    with pytest.raises(RegistryError, match="role"):
        reg.add_instance("research", "planner", "research-2", new_key().public_key())


def test_one_key_cannot_serve_two_instances():
    reg = AgentRegistry()
    key = new_key().public_key()
    reg.add_instance("research", "research", "research-1", key)
    with pytest.raises(RegistryError, match="already registered"):
        reg.add_instance("research", "research", "research-2", key)


def test_records_are_immutable_snapshots():
    reg = registry_with("tool")
    before = reg.get("tool")
    reg.suspend("tool")
    assert before.status == "active"            # old snapshot unchanged
    assert reg.get("tool").status == "suspended"


# --- suspend, revoke, restore (Amna's calls) ---------------------------------------

def test_revoke_raises_epoch_by_one():
    reg = registry_with("research")
    rec = reg.revoke("research")
    assert (rec.status, rec.epoch) == ("revoked", 1)
    assert reg.get("research").epoch == 1


def test_revoke_twice_does_not_raise_epoch_again():
    reg = registry_with("research")
    reg.revoke("research")
    assert reg.revoke("research").epoch == 1


def test_revoke_restore_revoke_raises_epoch_each_time():
    reg = registry_with("research")
    reg.revoke("research")
    reg.restore("research")
    assert reg.revoke("research").epoch == 2


def test_suspend_keeps_epoch_and_restore_reactivates():
    reg = registry_with("database")
    assert (reg.suspend("database").status, reg.get("database").epoch) == ("suspended", 0)
    assert reg.suspend("database").status == "suspended"        # idempotent
    assert (reg.restore("database").status, reg.get("database").epoch) == ("active", 0)


def test_restore_after_revoke_keeps_the_new_epoch():
    reg = registry_with("mailer")
    reg.revoke("mailer")
    rec = reg.restore("mailer")
    assert (rec.status, rec.epoch) == ("active", 1)


def test_suspend_does_not_undo_a_revocation():
    reg = registry_with("tool")
    reg.revoke("tool")
    assert reg.suspend("tool").status == "revoked"


def test_status_calls_on_unknown_agent_raise():
    reg = registry_with("planner")
    for call in (reg.suspend, reg.revoke, reg.restore):
        with pytest.raises(UnknownAgentError):
            call("ghost")
    assert reg.get("ghost") is None
