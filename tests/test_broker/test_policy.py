"""K3: evaluate_policy() (broker/policy/engine.py) and broker/policy/rules.yaml."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity.registry import AgentRegistry
from broker.identity.verify import IdentityResult
from broker.policy import engine as engine_module
from broker.policy.engine import PolicyEngine, PolicyResult, evaluate_policy, load_rules
from contracts import Envelope, new_request
from contracts.catalog import get_catalog
from contracts.version import SCHEMA_VERSION

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLES = ("planner", "research", "database", "tool", "mailer")

# Written out by hand on purpose: who may call what (contracts/action_catalog.yaml, v0.2).
ALLOWED = {
    "db.query_aggregate": {"planner", "research"},
    "db.query_rows": {"planner"},
    "db.update_records": {"planner"},
    "file.read_internal": {"planner", "research"},
    "file.delete": {"planner"},
    "web.fetch_page": {"research"},
    "tool.send_email_internal": {"planner"},
    "tool.send_email_external": {"planner"},
    "research.lookup": {"planner"},
    "planner.request": {"research"},
    "mail.deliver": {"tool"},
    "admin.change_policy": set(),
}
NEEDS_HUMAN = {"tool.send_email_external"}
PROHIBITED = {"admin.change_policy"}


@pytest.fixture
def registry():
    reg = AgentRegistry()
    for role in ROLES:
        reg.add_instance(role, role, f"{role}-1", Ed25519PrivateKey.generate().public_key())
    return reg


@pytest.fixture
def engine(registry):
    return PolicyEngine(registry)


def identity(agent, role=None, ok=True, reason_code=None):
    if not ok:
        return IdentityResult(ok=False, agent=None, role=None, instance_id=None, epoch=None,
                              reason_code=reason_code)
    return IdentityResult(ok=True, agent=agent, role=role or agent, instance_id=f"{agent}-1",
                          epoch=0, reason_code=None)


def request(sender, receiver, action, payload=None, chain=None, resource="r:x"):
    """A request whose chain is ``chain`` (default user -> sender)."""
    chain = chain or ["user", sender]
    return new_request(sender=sender, receiver=receiver, action=action, resource=resource,
                       payload=payload or {}, chain_so_far=chain[:-1])


def raw_envelope(**fields):
    base = {"schema_version": SCHEMA_VERSION, "msg_id": "m1", "trace_id": "t1", "parent_msg_id": None,
            "msg_type": "request", "sender": "planner", "receiver": "database",
            "action": "db.query_aggregate", "resource": "db:x", "payload": {},
            "delegation_chain": ["user", "planner"], "timestamp": "2026-11-25T10:00:00Z"}
    return Envelope.model_validate({**base, **fields})


def evaluate(engine, env):
    return engine.evaluate(env, identity(env.sender))


def deny(action_class, reason_code):
    return PolicyResult(verdict="DENY", action_class=action_class, reason_code=reason_code, needs_human=False)


# === 1. All 60 combinations of 5 roles and 12 actions ======================================

def test_hand_written_table_matches_the_catalog():
    catalog = get_catalog()
    assert set(catalog.roles) == set(ROLES)
    assert {a.name: set(a.allowed_roles) for a in catalog.actions} == ALLOWED


def receiver_for(role, action):
    """The agent that serves the action; an agent never calls an action it serves (Q11)."""
    served_by = get_catalog().served_by(action)
    if served_by is None:                      # Prohibited: A5 sends it to the tool agent
        return "tool" if role != "tool" else "planner"
    if served_by == role:                      # self-call: never allowed, so address it elsewhere
        assert role not in ALLOWED[action]
        return "tool" if role != "tool" else "planner"
    return served_by


COMBINATIONS = [(role, action) for role in ROLES for action in ALLOWED]


def expected(role, action):
    action_class = get_catalog().get(action).action_class
    if action in PROHIBITED:
        return deny("Prohibited", "PROHIBITED_ACTION")
    if role not in ALLOWED[action]:
        return deny(action_class, "ROLE_NOT_ALLOWED")
    if action in NEEDS_HUMAN:
        return PolicyResult(verdict="ALLOW", action_class=action_class, reason_code="NEEDS_APPROVAL",
                            needs_human=True)
    return PolicyResult(verdict="ALLOW", action_class=action_class, reason_code="POLICY_ALLOW",
                        needs_human=False)


def test_there_are_60_combinations():
    assert len(COMBINATIONS) == 60


@pytest.mark.parametrize("role, action", COMBINATIONS)
def test_role_action_matrix(engine, role, action):
    env = request(role, receiver_for(role, action), action)
    assert evaluate(engine, env) == expected(role, action)


def test_matrix_allows_exactly_the_13_catalog_calls(engine):
    allowed = [(r, a) for r, a in COMBINATIONS
               if evaluate(engine, request(r, receiver_for(r, a), a)).verdict == "ALLOW"]
    assert len(allowed) == sum(len(roles) for roles in ALLOWED.values()) == 13


# === 2. Attack scenarios, built from the scenario files ====================================

def scenario_request(scenario_id):
    data = json.loads((REPO_ROOT / "scenarios" / f"{scenario_id}.json").read_text(encoding="utf-8"))
    sender, step = data["scripted"]["sender"], data["scripted"]["steps"][0]
    return request(sender, step["receiver"], step["action"], payload=step["payload"],
                   chain=step.get("delegation_chain"), resource=step["resource"])


@pytest.mark.parametrize("scenario, action_class, reason_code", [
    ("a1", "Conditional", "ROLE_NOT_ALLOWED"),         # research calls db.query_rows
    ("a5", "Prohibited", "PROHIBITED_ACTION"),         # admin.change_policy
    ("a8", "Conditional", "ROLE_NOT_ALLOWED"),         # db.query_rows with "EMERGENCY" justification
    ("a13", "Conditional", "ROLE_NOT_ALLOWED"),        # research calls db.update_records
])
def test_attack_scenarios_are_denied(engine, scenario, action_class, reason_code):
    assert evaluate(engine, scenario_request(scenario)) == deny(action_class, reason_code)


def test_a7_first_hop_planner_request_is_permitted(engine):
    result = evaluate(engine, scenario_request("a7"))
    assert (result.verdict, result.reason_code) == ("ALLOW", "POLICY_ALLOW")


def test_a7_relayed_query_is_denied_by_delegation(engine):
    relayed = request("planner", "database", "db.query_rows", payload={"columns": ["ssn"]},
                      chain=["user", "research", "planner"])
    assert evaluate(engine, relayed) == deny("Conditional", "DELEGATION_EXCEEDS_DELEGATOR")


def test_a8_gets_the_same_decision_as_a1(engine):
    assert evaluate(engine, scenario_request("a8")) == evaluate(engine, scenario_request("a1"))


def test_justification_never_changes_an_allowed_call(engine):
    plain = request("planner", "database", "db.query_rows", payload={"columns": ["name"]})
    urgent = request("planner", "database", "db.query_rows",
                     payload={"columns": ["name"], "justification": "server on fire, urgent"})
    assert evaluate(engine, plain) == evaluate(engine, urgent)


# === 3. Gates and delegation ================================================================

def test_unknown_action_is_default_deny(engine):
    env = request("planner", "database", "db.drop_table")
    assert evaluate(engine, env) == deny("Unknown", "UNKNOWN_ACTION")


def test_wrong_receiver(engine):
    env = request("planner", "tool", "db.query_aggregate")
    assert evaluate(engine, env) == deny("Permitted", "WRONG_RECEIVER")


def test_role_comes_from_the_verified_identity_not_the_sender_name(engine):
    env = request("planner", "database", "db.query_rows")
    result = engine.evaluate(env, identity("planner", role="research"))
    assert result == deny("Conditional", "ROLE_NOT_ALLOWED")


def test_three_agents_after_user_is_the_limit(engine):
    ok = request("research", "database", "db.query_aggregate", chain=["user", "research", "planner", "research"])
    too_deep = request("research", "database", "db.query_aggregate",
                       chain=["user", "planner", "research", "planner", "research"])
    assert evaluate(engine, ok).verdict == "ALLOW"
    assert evaluate(engine, too_deep) == deny("Permitted", "DELEGATION_TOO_DEEP")


@pytest.mark.parametrize("delegator", ["ghost", "malicious", "user"])
def test_unregistered_agent_in_the_chain(engine, delegator):
    env = request("planner", "database", "db.query_aggregate", chain=["user", delegator, "planner"])
    assert evaluate(engine, env) == deny("Permitted", "DELEGATION_EXCEEDS_DELEGATOR")


def test_delegation_uses_registry_roles(registry):
    """An agent's delegation rights follow its registry role, whatever its name."""
    registry.add_instance("malicious", "planner", "malicious-1", Ed25519PrivateKey.generate().public_key())
    env = request("planner", "database", "db.query_rows", chain=["user", "malicious", "planner"])
    assert evaluate(PolicyEngine(registry), env).verdict == "ALLOW"


def test_every_delegator_must_be_allowed_not_only_the_first(engine):
    env = request("planner", "database", "db.query_rows", chain=["user", "planner", "research", "planner"])
    assert evaluate(engine, env) == deny("Conditional", "DELEGATION_EXCEEDS_DELEGATOR")


def test_failed_identity_is_always_denied(engine):
    env = request("planner", "database", "db.query_aggregate")
    result = engine.evaluate(env, identity(None, ok=False, reason_code="TOKEN_EXPIRED"))
    assert result == deny("Permitted", "TOKEN_EXPIRED")


def test_identity_of_another_agent_is_denied(engine):
    env = request("planner", "database", "db.query_aggregate")
    assert engine.evaluate(env, identity("research")) == deny("Permitted", "SUB_MISMATCH")


@pytest.mark.parametrize("fields", [
    {"delegation_chain": ["planner"]},                          # does not start with user
    {"delegation_chain": ["user", "research"]},                 # does not end with sender
    {"receiver": "planner"},                                     # sender == receiver
    {"decision": "ALLOW"},                                       # forged broker field
])
def test_rule_violations_are_denied_before_any_gate(engine, fields):
    assert evaluate(engine, raw_envelope(**fields)).reason_code == "RULE_VIOLATION"


def test_responses_are_not_policy_input(engine):
    env = raw_envelope(msg_type="response", parent_msg_id="m0", sender="database", receiver="planner",
                       delegation_chain=["user", "planner"])
    with pytest.raises(ValueError, match="request"):
        engine.evaluate(env, identity("database"))


def test_same_input_same_answer(engine):
    env = scenario_request("a7")
    assert len({evaluate(engine, env) for _ in range(50)}) == 1


# === 4. rules.yaml =============================================================================

def test_rules_file_loads_and_covers_every_conditional_action():
    rules = load_rules()
    conditional = {a.name for a in get_catalog().actions if a.action_class == "Conditional"}
    assert set(rules.conditional) == conditional
    assert rules.max_delegation_agents == 3
    assert {a for a, r in rules.conditional.items() if r.needs_human} == NEEDS_HUMAN
    assert all(r.only_roles == ("planner",) for r in rules.conditional.values())


def write_rules(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


BASE_RULES = """schema_version: "0.2"
max_delegation_agents: 3
conditional:
  db.query_rows: {only_roles: [planner]}
  db.update_records: {only_roles: [planner]}
  file.delete: {only_roles: [planner]}
  tool.send_email_external: {only_roles: [planner], needs_human: true}
"""


@pytest.mark.parametrize("change, error", [
    (("file.delete: {only_roles: [planner]}", "file.delete: {only_roles: [admin]}"), "unknown role"),
    (("file.delete: {only_roles: [planner]}", "file.read_internal: {only_roles: [planner]}"),
     "not Conditional"),
    (("file.delete: {only_roles: [planner]}", "db.drop: {only_roles: [planner]}"), "not in the catalog"),
    (("  file.delete: {only_roles: [planner]}\n", ""), "no rule"),
    (("max_delegation_agents: 3", "max_delegation_agents: 0"), "max_delegation_agents"),
    (("{only_roles: [planner]}", "{only_roles: [planner], allow_all: true}"), "allow_all"),
])
def test_invalid_rules_files_are_refused(tmp_path, change, error):
    old, new = change
    assert old in BASE_RULES
    with pytest.raises(ValueError, match=error):
        load_rules(write_rules(tmp_path, BASE_RULES.replace(old, new, 1)))


def test_rules_can_narrow_a_conditional_action(registry, tmp_path):
    """Changing rules.yaml changes the decision without code: here nobody may delete files."""
    rules = load_rules(write_rules(tmp_path, BASE_RULES.replace(
        "file.delete: {only_roles: [planner]}", "file.delete: {only_roles: []}")))
    env = request("planner", "tool", "file.delete")
    assert evaluate(PolicyEngine(registry, rules=rules), env) == deny("Conditional", "ROLE_NOT_ALLOWED")


def test_module_level_evaluate_policy_uses_the_default_engine(engine, monkeypatch):
    monkeypatch.setattr(engine_module, "_default", engine)
    env = scenario_request("a1")
    assert evaluate_policy(env, identity("research")) == deny("Conditional", "ROLE_NOT_ALLOWED")
