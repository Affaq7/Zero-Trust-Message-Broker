"""K-R2: docs/scenario-control-map.md stays consistent with the scenarios, the spec and the code."""

import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity.client import make_proof
from broker.identity.registry import AgentRegistry
from broker.identity.tokens import issue_expired_token, issue_token
from broker.identity.verify import IdentityResult, IdentityVerifier
from broker.policy.engine import PolicyEngine
from contracts import new_request

REPO_ROOT = Path(__file__).resolve().parents[2]
MAP = (REPO_ROOT / "docs" / "scenario-control-map.md").read_text(encoding="utf-8")
SPEC = (REPO_ROOT / "docs" / "identity-spec.md").read_text(encoding="utf-8")
DECISIONS = {"ALLOW", "SANITIZE", "HITL", "DENY", "QUARANTINE", "none"}


def map_rows() -> dict[str, dict[str, str]]:
    """The rows of the table in section 1, keyed by scenario ID."""
    section = MAP.split("## 1. The map", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 6 and re.fullmatch(r"[NAP]\d+", cells[0]):
            assert cells[0] not in rows, f"{cells[0]} listed twice"
            rows[cells[0]] = dict(zip(("threat", "control", "decision", "code", "fyp1"), cells[1:]))
    return rows


ROWS = map_rows()


def code_of(scenario: str) -> str | None:
    cell = ROWS[scenario]["code"]
    return None if cell == "none" else cell.strip("`")


def test_every_scenario_file_is_in_the_map_exactly_once():
    ids = {json.loads(p.read_text(encoding="utf-8"))["id"] for p in (REPO_ROOT / "scenarios").glob("*.json")}
    assert len(ids) == 19
    assert set(ROWS) == ids


@pytest.mark.parametrize("scenario", sorted(ROWS))
def test_one_decision_and_a_code_from_the_spec(scenario):
    row = ROWS[scenario]
    assert row["decision"] in DECISIONS, f"{scenario}: one decision, got {row['decision']!r}"
    code = code_of(scenario)
    if row["decision"] == "none":
        assert code is None
    else:
        assert code and f"`{code}`" in SPEC, f"{scenario}: {code} is not defined in identity-spec.md"
    assert row["fyp1"] in {"yes", "no"}
    assert row["threat"] and row["control"]


def test_sixteen_scenarios_run_in_fyp1():
    assert {s for s, r in ROWS.items() if r["fyp1"] == "no"} == {"A3", "A11", "A12"}


def test_attack_rows_name_an_owasp_agentic_class():
    for scenario, row in ROWS.items():
        if scenario.startswith("A"):
            assert re.search(r"\bASI(0[1-9]|10)\b", row["threat"]), scenario


# --- the rows Kissa's modules decide match what the code really returns ---------------------

@pytest.fixture
def setup():
    keys = {role: Ed25519PrivateKey.generate() for role in ("planner", "research", "database", "tool", "mailer")}
    registry = AgentRegistry()
    for role, key in keys.items():
        registry.add_instance(role, role, f"{role}-1", key.public_key())
    return keys, registry


def scenario_request(scenario_id):
    data = json.loads((REPO_ROOT / "scenarios" / f"{scenario_id.lower()}.json").read_text(encoding="utf-8"))
    step = data["scripted"]["steps"][0]
    sender = data["scripted"]["sender"]
    chain = step.get("delegation_chain") or ["user", sender]
    return new_request(sender=sender, receiver=step["receiver"], action=step["action"],
                       resource=step["resource"], payload=step["payload"], chain_so_far=chain[:-1])


def verified(agent):
    return IdentityResult(ok=True, agent=agent, role=agent, instance_id=f"{agent}-1", epoch=0, reason_code=None)


@pytest.mark.parametrize("scenario", ["A1", "A5", "A8", "A13"])
def test_policy_rows_match_the_engine(setup, scenario):
    _, registry = setup
    env = scenario_request(scenario)
    result = PolicyEngine(registry).evaluate(env, verified(env.sender))
    assert (result.verdict, result.reason_code) == (ROWS[scenario]["decision"], code_of(scenario))


def test_a7_row_matches_the_engine(setup):
    _, registry = setup
    relayed = new_request(sender="planner", receiver="database", action="db.query_rows", resource="db:employees",
                          payload={"columns": ["ssn"]}, chain_so_far=["user", "research"])
    result = PolicyEngine(registry).evaluate(relayed, verified("planner"))
    assert (ROWS["A7"]["decision"], result.verdict, result.reason_code) == ("DENY", "DENY", code_of("A7"))


def test_a3_row_matches_the_engine(setup):
    _, registry = setup
    env = new_request(sender="planner", receiver="tool", action="tool.send_email_external",
                      resource="email:external",
                      payload={"to": ["records-backup@evil.example"], "subject": "s", "body": "b"},
                      chain_so_far=["user"])
    result = PolicyEngine(registry).evaluate(env, verified("planner"))
    assert ROWS["A3"]["decision"] == "HITL"
    assert (result.needs_human, result.reason_code) == (True, code_of("A3"))


@pytest.mark.parametrize("scenario", ["A6", "A10", "A14"])
def test_identity_rows_match_the_verifier(setup, scenario):
    keys, registry = setup
    env = scenario_request("A6" if scenario == "A6" else "A1")
    key = keys[env.sender]
    if scenario == "A6":
        token = issue_expired_token(key, agent=env.sender, role=env.sender)
    else:
        token = issue_token(key, agent=env.sender, role=env.sender)
    signer = Ed25519PrivateKey.generate() if scenario == "A14" else key   # A14: thief signs with own key
    if scenario == "A10":
        registry.revoke(env.sender)
    headers = {"Authorization": f"Bearer {token}", "X-Agent-Proof": make_proof(env, token, signer)}
    result = IdentityVerifier(registry).verify(headers, env)
    assert ROWS[scenario]["decision"] == "DENY"
    assert result.reason_code == code_of(scenario)


# --- section 6: TC-001 to TC-007 point at tests that exist ---------------------------------------

def tc_rows() -> dict[str, list[str]]:
    section = MAP.split("## 6. Test cases", 1)[1]
    rows = {}
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and re.fullmatch(r"TC-00[1-7]", cells[0]):
            rows[cells[0]] = re.findall(r"`(test_\w+\.py)::(test_\w+)`", cells[2])
    return rows


def test_tc_001_to_007_are_all_mapped():
    rows = tc_rows()
    assert sorted(rows) == [f"TC-00{i}" for i in range(1, 8)]
    assert all(rows.values()), "every TC names at least one test"


@pytest.mark.parametrize("tc", [f"TC-00{i}" for i in range(1, 8)])
def test_every_named_test_exists(tc):
    for filename, name in tc_rows()[tc]:
        path = REPO_ROOT / "tests" / "test_broker" / filename
        assert path.exists(), f"{tc}: {filename} does not exist"
        assert re.search(rf"^def {name}\(", path.read_text(encoding="utf-8"), re.M), f"{tc}: {filename}::{name} not found"
