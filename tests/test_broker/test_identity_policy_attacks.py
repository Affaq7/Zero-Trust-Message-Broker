"""K5: the attack cases end to end through the broker pipeline, with Kissa's real modules.

Each case uses real credential files from scripts/issue_credentials.py, a real
per-message proof and the attack message from its scenario file. It goes through
broker.pipeline.Broker with the real validate (step 1), identity (step 2) and
policy (step 4) modules, and the reply must carry exactly the decision and
reason code that docs/scenario-control-map.md (K-R2) gives for that scenario.
N1 runs the same way as the control: it must be allowed and forwarded.
No network: the receiver is an in-process mock.
"""

import importlib.util
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity import verify as verify_module
from broker.identity.client import make_proof
from broker.identity.registry import AgentRegistry
from broker.identity.tokens import issue_expired_token
from broker.identity.verify import IdentityVerifier
from broker.intercept import validate as validate_module
from broker.intercept.validate import EnvelopeValidator
from broker.pipeline import Broker, Modules
from broker.policy import engine as engine_module
from broker.policy.engine import PolicyEngine
from contracts import Envelope, make_response, new_request
from contracts.payloads import ResponsePayload
from wrapper.credentials import load_credentials

REPO_ROOT = Path(__file__).resolve().parents[2]
MAP = (REPO_ROOT / "docs" / "scenario-control-map.md").read_text(encoding="utf-8")
AGENT_URLS = {a: f"http://{a}.test" for a in ("planner", "research", "database", "tool", "mailer")}


def map_row(scenario: str) -> tuple[str, str]:
    """(decision, reason code) for ``scenario`` from section 1 of the K-R2 map."""
    section = MAP.split("## 1. The map", 1)[1].split("\n## ", 1)[0]
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 6 and cells[0] == scenario:
            return cells[3], cells[4].strip("`")
    raise KeyError(scenario)


@pytest.fixture
def keys_dir(tmp_path):
    spec = importlib.util.spec_from_file_location("issue_credentials", REPO_ROOT / "scripts" / "issue_credentials.py")
    issue = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(issue)
    out = tmp_path / "keys"
    assert issue.main(["--out", str(out)]) == 0
    return out


@pytest.fixture
def broker(keys_dir, monkeypatch):
    """A broker with Kissa's real steps 1, 2 and 4, all sharing one registry built from keys_dir."""
    registry = AgentRegistry.from_credentials_dir(keys_dir)
    monkeypatch.setattr(verify_module, "_default", IdentityVerifier(registry))
    monkeypatch.setattr(engine_module, "_default", PolicyEngine(registry))
    monkeypatch.setattr(validate_module, "_default", EnvelopeValidator())
    forwarded = []

    def receiver(request):
        env = Envelope.model_validate_json(request.content)
        forwarded.append(env)
        return httpx.Response(200, content=make_response(env, ResponsePayload(status="ok", result=1)).model_dump_json())

    b = Broker(Modules.with_real(["validate", "identity", "policy"]),
               client=httpx.Client(transport=httpx.MockTransport(receiver)), agent_urls=AGENT_URLS)
    b.registry, b.forwarded = registry, forwarded
    real = {n for n, s in b.modules.status.items() if s == "real"}
    assert real >= {"validate_envelope", "verify_identity", "evaluate_policy"}, real
    return b


def creds(keys_dir, name, agent):
    return load_credentials(agent, agent, environ={"AGENT_CREDENTIALS": name, "AGENT_KEYS_DIR": str(keys_dir)})


def scenario_message(scenario: str):
    """The attack request exactly as its scenario file scripts it."""
    data = json.loads((REPO_ROOT / "scenarios" / f"{scenario.lower()}.json").read_text(encoding="utf-8"))
    sender, step = data["scripted"]["sender"], data["scripted"]["steps"][0]
    chain = step.get("delegation_chain") or ["user", sender]
    return new_request(sender=sender, receiver=step["receiver"], action=step["action"],
                       resource=step["resource"], payload=step["payload"], chain_so_far=chain[:-1])


def send(broker, env, token, signer):
    headers = {"Authorization": f"Bearer {token}", "X-Agent-Proof": make_proof(env, token, signer)}
    return broker.handle(json.loads(env.model_dump_json()), headers)


def assert_matches_map(reply, scenario):
    decision, code = map_row(scenario)
    assert (reply.decision, reply.reason_code) == (decision, code), f"{scenario}: map says {decision} {code}"


# === the control ===============================================================================

def test_n1_is_allowed_and_forwarded(broker, keys_dir):
    planner = creds(keys_dir, "planner", "planner")
    env = new_request(sender="planner", receiver="database", action="db.query_aggregate", resource="db:project_costs",
                      payload={"metric": "sum", "column": "amount"}, chain_so_far=["user"])
    reply = send(broker, env, planner.token, planner.private_key)
    assert reply.decision == "ALLOW"
    assert [e.msg_id for e in broker.forwarded] == [env.msg_id]


# === policy attacks: a compromised research agent with its own valid credentials ===============

@pytest.mark.parametrize("scenario", ["A1", "A5", "A8", "A13"])
def test_policy_attack_is_denied_with_the_map_code(broker, keys_dir, scenario):
    research = creds(keys_dir, "research", "research")
    reply = send(broker, scenario_message(scenario), research.token, research.private_key)
    assert_matches_map(reply, scenario)
    assert broker.forwarded == []


def test_a7_first_hop_is_allowed_and_the_relayed_query_is_denied(broker, keys_dir):
    research, planner = creds(keys_dir, "research", "research"), creds(keys_dir, "planner", "planner")
    first = scenario_message("A7")                                   # research -> planner, planner.request
    assert send(broker, first, research.token, research.private_key).decision == "ALLOW"
    relayed = new_request(sender="planner", receiver="database", action="db.query_rows", resource="db:employees",
                          payload={"columns": ["name", "ssn", "home_address"], "limit": 50},
                          chain_so_far=["user", "research"], trace_id=first.trace_id)
    assert_matches_map(send(broker, relayed, planner.token, planner.private_key), "A7")
    assert [e.action for e in broker.forwarded] == ["planner.request"]


# === identity attacks ============================================================================

def test_a6_expired_token(broker, keys_dir):
    planner = creds(keys_dir, "planner", "planner")
    expired = issue_expired_token(planner.private_key, agent="planner", role="planner")
    assert_matches_map(send(broker, scenario_message("A6"), expired, planner.private_key), "A6")
    assert broker.forwarded == []


def test_a14_stolen_token_signed_with_the_thiefs_key(broker, keys_dir):
    stolen = creds(keys_dir, "research-stolen", "research")
    thief_key = Ed25519PrivateKey.generate()
    env = new_request(sender="research", receiver="database", action="db.query_aggregate", resource="db:payroll",
                      payload={"metric": "avg", "column": "salary"}, chain_so_far=["user"])
    assert_matches_map(send(broker, env, stolen.token, thief_key), "A14")
    assert broker.forwarded == []


def test_a10_agent_revoked_mid_session(broker, keys_dir):
    research = creds(keys_dir, "research", "research")

    def env():
        return new_request(sender="research", receiver="database", action="db.query_aggregate",
                           resource="db:project_costs", payload={"metric": "count"}, chain_so_far=["user"])

    assert send(broker, env(), research.token, research.private_key).decision == "ALLOW"
    broker.registry.revoke("research")
    assert_matches_map(send(broker, env(), research.token, research.private_key), "A10")
    assert len(broker.forwarded) == 1                                # only the message before the revocation
