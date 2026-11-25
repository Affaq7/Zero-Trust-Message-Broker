"""K2: verify_identity() (broker/identity/verify.py).

Section 1 holds the 9 cases of the proof of concept (report Appendix A, Table 8),
mapped to the spec's reason codes. Section 2 covers every other identity code in
the order of docs/identity-spec.md section 7.
"""

import importlib.util
import time
import uuid
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity import verify as verify_module
from broker.identity.client import envelope_hash, make_proof, token_hash
from broker.identity.keys import jwk_thumbprint
from broker.identity.registry import AgentRegistry
from broker.identity.tokens import issue_expired_token, issue_token
from broker.identity.verify import (
    IDENTITY_REASON_CODES,
    IdentityResult,
    IdentityVerifier,
    verify_identity,
)
from contracts import new_request
from contracts.tokens import BROKER_AUDIENCE, BROKER_ISSUER, PROOF_STUB_VALUE
from wrapper.credentials import load_credentials

NOW = 1_800_000_000
KEYS = {name: Ed25519PrivateKey.generate() for name in ("planner", "research-1", "research-2", "database")}


def jkt(key):
    return jwk_thumbprint(key.public_key())


@pytest.fixture
def registry():
    reg = AgentRegistry()
    reg.add_instance("planner", "planner", "planner-1", KEYS["planner"].public_key())
    reg.add_instance("research", "research", "research-1", KEYS["research-1"].public_key())
    reg.add_instance("research", "research", "research-2", KEYS["research-2"].public_key())
    reg.add_instance("database", "database", "database-1", KEYS["database"].public_key())
    return reg


@pytest.fixture
def verifier(registry):
    return IdentityVerifier(registry)


def request(sender="planner", receiver="database", action="db.query_aggregate", chain=("user",)):
    return new_request(sender=sender, receiver=receiver, action=action, resource="db:project_costs",
                       payload={"metric": "sum", "column": "amount"}, chain_so_far=list(chain))


def token_for(key_name="planner", agent="planner", role="planner", now=NOW, epoch=0):
    return issue_token(KEYS[key_name], agent=agent, role=role, epoch=epoch, now=now)


def signed_token(key, kid=None, **overrides):
    """A token with any claim overridden (None removes it), signed with ``key``."""
    claims = {"iss": BROKER_ISSUER, "aud": BROKER_AUDIENCE, "sub": "planner", "role": "planner",
              "iat": NOW, "nbf": NOW, "exp": NOW + 3600, "jti": str(uuid.uuid4()), "epoch": 0,
              "cnf": {"jkt": jkt(key)}}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"typ": "JWT", "kid": kid or jkt(key)})


def signed_proof(key, typ="ztb-proof+jwt", **claims):
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"typ": typ})


def proof_claims(env, token, **overrides):
    claims = {"jti": str(uuid.uuid4()), "iat": NOW, "aud": BROKER_AUDIENCE, "ath": token_hash(token),
              "msg_hash": envelope_hash(env), "trace_id": env.trace_id}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def headers(token, proof):
    return {"Authorization": f"Bearer {token}", "X-Agent-Proof": proof}


def send(verifier, env, token=None, key_name="planner", now=NOW, proof_now=None):
    token = token or token_for(key_name)
    proof = make_proof(env, token, KEYS[key_name], now=NOW if proof_now is None else proof_now)
    return verifier.verify(headers(token, proof), env, now=now)


def code(result: IdentityResult) -> str | None:
    assert result.ok is (result.reason_code is None)
    return result.reason_code


# === 1. The 9 proof-of-concept cases (report Table 8) ====================================

def test_poc1_legitimate_message_is_accepted(verifier):
    result = send(verifier, request())
    assert result == IdentityResult(ok=True, agent="planner", role="planner", instance_id="planner-1",
                                    epoch=0, reason_code=None)


def test_poc2_replayed_proof(verifier):
    env, token = request(), token_for()
    hdrs = headers(token, make_proof(env, token, KEYS["planner"], now=NOW))
    assert verifier.verify(hdrs, env, now=NOW).ok
    assert code(verifier.verify(hdrs, env, now=NOW + 1)) == "PROOF_REPLAY"


def test_poc3_tampered_payload(verifier):
    env, token = request(), token_for()
    proof = make_proof(env, token, KEYS["planner"], now=NOW)
    tampered = env.model_copy(update={"payload": {"metric": "count", "drop": "everything"}})
    assert code(verifier.verify(headers(token, proof), tampered, now=NOW)) == "MSG_HASH_MISMATCH"


def test_poc4_a14_stolen_token_with_the_thiefs_own_key(verifier):
    env, stolen = request(), token_for()
    thief = Ed25519PrivateKey.generate()
    proof = make_proof(env, stolen, thief, now=NOW)
    assert code(verifier.verify(headers(stolen, proof), env, now=NOW)) == "PROOF_KEY_MISMATCH"


def test_poc5_message_redirected_to_another_receiver(verifier):
    """The receiver is inside the signed envelope hash, so redirecting breaks the proof."""
    env, token = request(receiver="database"), token_for()
    proof = make_proof(env, token, KEYS["planner"], now=NOW)
    redirected = env.model_copy(update={"receiver": "tool"})
    assert code(verifier.verify(headers(token, proof), redirected, now=NOW)) == "MSG_HASH_MISMATCH"


def test_poc6_algorithm_none_token(verifier):
    forged = jwt.encode({"iss": BROKER_ISSUER, "sub": "planner", "aud": BROKER_AUDIENCE},
                        key=None, algorithm="none", headers={"typ": "JWT"})
    assert code(send(verifier, request(), token=forged)) == "BAD_ALGORITHM"


def test_poc7_a6_expired_token(verifier):
    expired = issue_expired_token(KEYS["planner"], agent="planner", role="planner", now=NOW)
    assert code(send(verifier, request(), token=expired)) == "TOKEN_EXPIRED"


def test_poc8_a10_revoked_agent(verifier, registry):
    """A10 (K-R2): the first message after revoke() is STALE_EPOCH."""
    env = request()
    registry.revoke("planner")
    assert code(send(verifier, env)) == "STALE_EPOCH"                  # old epoch-0 token
    assert code(send(verifier, env, token=token_for(epoch=1))) == "AGENT_REVOKED"  # new token, still revoked
    registry.restore("planner")
    assert code(send(verifier, env)) == "STALE_EPOCH"                  # old token stays dead
    assert send(verifier, env, token=token_for(epoch=1)).ok           # re-issued token works


def test_poc9_suspended_agent(verifier, registry):
    registry.suspend("planner")
    assert code(send(verifier, request())) == "AGENT_SUSPENDED"
    registry.restore("planner")
    assert send(verifier, request()).ok                                # same token valid again


# === 2. Every other identity code, in check order ========================================

@pytest.mark.parametrize("value", [None, "", "Bearer", "Bearer ", "Basic abc", "Bearer a b"])
def test_token_missing(verifier, value):
    hdrs = {"X-Agent-Proof": "x"} if value is None else {"Authorization": value, "X-Agent-Proof": "x"}
    assert code(verifier.verify(hdrs, request(), now=NOW)) == "TOKEN_MISSING"


@pytest.mark.parametrize("token", ["not-a-jwt", "a.b.c", "e30"])
def test_token_malformed_when_it_does_not_decode(verifier, token):
    assert code(send(verifier, request(), token=token)) == "TOKEN_MALFORMED"


@pytest.mark.parametrize("bad_char", ["!", "+", "="])
def test_token_with_a_character_outside_base64url_is_malformed(verifier, bad_char):
    head, body, sig = token_for().split(".")
    token = f"{head}.{body[:10]}{bad_char}{body[10:]}.{sig}"
    assert code(send(verifier, request(), token=token)) == "TOKEN_MALFORMED"


def test_bad_algorithm_hs256(verifier):
    token = jwt.encode({"sub": "planner"}, "secret" * 8, algorithm="HS256")
    assert code(send(verifier, request(), token=token)) == "BAD_ALGORITHM"


@pytest.mark.parametrize("sub", ["malicious", "ghost", 42, None])
def test_unknown_agent(verifier, sub):
    token = signed_token(KEYS["planner"], sub=sub)
    assert code(send(verifier, request(), token=token)) == "UNKNOWN_AGENT"


def test_bad_signature_when_kid_is_not_a_key_of_that_agent(verifier):
    outsider = Ed25519PrivateKey.generate()
    assert code(send(verifier, request(), token=signed_token(outsider))) == "BAD_SIGNATURE"


def test_bad_signature_when_kid_names_the_real_key_but_another_key_signed(verifier):
    forger = Ed25519PrivateKey.generate()
    token = signed_token(forger, kid=jkt(KEYS["planner"]), cnf={"jkt": jkt(KEYS["planner"])})
    assert code(send(verifier, request(), token=token)) == "BAD_SIGNATURE"


def test_bad_signature_when_research_key_signs_a_planner_token(verifier):
    token = signed_token(KEYS["research-1"])          # sub planner, but research's key
    assert code(send(verifier, request(), token=token)) == "BAD_SIGNATURE"


@pytest.mark.parametrize("overrides", [
    {"epoch": None},                                   # epoch missing
    {"epoch": -1},
    {"jti": None},
    {"role": "admin"},                                 # not a catalog role
    {"trust_score": 0.9},                              # extra claim
    {"cnf": {"jkt": "A" * 43}},                        # cnf.jkt is not the signing key
    {"exp": NOW + 3601},                               # lifetime over 3600 s
])
def test_token_malformed_claims(verifier, overrides):
    token = signed_token(KEYS["planner"], **overrides)
    assert code(send(verifier, request(), token=token)) == "TOKEN_MALFORMED"


def test_wrong_issuer(verifier):
    token = signed_token(KEYS["planner"], iss="https://evil.example")
    assert code(send(verifier, request(), token=token)) == "WRONG_ISSUER"


def test_wrong_audience_for_a_direct_mode_style_token(verifier):
    token = signed_token(KEYS["planner"], aud="database")
    assert code(send(verifier, request(), token=token)) == "WRONG_AUDIENCE"


@pytest.mark.parametrize("exp_offset, expected", [(-6, "TOKEN_EXPIRED"), (-5, "TOKEN_EXPIRED"), (-4, None)])
def test_expiry_has_five_seconds_leeway(verifier, exp_offset, expected):
    token = signed_token(KEYS["planner"], iat=NOW - 3000, nbf=NOW - 3000, exp=NOW + exp_offset)
    assert code(send(verifier, request(), token=token)) == expected


@pytest.mark.parametrize("field, offset, expected", [
    ("nbf", 6, "TOKEN_NOT_YET_VALID"), ("nbf", 5, None),
    ("iat", 6, "TOKEN_NOT_YET_VALID"), ("iat", 5, None),
])
def test_not_yet_valid_has_five_seconds_leeway(verifier, field, offset, expected):
    times = {"iat": NOW, "nbf": NOW, "exp": NOW + 3000}
    times[field] = NOW + offset
    token = signed_token(KEYS["planner"], **times)
    assert code(send(verifier, request(), token=token)) == expected


def test_sub_mismatch_when_planner_token_sends_as_research(verifier):
    env = request(sender="research", receiver="database")
    assert code(send(verifier, env, token=token_for())) == "SUB_MISMATCH"


def test_role_mismatch_when_token_claims_another_catalog_role(verifier):
    token = signed_token(KEYS["planner"], role="research")
    assert code(send(verifier, request(), token=token)) == "ROLE_MISMATCH"


@pytest.mark.parametrize("proof", [None, "", PROOF_STUB_VALUE])
def test_proof_missing(verifier, proof):
    hdrs = {"Authorization": f"Bearer {token_for()}"}
    if proof is not None:
        hdrs["X-Agent-Proof"] = proof
    assert code(verifier.verify(hdrs, request(), now=NOW)) == "PROOF_MISSING"


@pytest.mark.parametrize("typ, overrides", [
    ("JWT", {}),                                       # wrong typ
    ("ztb-proof+jwt", {"trace_id": None}),             # missing claim
    ("ztb-proof+jwt", {"extra": "x"}),                 # extra claim
    ("ztb-proof+jwt", {"iat": True}),                  # bool is not a time
    ("ztb-proof+jwt", {"iat": "1800000000"}),
    ("ztb-proof+jwt", {"jti": ""}),
])
def test_proof_malformed_claims_or_type(verifier, typ, overrides):
    env, token = request(), token_for()
    proof = signed_proof(KEYS["planner"], typ=typ, **proof_claims(env, token, **overrides))
    assert code(verifier.verify(headers(token, proof), env, now=NOW)) == "PROOF_MALFORMED"


@pytest.mark.parametrize("proof", ["garbage", "a.b.c"])
def test_proof_malformed_when_it_does_not_decode(verifier, proof):
    assert code(verifier.verify(headers(token_for(), proof), request(), now=NOW)) == "PROOF_MALFORMED"


def test_proof_with_hs256_is_malformed(verifier):
    env, token = request(), token_for()
    proof = jwt.encode(proof_claims(env, token), "secret" * 8, algorithm="HS256",
                       headers={"typ": "ztb-proof+jwt"})
    assert code(verifier.verify(headers(token, proof), env, now=NOW)) == "PROOF_MALFORMED"


def test_proof_signed_by_the_other_research_instance_is_a_key_mismatch(verifier):
    env = request(sender="research", receiver="database")
    token = token_for("research-1", agent="research", role="research")
    proof = make_proof(env, token, KEYS["research-2"], now=NOW)
    assert code(verifier.verify(headers(token, proof), env, now=NOW)) == "PROOF_KEY_MISMATCH"


@pytest.mark.parametrize("proof_offset, expected", [
    (-31, "PROOF_STALE"), (-30, None), (5, None), (6, "PROOF_STALE"),
])
def test_proof_is_accepted_for_30_seconds_only(verifier, proof_offset, expected):
    assert code(send(verifier, request(), proof_now=NOW + proof_offset)) == expected


def test_proof_with_wrong_audience(verifier):
    env, token = request(), token_for()
    proof = signed_proof(KEYS["planner"], **proof_claims(env, token, aud="database"))
    assert code(verifier.verify(headers(token, proof), env, now=NOW)) == "WRONG_AUDIENCE"


def test_proof_made_for_another_token_of_the_same_agent(verifier):
    env, token, other = request(), token_for(), token_for(now=NOW - 10)
    proof = make_proof(env, other, KEYS["planner"], now=NOW)
    assert code(verifier.verify(headers(token, proof), env, now=NOW)) == "PROOF_TOKEN_MISMATCH"


def test_trace_id_claim_must_match_the_envelope(verifier):
    env, token = request(), token_for()
    proof = signed_proof(KEYS["planner"], **proof_claims(env, token, trace_id="other-trace"))
    assert code(verifier.verify(headers(token, proof), env, now=NOW)) == "MSG_HASH_MISMATCH"


def test_rejected_proof_is_not_recorded_as_used(verifier):
    """A proof that fails before the replay check is not burnt: the honest envelope still passes."""
    env, token = request(), token_for()
    proof = make_proof(env, token, KEYS["planner"], now=NOW)
    tampered = env.model_copy(update={"payload": {"metric": "count"}})
    assert code(verifier.verify(headers(token, proof), tampered, now=NOW)) == "MSG_HASH_MISMATCH"
    assert verifier.verify(headers(token, proof), env, now=NOW).ok


def test_replay_after_the_window_is_stale_not_accepted(verifier):
    env, token = request(), token_for()
    hdrs = headers(token, make_proof(env, token, KEYS["planner"], now=NOW))
    assert verifier.verify(hdrs, env, now=NOW).ok
    assert code(verifier.verify(hdrs, env, now=NOW + 61)) == "PROOF_STALE"


# === 3. Other behaviour =====================================================================

def test_second_research_instance_is_identified(verifier):
    env = request(sender="research", receiver="database")
    token = token_for("research-2", agent="research", role="research")
    result = send(verifier, env, token=token, key_name="research-2")
    assert (result.ok, result.agent, result.instance_id) == (True, "research", "research-2")


def test_header_names_are_case_insensitive(verifier):
    env, token = request(), token_for()
    proof = make_proof(env, token, KEYS["planner"], now=NOW)
    assert verifier.verify({"authorization": f"bearer {token}", "x-agent-proof": proof}, env, now=NOW).ok


def test_failure_reveals_no_identity(verifier):
    result = send(verifier, request(), token=signed_token(KEYS["planner"], iss="x"))
    assert (result.agent, result.role, result.instance_id, result.epoch) == (None, None, None, None)


def test_every_code_in_the_spec_is_known():
    spec = (Path(__file__).resolve().parents[2] / "docs" / "identity-spec.md").read_text(encoding="utf-8")
    for reason in IDENTITY_REASON_CODES:
        assert f"`{reason}`" in spec
    assert len(IDENTITY_REASON_CODES) == 21


def test_module_level_verify_identity_uses_the_default_verifier(registry, monkeypatch):
    monkeypatch.setattr(verify_module, "_default", IdentityVerifier(registry))
    env, token = request(), token_for(now=int(time.time()))
    proof = make_proof(env, token, KEYS["planner"])
    assert verify_identity(headers(token, proof), env).ok


def test_average_check_is_under_one_millisecond(verifier):
    """Done when: average time per check under 1 ms in process (token + proof, proofs premade).

    Best of 5 batches, as timeit recommends: a busy laptop can only make a batch
    slower, so the fastest batch measures the code, not the machine's load.
    """
    env, token = request(), token_for(now=int(time.time()))
    batches, per_batch = 5, 200
    averages = []
    for _ in range(batches):
        proofs = [make_proof(env, token, KEYS["planner"]) for _ in range(per_batch)]
        start = time.perf_counter()
        for proof in proofs:
            assert verifier.verify(headers(token, proof), env).ok
        averages.append((time.perf_counter() - start) / per_batch * 1000)
    assert min(averages) < 1.0, f"best batch {min(averages):.3f} ms per check, all {averages}"


def test_issued_credential_files_pass_end_to_end(tmp_path):
    """K1 + K2: credentials from the issue script, proof from FileCredentials, verified against keys/."""
    script = Path(__file__).resolve().parents[2] / "scripts" / "issue_credentials.py"
    spec = importlib.util.spec_from_file_location("issue_credentials", script)
    issue = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(issue)
    keys_dir = tmp_path / "keys"
    assert issue.main(["--out", str(keys_dir)]) == 0
    verifier = IdentityVerifier(AgentRegistry.from_credentials_dir(keys_dir))
    for name, agent in [("planner", "planner"), ("research-2", "research"), ("research-stolen", "research")]:
        creds = load_credentials(agent, agent, environ={"AGENT_CREDENTIALS": name, "AGENT_KEYS_DIR": str(keys_dir)})
        env = request(sender=agent, receiver="database")
        token = creds.token_for("database")
        result = verifier.verify(headers(token, make_proof(env, token, creds.private_key)), env)
        assert result.ok and result.instance_id == creds.instance_id
