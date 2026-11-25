"""K2: sender-side proof (broker/identity/client.py) and the jti replay cache (replay.py)."""

import base64
import hashlib
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.identity.client import PROOF_TYP, envelope_hash, make_proof, token_hash
from broker.identity.replay import REPLAY_WINDOW_SECONDS, ReplayCache
from broker.identity.tokens import issue_token
from contracts import Envelope, new_request
from contracts.tokens import BROKER_AUDIENCE

NOW = 1_800_000_000


def b64_sha256(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def token(key):
    return issue_token(key, agent="planner", role="planner", now=NOW)


@pytest.fixture
def env():
    return new_request(sender="planner", receiver="database", action="db.query_aggregate",
                       resource="db:project_costs",
                       payload={"metric": "sum", "column": "amount", "filters": {"project": "Project X"}},
                       chain_so_far=["user"])


def decode(proof, key):
    return jwt.decode(proof, key.public_key(), algorithms=["EdDSA"], audience=BROKER_AUDIENCE,
                      options={"verify_iat": False})


# --- envelope_hash ---------------------------------------------------------------------

def test_envelope_hash_survives_the_wire(env):
    back = Envelope.model_validate(json.loads(env.model_dump_json()))
    assert envelope_hash(back) == envelope_hash(env)
    assert len(envelope_hash(env)) == 43


def test_envelope_hash_ignores_broker_fields(env):
    forged = env.model_copy(update={"decision": "ALLOW", "reason_code": "X",
                                    "redacted_fields": ["a"], "broker_signature": "sig"})
    assert envelope_hash(forged) == envelope_hash(env)


@pytest.mark.parametrize("change", [
    {"payload": {"metric": "count"}},
    {"receiver": "tool"},
    {"action": "db.query_rows"},
    {"trace_id": "another-trace"},
    {"delegation_chain": ["user", "research", "planner"]},
])
def test_envelope_hash_changes_with_any_signed_field(env, change):
    assert envelope_hash(env.model_copy(update=change)) != envelope_hash(env)


def test_envelope_hash_is_the_spec_formula(env):
    body = env.model_dump(mode="json", exclude={"decision", "reason_code", "redacted_fields", "broker_signature"})
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert envelope_hash(env) == b64_sha256(raw)


def test_token_hash_is_sha256_of_the_token(token):
    assert token_hash(token) == b64_sha256(token.encode("ascii"))


# --- make_proof -------------------------------------------------------------------------

def test_proof_header_and_claims(env, token, key):
    proof = make_proof(env, token, key, now=NOW)
    header = jwt.get_unverified_header(proof)
    assert (header["alg"], header["typ"]) == ("EdDSA", PROOF_TYP) == ("EdDSA", "ztb-proof+jwt")
    claims = decode(proof, key)
    assert set(claims) == {"jti", "iat", "aud", "ath", "msg_hash", "trace_id"}
    assert claims["iat"] == NOW
    assert claims["aud"] == BROKER_AUDIENCE
    assert claims["ath"] == token_hash(token)
    assert claims["msg_hash"] == envelope_hash(env)
    assert claims["trace_id"] == env.trace_id


def test_proof_is_signed_by_the_given_key_only(env, token, key):
    proof = make_proof(env, token, key, now=NOW)
    with pytest.raises(jwt.InvalidSignatureError):
        decode(proof, Ed25519PrivateKey.generate())


def test_every_proof_has_a_new_jti(env, token, key):
    a, b = (decode(make_proof(env, token, key, now=NOW), key)["jti"] for _ in range(2))
    assert a != b


def test_proof_uses_the_current_time_by_default(env, token, key):
    before = int(time.time())
    iat = decode(make_proof(env, token, key), key)["iat"]
    assert before <= iat <= int(time.time())


# --- ReplayCache ------------------------------------------------------------------------

def test_first_use_is_fresh_and_second_is_a_replay():
    cache = ReplayCache()
    assert cache.seen_or_record("j1", now=NOW) is False
    assert cache.seen_or_record("j1", now=NOW + 1) is True
    assert cache.seen_or_record("j2", now=NOW + 1) is False


def test_entry_lives_exactly_the_window():
    cache = ReplayCache()
    cache.seen_or_record("j1", now=NOW)
    assert REPLAY_WINDOW_SECONDS == 60
    assert cache.seen_or_record("j1", now=NOW + 59) is True
    assert cache.seen_or_record("j1", now=NOW + 60) is False     # expired, recorded again
    assert cache.seen_or_record("j1", now=NOW + 61) is True


def test_a_replay_does_not_extend_the_entry():
    cache = ReplayCache()
    cache.seen_or_record("j1", now=NOW)
    cache.seen_or_record("j1", now=NOW + 50)
    assert cache.seen_or_record("j1", now=NOW + 60) is False


def test_expired_entries_are_removed():
    cache = ReplayCache()
    for i in range(100):
        cache.seen_or_record(f"j{i}", now=NOW)
    assert len(cache) == 100
    cache.seen_or_record("late", now=NOW + REPLAY_WINDOW_SECONDS)
    assert len(cache) == 1
