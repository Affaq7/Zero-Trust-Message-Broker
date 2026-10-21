"""Step 5: JWT claim model, algorithm check and the proof stub.

Keys used here are generated in memory for each test run and never written
to disk.
"""

import secrets

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from contracts import new_request
from contracts.tokens import (
    ALLOWED_ALGORITHMS,
    BROKER_AUDIENCE,
    BROKER_ISSUER,
    PROOF_HEADER,
    PROOF_STUB_VALUE,
    TokenClaims,
    algorithm_allowed,
    make_proof_stub,
    sub_matches_sender,
)

NOW = 1_792_576_800
JKT = "A" * 43


def claims_dict(**overrides):
    data = {
        "sub": "planner", "role": "planner", "iss": "zt-local-issuer",
        "aud": "database", "iat": NOW, "nbf": NOW, "exp": NOW + 300,
        "jti": "j-1", "cnf": {"jkt": JKT},
    }
    data.update(overrides)
    return data


def request_from(sender="planner"):
    return new_request(
        sender=sender, receiver="database", action="db.query_aggregate",
        resource="db:sales", payload={"metric": "count"}, chain_so_far=["user"],
    )


def test_valid_claims_parse():
    claims = TokenClaims.model_validate(claims_dict())
    assert claims.cnf.jkt == JKT


def test_only_eddsa_allowed():
    assert ALLOWED_ALGORITHMS == ("EdDSA",)


def test_agreed_broker_constants():
    assert BROKER_AUDIENCE == "ztbroker"
    assert BROKER_ISSUER == "https://broker.ztbroker.local"
    claims = TokenClaims.model_validate(claims_dict(aud=BROKER_AUDIENCE, iss=BROKER_ISSUER))
    assert (claims.aud, claims.iss) == (BROKER_AUDIENCE, BROKER_ISSUER)


def test_contract_does_not_enforce_iss_or_aud_values():
    # Values are constants only (S9); any non-empty string is still accepted.
    TokenClaims.model_validate(claims_dict(aud="database", iss="some-other-issuer"))


@pytest.mark.parametrize("field", list(claims_dict().keys()))
def test_every_claim_required(field):
    data = claims_dict()
    del data[field]
    with pytest.raises(ValidationError):
        TokenClaims.model_validate(data)


@pytest.mark.parametrize("extra", ["trust_score", "scenario_label", "label"])
def test_extra_claims_forbidden(extra):
    with pytest.raises(ValidationError):
        TokenClaims.model_validate(claims_dict(**{extra: 1}))


@pytest.mark.parametrize("overrides", [
    {"role": "malicious"},              # no such role (Q2/Q13)
    {"role": "admin"},
    {"sub": ""},
    {"aud": ["database", "broker"]},    # single audience only
    {"iat": True},                       # bool is not a NumericDate
    {"exp": float(NOW + 300)},
    {"exp": NOW - 1},                    # exp before iat
    {"nbf": NOW + 300},                  # nbf == exp
    {"cnf": {"jkt": "short"}},
    {"cnf": {"jkt": JKT, "x5t": "y"}},
    {"cnf": {}},
])
def test_invalid_claims_rejected(overrides):
    with pytest.raises(ValidationError):
        TokenClaims.model_validate(claims_dict(**overrides))


@pytest.mark.parametrize("now, leeway, expected", [
    (NOW, 0, []),
    (NOW + 299, 0, []),
    (NOW - 1, 0, ["token not yet valid (nbf)"]),
    (NOW - 5, 10, []),
    (NOW + 300, 0, ["token expired (exp)"]),
    (NOW + 305, 10, []),
])
def test_time_problems(now, leeway, expected):
    assert TokenClaims.model_validate(claims_dict()).time_problems(now, leeway) == expected


def test_sub_must_match_sender():
    claims = TokenClaims.model_validate(claims_dict(sub="planner"))
    assert sub_matches_sender(claims, request_from("planner"))
    assert not sub_matches_sender(claims, request_from("research"))


def test_eddsa_token_round_trip_with_in_memory_key():
    key = Ed25519PrivateKey.generate()
    token = jwt.encode(claims_dict(), key, algorithm="EdDSA")
    assert algorithm_allowed(token)
    decoded = jwt.decode(
        token, key.public_key(), algorithms=list(ALLOWED_ALGORITHMS),
        audience="database", options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert TokenClaims.model_validate(decoded) == TokenClaims.model_validate(claims_dict())


@pytest.mark.parametrize("token", [
    jwt.encode(claims_dict(), secrets.token_hex(32), algorithm="HS256"),
    jwt.encode(claims_dict(), None, algorithm="none"),
    "not.a.jwt",
    "",
])
def test_non_eddsa_or_garbage_tokens_rejected(token):
    assert not algorithm_allowed(token)


def test_proof_stub_is_marked_and_carries_no_data():
    req = request_from()
    proof = make_proof_stub(req)
    assert PROOF_HEADER == "X-Agent-Proof"
    assert proof == PROOF_STUB_VALUE
    assert "STUB" in proof
    assert req.msg_id not in proof
