"""Unit tests for make_expired_token and make_wrong_key_token."""

import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wrapper.credentials import (
    make_expired_token,
    make_stub_token,
    make_wrong_key_token,
)


def test_expired_token_has_exp_in_the_past():
    token = make_expired_token("attacker", "planner", "database")
    claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert claims["exp"] < int(time.time()), "exp should be in the past"
    assert claims["sub"] == "attacker"
    assert claims["role"] == "planner"
    assert claims["aud"] == "database"


def test_expired_token_is_structurally_valid():
    token = make_expired_token("a", "planner", "b")
    claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert claims["iat"] <= claims["exp"]
    assert claims["nbf"] < claims["exp"]
    for field in ("sub", "role", "iss", "aud", "iat", "nbf", "exp", "jti", "cnf"):
        assert field in claims


def test_expired_token_with_explicit_key():
    key = Ed25519PrivateKey.generate()
    t1 = make_expired_token("a", "planner", "b", key=key)
    t2 = make_expired_token("a", "planner", "b", key=key)
    c1 = jwt.decode(t1, options={"verify_signature": False, "verify_exp": False})
    c2 = jwt.decode(t2, options={"verify_signature": False, "verify_exp": False})
    assert c1["cnf"]["jkt"] == c2["cnf"]["jkt"], "same key should produce same thumbprint"


def test_wrong_key_token_is_valid_but_different_key():
    known_key = Ed25519PrivateKey.generate()
    valid = make_stub_token("a", "planner", "b", key=known_key)
    wrong = make_wrong_key_token("a", "planner", "b")
    vc = jwt.decode(valid, options={"verify_signature": False})
    wc = jwt.decode(wrong, options={"verify_signature": False})
    assert vc["cnf"]["jkt"] != wc["cnf"]["jkt"], "wrong-key token should have a different jkt"
    assert wc["exp"] > int(time.time()), "wrong-key token should not be expired"
