"""Step 1: envelope structure (Envelope) and cross-field rules (rule_violations)."""

import json

import pytest
from pydantic import ValidationError

from contracts import SCHEMA_VERSION, Envelope, rule_violations


def request_dict(**overrides):
    data = {
        "schema_version": "0.2",
        "msg_id": "m-1",
        "trace_id": "t-1",
        "parent_msg_id": None,
        "msg_type": "request",
        "sender": "planner",
        "receiver": "database",
        "action": "db.query_aggregate",
        "resource": "db:sales",
        "payload": {"metric": "sum(amount)"},
        "delegation_chain": ["user", "planner"],
        "timestamp": "2026-10-21T10:00:00Z",
    }
    data.update(overrides)
    return data


def response_dict(**overrides):
    data = request_dict(
        msg_id="m-2",
        parent_msg_id="m-1",
        msg_type="response",
        sender="database",
        receiver="planner",
        payload={"status": "ok", "result": 42, "error": None},
    )
    data.update(overrides)
    return data


# --- structure -------------------------------------------------------------

def test_schema_version_constant():
    assert SCHEMA_VERSION == "0.2"


def test_valid_request_parses_from_dict_and_json():
    env = Envelope.model_validate(request_dict())
    assert env.msg_type == "request"
    assert env.parent_msg_id is None
    assert Envelope.model_validate_json(json.dumps(request_dict())) == env


def test_json_round_trip_keeps_utc_z_timestamp():
    env = Envelope.model_validate(request_dict())
    dumped = env.model_dump(mode="json")
    assert dumped["timestamp"] == "2026-10-21T10:00:00Z"
    assert Envelope.model_validate(dumped) == env


def test_broker_fields_default_to_none():
    env = Envelope.model_validate(request_dict())
    assert env.decision is None
    assert env.reason_code is None
    assert env.redacted_fields is None
    assert env.broker_signature is None


def test_broker_fields_accepted_when_set():
    env = Envelope.model_validate(response_dict(
        decision="SANITIZE", reason_code="PII", redacted_fields=["email"],
        broker_signature="sig",
    ))
    assert env.decision == "SANITIZE"


def test_unknown_decision_rejected():
    with pytest.raises(ValidationError):
        Envelope.model_validate(response_dict(decision="MAYBE"))


@pytest.mark.parametrize("field", list(request_dict().keys()))
def test_every_core_field_is_required(field):
    data = request_dict()
    del data[field]
    with pytest.raises(ValidationError):
        Envelope.model_validate(data)


@pytest.mark.parametrize("field", ["trust_score", "scenario_label", "label", "token"])
def test_extra_fields_forbidden(field):
    # Trust scores, test labels and the JWT must never be in the envelope.
    with pytest.raises(ValidationError):
        Envelope.model_validate(request_dict(**{field: "x"}))


@pytest.mark.parametrize("overrides", [
    {"schema_version": "0.1"},
    {"msg_type": "notify"},
    {"msg_id": ""},
    {"sender": 123},
    {"payload": "not an object"},
    {"delegation_chain": "user"},
])
def test_wrong_types_or_values_rejected(overrides):
    with pytest.raises(ValidationError):
        Envelope.model_validate(request_dict(**overrides))


@pytest.mark.parametrize("ts", ["2026-10-21T10:00:00Z", "2026-10-21T10:00:00+00:00"])
def test_utc_timestamps_accepted(ts):
    Envelope.model_validate(request_dict(timestamp=ts))


@pytest.mark.parametrize("ts", [
    "2026-10-21T10:00:00",        # no timezone
    "2026-10-21T15:00:00+05:00",  # not UTC
    1792576800,                   # Unix number, not ISO 8601
    "yesterday",
])
def test_non_utc_or_non_iso_timestamps_rejected(ts):
    with pytest.raises(ValidationError):
        Envelope.model_validate(request_dict(timestamp=ts))


def test_envelope_is_immutable():
    env = Envelope.model_validate(request_dict())
    with pytest.raises(ValidationError):
        env.sender = "malicious"


def test_structure_alone_accepts_rule_breaking_envelope():
    # Direct mode relies on this: rule checks are separate from parsing.
    env = Envelope.model_validate(request_dict(delegation_chain=["planner"], parent_msg_id="x"))
    assert rule_violations(env)


# --- rules -----------------------------------------------------------------

def test_valid_request_and_response_have_no_violations():
    assert rule_violations(Envelope.model_validate(request_dict())) == []
    assert rule_violations(Envelope.model_validate(response_dict())) == []


def test_longer_chain_ending_with_sender_is_valid():
    env = Envelope.model_validate(request_dict(
        sender="research", delegation_chain=["user", "planner", "research"],
    ))
    assert rule_violations(env) == []


@pytest.mark.parametrize("build, overrides, expected", [
    (request_dict, {"delegation_chain": []}, "must start with 'user'"),
    (request_dict, {"delegation_chain": ["planner"]}, "must start with 'user'"),
    (request_dict, {"receiver": "planner"}, "sender and receiver must differ"),
    (request_dict, {"parent_msg_id": "m-0"}, "parent_msg_id = null"),
    (request_dict, {"delegation_chain": ["user", "research"]}, "must end with sender"),
    (response_dict, {"parent_msg_id": None}, "parent_msg_id set"),
    (response_dict, {"parent_msg_id": "m-2"}, "must differ from msg_id"),
    (response_dict, {"delegation_chain": ["user", "database"]}, "must end with receiver"),
])
def test_rule_violations(build, overrides, expected):
    problems = rule_violations(Envelope.model_validate(build(**overrides)))
    assert any(expected in p for p in problems), problems
