"""Step 4: new_request() and make_response()."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from contracts import Envelope, EnvelopeRuleError, make_response, new_request, rule_violations
from contracts.payloads import ResponsePayload

OK = ResponsePayload(status="ok", result={"total": 42})


def first_request(**overrides):
    args = dict(
        sender="planner", receiver="database", action="db.query_aggregate",
        resource="db:sales", payload={"metric": "count"}, chain_so_far=["user"],
    )
    args.update(overrides)
    return new_request(**args)


def is_uuid4(value):
    return UUID(value).version == 4


def test_new_request_fills_ids_timestamp_and_chain():
    req = first_request()
    assert req.msg_type == "request"
    assert req.parent_msg_id is None
    assert is_uuid4(req.msg_id) and is_uuid4(req.trace_id)
    assert req.msg_id != req.trace_id
    assert req.delegation_chain == ["user", "planner"]
    assert abs(datetime.now(timezone.utc) - req.timestamp) < timedelta(seconds=5)
    assert req.timestamp.utcoffset() == timedelta(0)
    assert rule_violations(req) == []


def test_new_request_ids_are_unique():
    assert len({first_request().msg_id for _ in range(50)}) == 50


def test_next_hop_appends_itself_and_keeps_trace():
    req = first_request(receiver="research", action="web.fetch_page", resource="https://x")
    hop = new_request(
        sender="research", receiver="tool", action="web.fetch_page",
        resource="https://example.com", payload={}, chain_so_far=req.delegation_chain,
        trace_id=req.trace_id,
    )
    assert hop.delegation_chain == ["user", "planner", "research"]
    assert hop.trace_id == req.trace_id


def test_new_request_round_trips_through_json():
    req = first_request()
    assert Envelope.model_validate_json(req.model_dump_json()) == req


@pytest.mark.parametrize("overrides", [
    {"chain_so_far": []},              # chain would not start with "user"
    {"chain_so_far": ["planner"]},
    {"receiver": "planner"},           # sender == receiver
])
def test_new_request_refuses_rule_breaking_envelopes(overrides):
    with pytest.raises(EnvelopeRuleError):
        first_request(**overrides)


def test_make_response_follows_contract():
    req = first_request()
    resp = make_response(req, OK)
    assert resp.msg_type == "response"
    assert is_uuid4(resp.msg_id) and resp.msg_id != req.msg_id
    assert resp.trace_id == req.trace_id
    assert resp.parent_msg_id == req.msg_id
    assert (resp.sender, resp.receiver) == (req.receiver, req.sender)
    assert (resp.action, resp.resource) == (req.action, req.resource)
    assert resp.delegation_chain == req.delegation_chain
    assert resp.payload == {"status": "ok", "result": {"total": 42}, "error": None}
    assert resp.decision is None and resp.broker_signature is None
    assert resp.timestamp >= req.timestamp
    assert rule_violations(resp) == []


def test_make_response_error_payload():
    resp = make_response(first_request(), ResponsePayload(status="error", error="no table"))
    assert resp.payload["status"] == "error"


def test_cannot_respond_to_a_response():
    resp = make_response(first_request(), OK)
    with pytest.raises(ValueError):
        make_response(resp, OK)


def test_make_response_works_for_rule_breaking_request():
    # Direct mode must still answer requests that break the rules.
    bad = Envelope.model_validate({
        **first_request().model_dump(mode="json"),
        "delegation_chain": ["planner"],
    })
    resp = make_response(bad, OK)
    assert resp.delegation_chain == ["planner"]
    assert rule_violations(resp)
