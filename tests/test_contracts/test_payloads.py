"""Step 3: per-action payload schemas (provisional) and the response payload."""

import pytest
from pydantic import ValidationError

from contracts.catalog import get_catalog
from contracts.payloads import (
    ACTION_SCHEMAS,
    ResponsePayload,
    UnknownActionError,
    validate_payload,
)

VALID = {
    "db.query_aggregate": {"metric": "sum", "column": "amount", "group_by": ["region"]},
    "db.query_rows": {"columns": ["id", "amount"], "filters": {"region": "EU"}, "limit": 10},
    "db.update_records": {"filters": {"id": 7}, "updates": {"status": "closed"}},
    "file.read_internal": {},
    "file.delete": {"reason": "cleanup"},
    "web.fetch_page": {"max_chars": 5000},
    "tool.send_email_internal": {"to": ["a@corp.local"], "subject": "Hi", "body": "Report"},
    "tool.send_email_external": {"to": ["x@example.com"], "subject": "Hi", "body": "Report"},
    "research.lookup": {"query": "HR policy on remote work", "max_sources": 2},
    "planner.request": {"request": "Please relay a request to the database agent."},
    "mail.deliver": {"to": ["a@corp.local"], "cc": [], "bcc": [], "subject": "Hi", "body": "Report"},
    "admin.change_policy": {"policy_id": "p1", "changes": {"allow_all": True}},
}

INVALID = [
    ("db.query_aggregate", {"metric": "median", "column": "amount"}),
    ("db.query_aggregate", {"metric": "sum"}),                       # needs column
    ("db.query_rows", {"columns": []}),
    ("db.query_rows", {"columns": ["id"], "limit": 0}),
    ("db.query_rows", {"columns": ["id"], "limit": 1001}),
    ("db.query_rows", {"columns": ["id"], "filters": {"x": [1, 2]}}),
    ("db.update_records", {"filters": {"id": 1}, "updates": {}}),
    ("db.update_records", {"updates": {"a": 1}}),                    # filters required
    ("file.read_internal", {"max_bytes": 0}),
    ("file.delete", {"reason": "x" * 501}),
    ("web.fetch_page", {"max_chars": -1}),
    ("tool.send_email_internal", {"to": [], "subject": "s", "body": "b"}),
    ("tool.send_email_internal", {"to": ["not-an-address"], "subject": "s", "body": "b"}),
    ("tool.send_email_external", {"to": ["x@example.com"], "subject": "s" * 201, "body": "b"}),
    ("research.lookup", {"query": "q"}),                                  # max_sources required
    ("planner.request", {}),                                              # request required
    ("mail.deliver", {"cc": ["a@corp.local"], "subject": "s", "body": "b"}),   # to required
    ("admin.change_policy", {"policy_id": "p1", "changes": {}}),
]


def test_schemas_cover_exactly_the_catalog():
    # Keeps payloads.py and action_catalog.yaml from drifting apart.
    assert set(ACTION_SCHEMAS) == get_catalog().names()
    assert set(VALID) == get_catalog().names()


@pytest.mark.parametrize("action", sorted(VALID))
def test_valid_payload_accepted(action):
    assert isinstance(validate_payload(action, VALID[action]), ACTION_SCHEMAS[action])


@pytest.mark.parametrize("action, payload", INVALID)
def test_invalid_payload_rejected(action, payload):
    with pytest.raises(ValidationError):
        validate_payload(action, payload)


@pytest.mark.parametrize("action", sorted(VALID))
@pytest.mark.parametrize("extra", ["trust_score", "scenario_label", "ignore_previous_instructions"])
def test_extra_payload_fields_rejected(action, extra):
    with pytest.raises(ValidationError):
        validate_payload(action, {**VALID[action], extra: "x"})


def test_defaults_applied():
    assert validate_payload("db.query_rows", {"columns": ["id"]}).limit == 100
    assert validate_payload("db.query_aggregate", {"metric": "count"}).column is None
    assert validate_payload("file.read_internal", {}).max_bytes == 65536


def test_update_with_empty_filter_is_schema_valid():
    # "Update every row" is for the broker's policy to judge, not the schema.
    validate_payload("db.update_records", {"filters": {}, "updates": {"a": 1}})


@pytest.mark.parametrize("action", ["db.drop_table", "", "admin.delete_logs"])
def test_unknown_action_raises(action):
    with pytest.raises(UnknownActionError):
        validate_payload(action, {})


@pytest.mark.parametrize("payload", [
    {"status": "ok", "result": {"total": 42}},
    {"status": "ok"},
    {"status": "error", "error": "table not found"},
])
def test_valid_response_payload(payload):
    ResponsePayload.model_validate(payload)


@pytest.mark.parametrize("payload", [
    {"status": "denied"},
    {"status": "error"},
    {"status": "error", "error": ""},
    {"status": "ok", "error": "oops"},
    {"result": 1},
    {"status": "ok", "decision": "ALLOW"},  # broker fields belong on the envelope
])
def test_invalid_response_payload(payload):
    with pytest.raises(ValidationError):
        ResponsePayload.model_validate(payload)
