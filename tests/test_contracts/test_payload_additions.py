"""Additive contract changes (same schema_version "0.2"; S10-S14):
research.lookup, planner.request, mail.deliver, optional justification,
optional cc/bcc, and the single normalize_address helper.
"""

import pytest
from pydantic import ValidationError

from contracts.catalog import get_catalog
from contracts.payloads import (
    ACTION_SCHEMAS,
    EmailPayload,
    MailDeliverPayload,
    PlannerRequestPayload,
    ResearchLookupPayload,
    normalize_address,
    validate_payload,
)

# Minimal valid payload per action (extra-field tests build on these).
BASE = {
    "db.query_aggregate": {"metric": "count"},
    "db.query_rows": {"columns": ["id"]},
    "db.update_records": {"filters": {"id": 1}, "updates": {"status": "closed"}},
    "file.read_internal": {},
    "file.delete": {},
    "web.fetch_page": {},
    "tool.send_email_internal": {"to": ["a@corp.local"], "subject": "s", "body": "b"},
    "tool.send_email_external": {"to": ["x@example.com"], "subject": "s", "body": "b"},
    "research.lookup": {"query": "q", "max_sources": 1},
    "planner.request": {"request": "r"},
    "mail.deliver": {"to": ["a@corp.local"], "subject": "s", "body": "b"},
    "admin.change_policy": {"policy_id": "p1", "changes": {"a": 1}},
}
WITH_JUSTIFICATION = ["db.query_rows", "db.update_records", "file.delete", "tool.send_email_external"]
WITH_CC_BCC = ["tool.send_email_internal", "tool.send_email_external", "mail.deliver"]
EMAIL_SHAPED = WITH_CC_BCC


def rejects(action, payload):
    with pytest.raises(ValidationError):
        validate_payload(action, payload)


def test_base_payloads_cover_the_catalog():
    assert set(BASE) == get_catalog().names() == set(ACTION_SCHEMAS)
    for action, payload in BASE.items():
        validate_payload(action, payload)


# --- justification (S13) ------------------------------------------------------------

@pytest.mark.parametrize("action", WITH_JUSTIFICATION)
def test_justification_optional_and_limited_to_500(action):
    assert validate_payload(action, BASE[action]).justification is None
    assert validate_payload(action, {**BASE[action], "justification": "Quarterly clean-up."}).justification
    assert validate_payload(action, {**BASE[action], "justification": "x" * 500})
    rejects(action, {**BASE[action], "justification": "x" * 501})
    rejects(action, {**BASE[action], "justification": 7})


@pytest.mark.parametrize("action", sorted(set(BASE) - set(WITH_JUSTIFICATION)))
def test_justification_rejected_where_not_agreed(action):
    # Only four actions carry it; tool.send_email_internal does not.
    rejects(action, {**BASE[action], "justification": "please"})


def test_file_delete_keeps_reason_next_to_justification():
    p = validate_payload("file.delete", {"reason": "old", "justification": "approved by finance"})
    assert (p.reason, p.justification) == ("old", "approved by finance")


# --- cc / bcc and normalisation (S14) -------------------------------------------------

@pytest.mark.parametrize("action", WITH_CC_BCC)
def test_cc_bcc_default_to_empty_lists(action):
    p = validate_payload(action, BASE[action])
    assert p.cc == [] and p.bcc == []


@pytest.mark.parametrize("action", WITH_CC_BCC)
@pytest.mark.parametrize("field", ["to", "cc", "bcc"])
def test_recipient_lists_share_the_same_limits(action, field):
    ok = [f"p{i}@corp.local" for i in range(20)]
    assert getattr(validate_payload(action, {**BASE[action], field: ok}), field) == ok
    rejects(action, {**BASE[action], field: ok + ["p20@corp.local"]})            # more than 20
    rejects(action, {**BASE[action], field: ["not-an-address"]})
    rejects(action, {**BASE[action], field: ["two@@corp.local"]})
    rejects(action, {**BASE[action], field: ["has space@corp.local"]})
    rejects(action, {**BASE[action], field: ["a" * 250 + "@corp.local"]})        # longer than 254
    rejects(action, {**BASE[action], field: "a@corp.local"})                      # a list, not text
    rejects(action, {**BASE[action], field: [123]})


@pytest.mark.parametrize("action", WITH_CC_BCC)
def test_to_is_still_required_and_non_empty(action):
    no_to = {k: v for k, v in BASE[action].items() if k != "to"}
    rejects(action, {**no_to, "cc": ["a@corp.local"], "bcc": ["b@corp.local"]})
    rejects(action, {**BASE[action], "to": []})


@pytest.mark.parametrize("action", sorted(set(BASE) - set(WITH_CC_BCC)))
def test_cc_bcc_rejected_on_other_actions(action):
    rejects(action, {**BASE[action], "cc": ["a@corp.local"]})
    rejects(action, {**BASE[action], "bcc": ["a@corp.local"]})


def test_normalize_address():
    assert normalize_address("  Alice.Morgan@Corp.LOCAL \t") == "alice.morgan@corp.local"
    assert normalize_address("a@b.c") == "a@b.c"
    assert normalize_address(normalize_address(" X@Y.Z ")) == "x@y.z"            # idempotent
    assert normalize_address("") == "" and normalize_address("   ") == ""


@pytest.mark.parametrize("action", WITH_CC_BCC)
def test_every_recipient_list_is_normalised(action):
    p = validate_payload(action, {**BASE[action], "to": ["  Alice@Corp.Local "], "cc": ["BOB@corp.local\n"],
                                  "bcc": ["\tCarol@EXAMPLE.org"]})
    assert (p.to, p.cc, p.bcc) == (["alice@corp.local"], ["bob@corp.local"], ["carol@example.org"])


def test_normalisation_happens_before_the_shape_check():
    rejects("tool.send_email_internal", {**BASE["tool.send_email_internal"], "to": ["   "]})   # empty after strip
    validate_payload("tool.send_email_internal", {**BASE["tool.send_email_internal"], "to": [" a@b.c "]})


def test_aliases_and_groups_are_not_supported_or_expanded():
    # An alias without a domain is not an address; one with a domain is taken literally.
    rejects("tool.send_email_internal", {**BASE["tool.send_email_internal"], "to": ["all-staff"]})
    p = validate_payload("tool.send_email_internal", {**BASE["tool.send_email_internal"],
                                                      "to": ["all-staff@corp.local"]})
    assert p.to == ["all-staff@corp.local"]                                       # not expanded
    p = validate_payload("tool.send_email_internal", {**BASE["tool.send_email_internal"],
                                                      "to": ["alice+news@corp.local"]})
    assert p.to == ["alice+news@corp.local"]                                      # plus-tags kept as written


# --- research.lookup (S10) ------------------------------------------------------------

def test_research_lookup_accepts_the_agreed_shape():
    p = validate_payload("research.lookup", {"query": "Q3 policy", "max_sources": 3,
                                             "sources": ["file:/internal/hr_policy.txt", "https://news.example.com/q3-market"]})
    assert isinstance(p, ResearchLookupPayload) and p.max_sources == 3 and len(p.sources) == 2
    assert validate_payload("research.lookup", BASE["research.lookup"]).sources == []     # optional


@pytest.mark.parametrize("change", [
    {"query": ""},
    {"query": "x" * 501},
    {"query": 5},
    {"max_sources": 0},
    {"max_sources": 4},
    {"max_sources": "two"},
    {"sources": ["s"] * 6},
    {"sources": [""]},
    {"sources": "file:/internal/a.txt"},
    {"sources": [5]},
])
def test_research_lookup_rejects(change):
    rejects("research.lookup", {**BASE["research.lookup"], **change})


def test_research_lookup_limits_are_inclusive():
    assert validate_payload("research.lookup", {"query": "x" * 500, "max_sources": 1, "sources": ["s"] * 5})
    assert validate_payload("research.lookup", {"query": "q", "max_sources": 3})


def test_research_lookup_max_sources_is_required():
    rejects("research.lookup", {"query": "q"})
    rejects("research.lookup", {"query": "q", "sources": ["file:/internal/a.txt"]})


# --- planner.request (S11) -----------------------------------------------------------

def test_planner_request_shape():
    p = validate_payload("planner.request", {"request": "Relay this", "suggested_action": "db.query_rows"})
    assert isinstance(p, PlannerRequestPayload) and p.suggested_action == "db.query_rows"
    assert validate_payload("planner.request", BASE["planner.request"]).suggested_action is None


@pytest.mark.parametrize("change", [
    {"request": ""},
    {"request": "x" * 501},
    {"request": 3},
    {"suggested_action": ""},
    {"suggested_action": "x" * 101},
    {"suggested_action": 5},
])
def test_planner_request_rejects(change):
    rejects("planner.request", {**BASE["planner.request"], **change})


# --- mail.deliver (S12) ---------------------------------------------------------------

def test_mail_deliver_shape_and_normalisation():
    p = validate_payload("mail.deliver", {"to": ["A@Corp.Local"], "cc": ["B@corp.local"],
                                          "bcc": ["C@Example.ORG"], "subject": "s", "body": "b"})
    assert isinstance(p, MailDeliverPayload)
    assert (p.to, p.cc, p.bcc) == (["a@corp.local"], ["b@corp.local"], ["c@example.org"])


def test_mail_deliver_has_the_same_shape_as_the_email_actions_but_no_justification():
    assert set(MailDeliverPayload.model_fields) == set(EmailPayload.model_fields) == \
        {"to", "cc", "bcc", "subject", "body"}
    assert set(ACTION_SCHEMAS["tool.send_email_external"].model_fields) == set(EmailPayload.model_fields) | {"justification"}
    assert set(ACTION_SCHEMAS["tool.send_email_internal"].model_fields) == set(EmailPayload.model_fields)


@pytest.mark.parametrize("change", [
    {"subject": "s" * 201},
    {"body": "b" * 20001},
    {"subject": 5},
])
@pytest.mark.parametrize("action", EMAIL_SHAPED)
def test_email_shaped_text_limits(action, change):
    rejects(action, {**BASE[action], **change})


# --- extra fields stay forbidden everywhere -----------------------------------------------

@pytest.mark.parametrize("action", sorted(BASE))
@pytest.mark.parametrize("extra", ["trust_score", "scenario_label", "label", "decision", "token"])
def test_extra_fields_rejected_on_every_action(action, extra):
    rejects(action, {**BASE[action], extra: "x"})


@pytest.mark.parametrize("model", [ResearchLookupPayload, PlannerRequestPayload, MailDeliverPayload])
def test_new_models_are_frozen_and_forbid_extras(model):
    assert model.model_config["extra"] == "forbid" and model.model_config["frozen"] is True
