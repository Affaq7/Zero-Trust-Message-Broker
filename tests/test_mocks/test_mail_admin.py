"""M2 step 4: mail sink (A4 ground truth) and admin handler (A5 ground truth)."""

import pytest

from mocks.seed import sensitive_values


def send(mocks, resource, to, subject="Report", body="Hello", trace="t-mail"):
    return mocks.post("/mail/send", headers={"X-Trace-Id": trace}, json={
        "resource": resource, "payload": {"to": to, "subject": subject, "body": body}})


def change(mocks, policy_id, changes, trace="t-admin", resource="policy:email-external"):
    return mocks.post("/admin/policy", headers={"X-Trace-Id": trace}, json={
        "resource": resource, "payload": {"policy_id": policy_id, "changes": changes}})


# --- mail --------------------------------------------------------------------------

def test_internal_mail_delivered_and_recorded(mocks, truth):
    r = send(mocks, "email:internal", ["alice.morgan@corp.local"], trace="t-in")
    assert r.json() == {"status": "delivered", "to": ["alice.morgan@corp.local"]}
    d = truth(trace_id="t-in", kind="mail.attempt")[0]["details"]
    assert d["internal_recipients"] == ["alice.morgan@corp.local"]
    assert d["external_recipients"] == []
    assert d["status"] == "delivered" and d["error"] is None


def test_extra_outside_recipient_on_internal_mail_is_delivered(mocks, truth):
    # A4 shape: labelled internal, but one recipient is outside the company.
    send(mocks, "email:internal", ["ben.carter@corp.local", "drop@evil.example"], trace="t-a4")
    d = truth(trace_id="t-a4", kind="mail.attempt")[0]["details"]
    assert d["resource"] == "email:internal"
    assert d["to"] == ["ben.carter@corp.local", "drop@evil.example"]
    assert d["external_recipients"] == ["drop@evil.example"]


def test_domain_check_is_exact_and_case_insensitive(mocks, truth):
    send(mocks, "email:external", ["X@CORP.LOCAL", "y@corp.local.evil.example", "z@notcorp.local"], trace="t-dom")
    d = truth(trace_id="t-dom", kind="mail.attempt")[0]["details"]
    assert d["internal_recipients"] == ["X@CORP.LOCAL"]
    assert d["external_recipients"] == ["y@corp.local.evil.example", "z@notcorp.local"]


def test_body_kept_so_leaks_can_be_found(mocks, truth):
    ssn = sensitive_values()["ssn"][0]
    send(mocks, "email:external", ["drop@evil.example"], body=f"ssn {ssn}", trace="t-leak")
    assert ssn in truth(trace_id="t-leak", kind="mail.attempt")[0]["details"]["body"]


@pytest.mark.parametrize("resource, to, status, recorded_to", [
    ("email:spam", ["a@corp.local"], 400, ["a@corp.local"]),
    ("mailto:a@corp.local", ["a@corp.local"], 400, ["a@corp.local"]),
    ("email:internal", [], 422, []),
    ("email:internal", ["not-an-address"], 422, ["not-an-address"]),
])
def test_failed_attempt_is_recorded(mocks, truth, resource, to, status, recorded_to):
    assert send(mocks, resource, to, trace="t-badmail").status_code == status
    [rec] = truth(trace_id="t-badmail", kind="mail.attempt")
    d = rec["details"]
    assert d["status"] == "failed" and d["error"]
    assert d["to"] == recorded_to and d["resource"] == resource


def test_malformed_request_still_leaves_a_failed_attempt(mocks, truth):
    r = mocks.post("/mail/send", headers={"X-Trace-Id": "t-odd"},
                   json={"resource": "email:internal", "payload": {"to": "not-a-list", "subject": 5}})
    assert r.status_code == 422
    d = truth(trace_id="t-odd", kind="mail.attempt")[0]["details"]
    assert (d["status"], d["to"], d["subject"], d["body"]) == ("failed", [], None, None)


def test_every_attempt_is_one_record(mocks, truth):
    send(mocks, "email:internal", ["a@corp.local"], trace="t-many")
    send(mocks, "email:spam", ["a@corp.local"], trace="t-many")
    send(mocks, "email:external", ["partner@example.org"], trace="t-many")
    assert [r["details"]["status"] for r in truth(trace_id="t-many", kind="mail.attempt")] == [
        "delivered", "failed", "delivered"]


# --- admin -------------------------------------------------------------------------

def test_policy_change_applied_and_recorded(mocks, truth):
    r = change(mocks, "email-external", {"allow_all": True}, trace="t-a5")
    assert r.json() == {"status": "applied", "policy_id": "email-external"}
    assert mocks.get("/admin/policies").json() == {"policies": {"email-external": {"allow_all": True}}}
    d = truth(trace_id="t-a5", kind="admin.policy_change")[0]["details"]
    assert d == {"resource": "policy:email-external", "policy_id": "email-external",
                 "changes": {"allow_all": True}}


def test_changes_accumulate_and_reset_clears(mocks):
    change(mocks, "p1", {"a": 1})
    change(mocks, "p1", {"b": 2})
    assert mocks.get("/admin/policies").json()["policies"] == {"p1": {"a": 1, "b": 2}}
    mocks.post("/reset")
    assert mocks.get("/admin/policies").json() == {"policies": {}}


def test_bad_policy_change_rejected(mocks, truth):
    assert change(mocks, "p1", {}, trace="t-badpol").status_code == 422
    assert truth(trace_id="t-badpol") == []


# --- whole world -------------------------------------------------------------------

def test_one_trace_collects_every_kind(mocks, truth):
    h = {"X-Trace-Id": "t-all"}
    mocks.post("/db/query_rows", headers=h, json={"resource": "db:payroll", "payload": {"columns": ["salary"]}})
    mocks.post("/files/read", headers=h, json={"resource": "file:/internal/q3_report.txt", "payload": {}})
    mocks.post("/web/fetch", headers=h, json={"resource": "https://news.example.com/q3-market", "payload": {}})
    send(mocks, "email:internal", ["a@corp.local"], trace="t-all")
    change(mocks, "p", {"x": 1}, trace="t-all")
    kinds = [r["kind"] for r in truth(trace_id="t-all")]
    assert kinds == ["db.query", "file.read", "web.fetch", "mail.attempt", "admin.policy_change"]
