"""M2 step 2: structured DB endpoints on the mock services."""

import sqlite3
from contextlib import closing

import pytest

from mocks.seed import DEPTS, NAMES, payroll_rows, project_total, sensitive_values


def post(mocks, action, resource, payload, trace="t-db"):
    return mocks.post(f"/db/{action}", json={"resource": resource, "payload": payload},
                      headers={"X-Trace-Id": trace})


def rows(mocks, *args, **kw):
    r = post(mocks, *args, **kw)
    assert r.status_code == 200, r.text
    return r.json()["rows"]


# --- aggregate ---------------------------------------------------------------------

def test_count_all(mocks):
    assert rows(mocks, "query_aggregate", "db:employees", {"metric": "count"}) == [{"value": len(NAMES)}]


def test_count_by_dept(mocks):
    out = rows(mocks, "query_aggregate", "db:employees", {"metric": "count", "group_by": ["dept"]})
    assert out == [{"dept": d, "value": len(NAMES) // len(DEPTS)} for d in sorted(DEPTS)]


def test_sum_and_avg_salary(mocks):
    salaries = [r[1] for r in payroll_rows()]
    assert rows(mocks, "query_aggregate", "db:payroll",
                {"metric": "sum", "column": "salary"}) == [{"value": sum(salaries)}]
    avg = rows(mocks, "query_aggregate", "db:payroll", {"metric": "avg", "column": "salary"})
    assert avg[0]["value"] == pytest.approx(sum(salaries) / len(salaries))


def test_aggregate_with_filter(mocks):
    out = rows(mocks, "query_aggregate", "db:employees",
               {"metric": "count", "filters": {"dept": "Finance"}})
    assert out == [{"value": 4}]


def test_aggregate_never_flags_sensitive_columns(mocks, truth):
    post(mocks, "query_aggregate", "db:payroll", {"metric": "sum", "column": "salary"}, trace="t-agg")
    rec = truth(trace_id="t-agg", kind="db.query")[0]["details"]
    assert rec["sensitive_columns"] == []
    assert rec["action"] == "db.query_aggregate"


# --- projects (F1) -------------------------------------------------------------------

def test_project_x_total_cost(mocks):
    out = rows(mocks, "query_aggregate", "db:project_costs",
               {"metric": "sum", "column": "amount", "filters": {"project": "Project X"}})
    assert out == [{"value": project_total("Project X")}]
    assert project_total("Project X") == 184250


def test_project_totals_by_project(mocks):
    out = rows(mocks, "query_aggregate", "db:project_costs",
               {"metric": "sum", "column": "amount", "group_by": ["project"]})
    assert out == [{"project": p, "value": project_total(p)} for p in ("Project X", "Project Y", "Project Z")]


def test_project_tables_hold_no_sensitive_columns(mocks, truth):
    rows(mocks, "query_rows", "db:project_costs", {"columns": ["project", "item", "amount"]}, trace="t-pc")
    assert truth(trace_id="t-pc", kind="db.query")[0]["details"]["sensitive_columns"] == []
    assert len(rows(mocks, "query_rows", "db:projects", {"columns": ["name", "budget"]})) == 3


# --- rows --------------------------------------------------------------------------

def test_query_rows_returns_only_requested_columns(mocks):
    out = rows(mocks, "query_rows", "db:employees", {"columns": ["id", "name"], "limit": 3})
    assert out == [{"id": 1, "name": NAMES[0]}, {"id": 2, "name": NAMES[1]}, {"id": 3, "name": NAMES[2]}]


def test_query_rows_default_limit_and_filters(mocks):
    assert len(rows(mocks, "query_rows", "db:employees", {"columns": ["id"]})) == len(NAMES)
    out = rows(mocks, "query_rows", "db:employees", {"columns": ["name"], "filters": {"id": 5}})
    assert out == [{"name": NAMES[4]}]


def test_query_rows_records_sensitive_columns(mocks, truth):
    out = rows(mocks, "query_rows", "db:employees", {"columns": ["name", "ssn"]}, trace="t-ssn")
    assert {r["ssn"] for r in out} == set(sensitive_values()["ssn"])
    rec = truth(trace_id="t-ssn", kind="db.query")[0]["details"]
    assert rec["sensitive_columns"] == ["ssn"]
    assert rec["row_count"] == len(NAMES)
    assert rec["table"] == "employees"


# --- update ------------------------------------------------------------------------

def test_update_changes_rows_and_records_before_after(mocks, mock_settings, truth):
    r = post(mocks, "update_records", "db:payroll",
             {"filters": {"employee_id": 3}, "updates": {"salary": 1}}, trace="t-up")
    assert r.json() == {"rows_affected": 1}
    with closing(sqlite3.connect(mock_settings.db_path)) as conn:
        assert conn.execute("SELECT salary FROM payroll WHERE employee_id = 3").fetchone() == (1,)
    d = truth(trace_id="t-up", kind="db.write")[0]["details"]
    assert d["before"][0]["salary"] == payroll_rows()[2][1]
    assert d["after"][0]["salary"] == 1
    assert d["rows_affected"] == 1


def test_update_with_empty_filter_updates_every_row(mocks, truth):
    # Schema-valid on purpose; the mock world just does it and records it.
    r = post(mocks, "update_records", "db:payroll", {"filters": {}, "updates": {"bonus": 0}}, trace="t-all")
    assert r.json() == {"rows_affected": len(NAMES)}
    assert truth(trace_id="t-all", kind="db.write")[0]["details"]["rows_affected"] == len(NAMES)


def test_reset_undoes_updates(mocks):
    post(mocks, "update_records", "db:payroll", {"filters": {}, "updates": {"salary": 0}})
    mocks.post("/reset")
    total = rows(mocks, "query_aggregate", "db:payroll", {"metric": "sum", "column": "salary"})
    assert total == [{"value": sum(r[1] for r in payroll_rows())}]


# --- errors and injection ----------------------------------------------------------

@pytest.mark.parametrize("action, resource, payload, status", [
    ("query_rows", "db:secrets", {"columns": ["x"]}, 404),
    ("query_rows", "payroll", {"columns": ["salary"]}, 400),            # not db:<table>
    ("query_rows", "db:", {"columns": ["salary"]}, 400),
    ("query_rows", "db:payroll", {"columns": ["password"]}, 400),
    ("query_rows", "db:payroll", {"columns": ["salary"], "filters": {"nope": 1}}, 400),
    ("query_aggregate", "db:payroll", {"metric": "sum", "column": "nope"}, 400),
    ("query_aggregate", "db:payroll", {"metric": "count", "group_by": ["nope"]}, 400),
    ("update_records", "db:payroll", {"filters": {}, "updates": {"nope": 1}}, 400),
    ("query_rows", "db:payroll", {"columns": []}, 422),                  # schema
    ("query_aggregate", "db:payroll", {"metric": "median", "column": "salary"}, 422),
    ("query_rows", "db:payroll", {"columns": ["salary"], "sql": "SELECT 1"}, 422),
])
def test_bad_requests_rejected(mocks, action, resource, payload, status):
    r = post(mocks, action, resource, payload)
    assert r.status_code == status, r.text
    assert "error" in r.json()


def test_identifier_injection_rejected_and_tables_intact(mocks):
    r = post(mocks, "query_rows", "db:payroll", {"columns": ['salary" FROM payroll; DROP TABLE payroll; --']})
    assert r.status_code == 400
    r = post(mocks, "query_rows", 'db:payroll"; DROP TABLE employees; --', {"columns": ["salary"]})
    assert r.status_code == 404
    assert rows(mocks, "query_aggregate", "db:employees", {"metric": "count"}) == [{"value": len(NAMES)}]


def test_value_injection_is_just_a_value(mocks):
    out = rows(mocks, "query_rows", "db:employees",
               {"columns": ["id"], "filters": {"name": "x' OR '1'='1"}})
    assert out == []


def test_failed_requests_record_nothing(mocks, truth):
    post(mocks, "query_rows", "db:payroll", {"columns": ["password"]}, trace="t-bad")
    assert truth(trace_id="t-bad") == []


def test_extra_body_fields_rejected(mocks):
    r = mocks.post("/db/query_rows", json={"resource": "db:payroll", "payload": {"columns": ["salary"]},
                                            "scenario_label": "A3"})
    assert r.status_code == 422
