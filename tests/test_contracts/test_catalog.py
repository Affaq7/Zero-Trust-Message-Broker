"""Step 2: action catalog loading, validation and default-deny."""

import copy

import pytest
import yaml
from pydantic import ValidationError

from contracts.catalog import CATALOG_PATH, ActionCatalog, get_catalog, load_catalog

# The agreed table (v0.2). served_by is provisional (open-questions Q1).
EXPECTED = {
    "db.query_aggregate":       ("Permitted",   {"planner", "research"}, "database"),
    "db.query_rows":            ("Conditional", {"planner"},             "database"),
    "db.update_records":        ("Conditional", {"planner"},             "database"),
    "file.read_internal":       ("Permitted",   {"planner", "research"}, "tool"),
    "file.delete":              ("Conditional", {"tool"},                "tool"),
    "web.fetch_page":           ("Permitted",   {"research"},            "tool"),
    "tool.send_email_internal": ("Permitted",   {"planner", "tool"},     "tool"),
    "tool.send_email_external": ("Conditional", {"tool"},                "tool"),
    "admin.change_policy":      ("Prohibited",  set(),                   None),
}
ROLES = ["planner", "research", "database", "tool"]


def raw_catalog():
    with open(CATALOG_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_catalog_matches_agreed_table():
    catalog = get_catalog()
    assert catalog.names() == set(EXPECTED)
    for name, (cls, roles, served_by) in EXPECTED.items():
        spec = catalog.get(name)
        assert spec.action_class == cls
        assert set(spec.allowed_roles) == roles
        assert spec.served_by == served_by


@pytest.mark.parametrize("role", ROLES + ["malicious"])
@pytest.mark.parametrize("action", sorted(EXPECTED))
def test_is_allowed_matches_table(role, action):
    assert get_catalog().is_allowed(role, action) == (role in EXPECTED[action][1])


@pytest.mark.parametrize("role", ROLES)
def test_admin_change_policy_denied_for_everyone(role):
    assert not get_catalog().is_allowed(role, "admin.change_policy")


@pytest.mark.parametrize("action", ["db.drop_table", "", "DB.QUERY_ROWS", "db.query_rows "])
def test_unknown_action_default_denied(action):
    catalog = get_catalog()
    assert catalog.get(action) is None
    assert catalog.served_by(action) is None
    assert not any(catalog.is_allowed(role, action) for role in ROLES)


def test_load_catalog_from_other_path(tmp_path):
    path = tmp_path / "dir with space" / "catalog.yaml"
    path.parent.mkdir()
    path.write_text(CATALOG_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    assert load_catalog(path) == get_catalog()


def test_missing_catalog_file_fails(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_catalog(tmp_path / "nope.yaml")


def _break(mutate):
    data = copy.deepcopy(raw_catalog())
    mutate(data)
    return data


def _action(data, name):
    return next(a for a in data["actions"] if a["name"] == name)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version="0.1"),
    lambda d: d.update(trust_scores={"planner": 0.9}),
    lambda d: d["actions"].append(dict(d["actions"][0])),                       # duplicate action
    lambda d: _action(d, "db.query_rows").update({"class": "Sometimes"}),
    lambda d: _action(d, "db.query_rows").update(allowed_roles=["admin"]),       # unknown role
    lambda d: _action(d, "db.query_rows").update(allowed_roles=["planner", "planner"]),
    lambda d: _action(d, "db.query_rows").update(allowed_roles=[]),              # Conditional w/o roles
    lambda d: _action(d, "db.query_rows").update(served_by="nobody"),           # not an agent
    lambda d: _action(d, "db.query_rows").update(served_by=None),
    lambda d: _action(d, "db.query_rows").update(name="queryRows"),             # bad name format
    lambda d: _action(d, "db.query_rows").update(extra="x"),
    lambda d: _action(d, "admin.change_policy").update(allowed_roles=["planner"]),
    lambda d: _action(d, "admin.change_policy").update(served_by="tool"),
])
def test_malformed_catalog_rejected(mutate):
    with pytest.raises(ValidationError):
        ActionCatalog.model_validate(_break(mutate))
