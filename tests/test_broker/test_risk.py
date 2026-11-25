"""Task A1: risk ratings and the risk module (broker/trust/risk.py)."""

import copy
import math

import pytest
import yaml

from broker.trust import risk
from broker.trust.risk import (
    FACTORS,
    NEVER,
    RATINGS_PATH,
    is_compound_high,
    is_critical,
    load_ratings,
    required_trust,
    risk_vector,
)
from contracts.catalog import get_catalog

LOW = {f: "L" for f in FACTORS}


def raw_ratings():
    with open(RATINGS_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def write(tmp_path, data):
    p = tmp_path / "ratings.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


# --- ratings file ---------------------------------------------------------

def test_every_catalog_action_is_rated_and_nothing_else():
    ratings, _ = load_ratings()
    assert set(ratings) == get_catalog().names()
    assert len(ratings) == 12


@pytest.mark.parametrize("action", sorted(get_catalog().names()))
def test_vector_has_seven_factors_with_l_m_h(action):
    vec = risk_vector(action)
    assert tuple(vec) == FACTORS
    assert set(vec.values()) <= {"L", "M", "H"}


def test_s16_agreed_ratings_are_kept():
    agreed = {"R": "L", "T": "L", "D": "M", "E": "L", "P": "L", "A": "M", "S": "M"}
    assert risk_vector("research.lookup") == agreed
    assert risk_vector("planner.request") == agreed


def test_starting_thresholds():
    t = risk.thresholds()
    assert t == {"Permitted": 0.80, "Conditional": 0.60, "deny_below": 0.40}


# The ratings Amna approved on 2026-11-25 (R T D E P A S), on her approved scale.
APPROVED = {
    "db.query_aggregate":       "LLMLLML",
    "db.query_rows":            "LLHLMMM",
    "db.update_records":        "HHHLHLH",
    "file.read_internal":       "LLMLLLL",
    "file.delete":              "HHMLHLL",
    "web.fetch_page":           "LLLMLLL",
    "tool.send_email_internal": "HMMHMMH",
    "tool.send_email_external": "HMMHMMH",
    "research.lookup":          "LLMLLMM",
    "planner.request":          "LLMLLMM",
    "mail.deliver":             "HMMHMLH",
    "admin.change_policy":      "MHHLHHH",
}


def test_ratings_match_the_approved_table():
    assert {a: "".join(risk_vector(a).values()) for a in APPROVED} == APPROVED


def test_missing_catalog_action_is_rejected(tmp_path):
    data = raw_ratings()
    del data["ratings"]["mail.deliver"]
    with pytest.raises(ValueError, match="mail.deliver"):
        load_ratings(write(tmp_path, data))


def test_action_not_in_catalog_is_rejected(tmp_path):
    data = raw_ratings()
    data["ratings"]["db.drop_everything"] = dict(LOW, individual_data=False)
    with pytest.raises(ValueError, match="db.drop_everything"):
        load_ratings(write(tmp_path, data))


@pytest.mark.parametrize("bad", [{"R": "X"}, {"R": "l"}, {"Z": "L"}])
def test_bad_vector_is_rejected(tmp_path, bad):
    data = raw_ratings()
    vec = dict(LOW, individual_data=False)
    if "Z" in bad:
        vec.pop("R")
    vec.update(bad)
    data["ratings"]["web.fetch_page"] = vec
    with pytest.raises(ValueError, match="web.fetch_page"):
        load_ratings(write(tmp_path, data))


@pytest.mark.parametrize("bad", ["drop", "yes", None])
def test_individual_data_must_be_a_bool(tmp_path, bad):
    data = raw_ratings()
    if bad == "drop":
        del data["ratings"]["db.query_rows"]["individual_data"]
    else:
        data["ratings"]["db.query_rows"]["individual_data"] = bad
    with pytest.raises(ValueError, match="db.query_rows"):
        load_ratings(write(tmp_path, data))


def test_old_critical_threshold_is_rejected(tmp_path):
    data = raw_ratings()
    data["thresholds"]["critical"] = 0.80
    with pytest.raises(ValueError, match="thresholds"):
        load_ratings(write(tmp_path, data))


def test_threshold_out_of_range_is_rejected(tmp_path):
    data = raw_ratings()
    data["thresholds"]["Permitted"] = 1.5
    with pytest.raises(ValueError, match="Permitted"):
        load_ratings(write(tmp_path, data))


# --- risk_vector ----------------------------------------------------------

def test_unknown_action_gets_all_high():
    assert risk_vector("not.in_catalog") == {f: "H" for f in FACTORS}
    assert is_compound_high("not.in_catalog")


def test_returned_vector_is_a_copy():
    vec = risk_vector("db.query_aggregate")
    vec["D"] = "H"
    assert risk_vector("db.query_aggregate")["D"] == "M"


def test_vector_has_no_individual_data_key():
    assert "individual_data" not in risk_vector("db.query_rows")


def test_deterministic():
    assert [risk_vector(a) for a in sorted(get_catalog().names())] == [
        risk_vector(a) for a in sorted(get_catalog().names())
    ]


# --- compound high and critical --------------------------------------------

def test_send_email_external_is_compound_high():
    assert is_compound_high("tool.send_email_external") is True


@pytest.mark.parametrize("action", [
    "tool.send_email_external", "tool.send_email_internal", "db.update_records",
    "file.delete", "mail.deliver", "admin.change_policy",
])
def test_compound_high_actions(action):
    assert is_compound_high(action)


@pytest.mark.parametrize("action", [
    "db.query_aggregate", "db.query_rows", "file.read_internal", "web.fetch_page",
    "research.lookup", "planner.request",
])
def test_not_compound_high(action):
    assert not is_compound_high(action)


def test_only_individual_level_data_is_critical():
    critical = {a for a in get_catalog().names() if is_critical(a)}
    assert critical == {"db.query_rows"}


def test_critical_is_its_own_field_not_d_high():
    # D is H for db.update_records and admin.change_policy, but neither returns
    # individual-level data.
    assert risk_vector("db.update_records")["D"] == "H"
    assert not is_critical("db.update_records")
    assert not is_critical("admin.change_policy")


def test_unknown_action_is_critical():
    assert is_critical("not.in_catalog")


# --- required_trust --------------------------------------------------------

def test_low_risk_permitted_needs_0_80():
    assert required_trust("Permitted", LOW) == pytest.approx(0.80)


def test_low_risk_conditional_needs_0_60():
    assert required_trust("Conditional", LOW) == pytest.approx(0.60)


def test_compound_high_is_a_flag_only():
    # Amna, 2026-11-25: compound high does not change required_trust for now.
    vec = risk_vector("tool.send_email_external")
    assert is_compound_high("tool.send_email_external")
    assert required_trust("Conditional", vec) == pytest.approx(0.60)
    assert required_trust("Conditional", {f: "H" for f in FACTORS}) == pytest.approx(0.60)


def test_critical_does_not_change_required_trust():
    assert required_trust("Conditional", risk_vector("db.query_rows")) == pytest.approx(0.60)


@pytest.mark.parametrize("cls", ["Prohibited", "Unknown", "", "permitted"])
def test_prohibited_and_unknown_class_never_allowed(cls):
    assert required_trust(cls, LOW) == NEVER
    assert math.isinf(required_trust(cls, LOW))


def test_never_below_deny_floor():
    for action in get_catalog().names():
        spec = get_catalog().get(action)
        assert required_trust(spec.action_class, risk_vector(action)) >= 0.40


def test_catalog_class_and_rating_give_expected_requirement():
    expected = {
        "db.query_aggregate": 0.80, "db.query_rows": 0.60, "db.update_records": 0.60,
        "file.read_internal": 0.80, "file.delete": 0.60, "web.fetch_page": 0.80,
        "tool.send_email_internal": 0.80, "tool.send_email_external": 0.60,
        "research.lookup": 0.80, "planner.request": 0.80, "mail.deliver": 0.80,
        "admin.change_policy": NEVER,
    }
    got = {
        a: required_trust(get_catalog().get(a).action_class, risk_vector(a))
        for a in get_catalog().names()
    }
    assert got == pytest.approx(expected)


@pytest.mark.parametrize("bad", [{}, dict(LOW, R="X"), {**LOW, "Z": "L"}, "LLLLLLL"])
def test_malformed_risk_is_rejected(bad):
    with pytest.raises(ValueError):
        required_trust("Permitted", bad)


def test_required_trust_does_not_change_the_input():
    vec = risk_vector("db.query_rows")
    before = copy.deepcopy(vec)
    required_trust("Conditional", vec)
    assert vec == before
