"""Task A-R1: the calibration sweep (scripts/simulate_trust.py --sweep) and the
values written back into broker/trust/trust_settings.yaml."""

import importlib.util
import json
from pathlib import Path

from broker.trust.trust import default_settings

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("simulate_trust", REPO / "scripts" / "simulate_trust.py")
sim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sim)


def test_grid_is_the_planned_one():
    assert sim.LAMBDAS == (0.2, 0.5, 1.0) and sim.ETAS == (0.05, 0.1)


def test_chosen_values_are_in_the_settings():
    chosen = sim.choose(sim.sweep(sim.synthetic_normal()))
    s = default_settings()
    assert (chosen["lambda"], chosen["eta"]) == (s["lambda"], s["eta"]) == (0.5, 0.1)


def test_settings_meet_the_rule():
    r = sim.evaluate(default_settings()["lambda"], default_settings()["eta"], sim.synthetic_normal())
    assert r["normal_always_active"]
    assert r["attacker_restricted_at"] <= 5
    assert sim.passes(r)


def test_trust_alone_cannot_quarantine_within_five():
    # Why V1 (A3) does it: after 5 DENY, Ba is still 15/20, so T >= 0.575.
    for r in sim.sweep(sim.synthetic_normal()):
        assert r["attacker_quarantined_at"] == 13


def test_low_lambda_fails_the_rule():
    r = sim.evaluate(0.2, 0.1, sim.synthetic_normal())
    assert r["attacker_restricted_at"] == 7 and not sim.passes(r)


def test_noisy_agent_is_one_deny_every_ten():
    seq = sim.noisy_sequence()
    assert len(seq) == 60
    assert [i for i, (_, d) in enumerate(seq, 1) if d == "DENY"] == [10, 20, 30, 40, 50, 60]


def test_normal_data_from_events(tmp_path):
    rows = [
        {"run_id": "r", "logged_at": "2", "direction": "in", "msg_type": "request",
         "sender": "planner", "action": "tool.send_email_external"},
        {"run_id": "r", "logged_at": "1", "direction": "in", "msg_type": "request",
         "sender": "planner", "action": "db.query_aggregate"},
        {"run_id": "r", "logged_at": "3", "direction": "in", "msg_type": "response",
         "sender": "database", "action": "db.query_aggregate"},
        {"run_id": "r", "logged_at": "4", "direction": "out", "msg_type": "request",
         "sender": "tool", "action": "mail.deliver"},
    ]
    p = tmp_path / "events.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    assert sim.load_normal([p]) == {"planner": [("db.query_aggregate", "ALLOW"),
                                                ("tool.send_email_external", "HITL")]}


def test_svg_figures_are_written(tmp_path, monkeypatch):
    monkeypatch.setattr(sim, "FIGURES", tmp_path)
    results = sim.sweep(sim.synthetic_normal())
    paths = sim.write_figures(results, default_settings()["bands"], 0.1)
    assert sorted(p.name for p in paths) == ["trust_attacker.svg", "trust_noisy.svg"]
    assert all(p.read_text(encoding="utf-8").startswith("<svg") for p in paths)


def test_committed_figures_exist():
    for name in ("trust_attacker.svg", "trust_noisy.svg"):
        assert (REPO / "figures" / name).read_text(encoding="utf-8").startswith("<svg")
