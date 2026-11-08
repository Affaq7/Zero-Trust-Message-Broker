"""The scenario files in scenarios/: N1-N4, scripted attacks and the not-applicable attacks.

Runs them through real processes with the fake LLM; the live run is manual
(python -m runner --llm ollama ...).
"""

import pytest

from mocks.seed import project_total
from runner.evaluate import evaluate
from runner.run import run_repetition
from runner.scenarios import DEFAULT_SCENARIOS_DIR, load_scenarios


@pytest.fixture(scope="module")
def scenarios():
    return load_scenarios(DEFAULT_SCENARIOS_DIR)


NOT_APPLICABLE = ["A9", "A10", "A11", "A12", "A14"]
NOT_EXECUTED = ["A3"]                          # defined, but the testbed cannot run it yet (live model)
COMPROMISED = ["A2", "A4"]                     # run through the compromised-responder double
SCRIPTED = ["A1", "A5", "A6", "A8", "A13", "A7"]   # A7 relays through the planner (planner.request)


def test_encoded_set(scenarios):
    assert sorted(scenarios) == sorted(["N1", "N2", "N3", "N4", "P1", *NOT_APPLICABLE, *NOT_EXECUTED,
                                        *COMPROMISED, *SCRIPTED])
    for sid in ("N1", "N2", "N3", "N4"):
        assert scenarios[sid].category == "normal" and scenarios[sid].baseline == "applicable"
    for sid in SCRIPTED:
        assert scenarios[sid].category == "attack" and scenarios[sid].scripted is not None


@pytest.mark.parametrize("sid", NOT_APPLICABLE)
def test_not_applicable_attacks(scenarios, sid):
    s = scenarios[sid]
    assert (s.category, s.baseline) == ("attack", "not_applicable")
    assert s.not_applicable_reason and len(s.not_applicable_reason) > 20
    assert s.agents == [] and s.entry is None and s.success_criteria == []
    assert s.expected_decision                                  # runner-only, from the team sheet


@pytest.mark.parametrize("sid, words", [
    ("A3", "poisoned document")])
def test_not_executed_attacks_have_their_specific_reason(scenarios, sid, words):
    s = scenarios[sid]
    assert (s.category, s.baseline) == ("attack", "not_executed")
    assert words in s.not_executed_reason and s.not_applicable_reason is None
    assert s.agents == [] and s.entry is None and s.scripted is None and s.success_criteria == []


@pytest.mark.parametrize("sid, victim", [("A2", "database"), ("A4", "tool")])
def test_compromised_responder_attacks_are_applicable(scenarios, sid, victim):
    s = scenarios[sid]
    assert (s.category, s.baseline) == ("attack", "applicable")
    [bad] = [a for a in s.agents if a.impl == "malicious"]
    assert bad.name == victim and bad.behaviour is not None
    assert s.entry is not None and s.scripted is None


def test_cli_records_not_executed_separately_and_starts_nothing(tmp_path):
    import csv
    import json

    from runner.__main__ import main
    args = ["--results-dir", str(tmp_path)] + [a for sid in NOT_EXECUTED for a in ("--scenario", sid)]
    assert main(args) == 0
    [run] = list(tmp_path.iterdir())
    with open(run / "results.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert sorted(r["scenario_id"] for r in rows) == sorted(NOT_EXECUTED)
    assert all(r["status"] == "not_executed" and r["attack_succeeded"] == "" and r["not_executed_reason"]
               and r["not_applicable_reason"] == "" for r in rows)
    meta = json.loads((run / "run_meta.json").read_text(encoding="utf-8"))
    assert sorted(meta["not_executed"]) == sorted(NOT_EXECUTED) and meta["not_applicable"] == {}
    with open(run / "summary.csv", encoding="utf-8", newline="") as f:
        assert list(csv.DictReader(f)) == []                      # excluded from every rate
    assert not any(p.is_dir() for p in run.iterdir())             # nothing ran


def test_report_lists_not_executed_under_its_own_heading_with_reasons(tmp_path):
    from runner.__main__ import main
    from runner.report import main as report_main
    assert main(["--results-dir", str(tmp_path), "--scenario", "A3",
                 "--scenario", "A9"]) == 0
    [run] = list(tmp_path.iterdir())
    assert report_main([run.name, "--results-dir", str(tmp_path)]) == 0
    md = (run / "report.md").read_text(encoding="utf-8")
    ne_part = md.split("## Defined, not executed")[1]
    for sid, words in [("A3", "poisoned document")]:
        assert f"**{sid}**: " in ne_part and words in ne_part
    assert "**A9**" not in ne_part and "**A9**" in md.split("## Not applicable in direct mode")[1].split("## Defined")[0]
    results_table = md.split("## Results per scenario")[1].split("## Not applicable")[0]
    assert "| A3 |" not in results_table and "| A9 |" not in results_table      # in no rate table


def test_s6_reasons_for_a10_and_a14(scenarios):
    assert all("S6" in scenarios[sid].not_applicable_reason for sid in ("A10", "A14"))


def test_runner_refuses_to_run_a_not_applicable_scenario(scenarios, tmp_path):
    with pytest.raises(ValueError, match="not applicable"):
        run_repetition(scenarios["A9"], rep=1, run_dir=tmp_path)


def test_cli_records_not_applicable_and_starts_nothing(tmp_path, capsys):
    import csv
    import json

    from runner.__main__ import main
    args = ["--results-dir", str(tmp_path)] + [a for sid in NOT_APPLICABLE for a in ("--scenario", sid)]
    assert main(args) == 0
    [run] = list(tmp_path.iterdir())
    with open(run / "results.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert sorted(r["scenario_id"] for r in rows) == sorted(NOT_APPLICABLE)
    assert all(r["status"] == "not_applicable" and r["attack_succeeded"] == "" and r["not_applicable_reason"]
               for r in rows)
    assert sorted(json.loads((run / "run_meta.json").read_text(encoding="utf-8"))["not_applicable"]) == sorted(NOT_APPLICABLE)
    with open(run / "summary.csv", encoding="utf-8", newline="") as f:
        assert list(csv.DictReader(f)) == []                      # excluded from every rate
    assert not any(p.is_dir() for p in run.iterdir())             # no repetition folders: nothing ran


def test_runner_only_fields(scenarios):
    assert scenarios["N1"].expected_decision == "ALLOW; reply is a total only"
    assert scenarios["N2"].expected_decision == "ALLOW"
    assert scenarios["N3"].expected_decision == "ALLOW"
    assert scenarios["N4"].expected_decision == "ALLOW everything; task completes"
    assert all(s.entitled_parties is None for s in scenarios.values())     # not filled yet


def test_n1_expected_total_matches_the_seed(scenarios):
    [number] = [c for c in scenarios["N1"].success_criteria if c.type == "answer_contains_number"]
    assert number.value == project_total("Project X")


def test_n3_starts_the_mailer_process_and_n1_does_not(scenarios):
    assert [a.name for a in scenarios["N3"].agents] == ["planner", "database", "tool", "mailer"]
    assert "mailer" not in [a.name for a in scenarios["N1"].agents]


def test_n3_keeps_its_fake_llm_script_and_checks_cc_and_bcc_are_empty(scenarios):
    n3 = scenarios["N3"]
    assert sorted(n3.fake_llm) == ["database", "planner", "tool"]            # the mailer needs no LLM script
    decisions = n3.fake_llm["planner"]["planner.decide"]
    assert [d.get("action") or "done" for d in decisions] == [
        "db.query_aggregate", "tool.send_email_internal", "done"]             # same three planner steps as before
    assert decisions[1]["payload"]["to"] == ["alice.morgan@corp.local"] and "cc" not in decisions[1]["payload"]
    assert len(n3.fake_llm["database"]["database.summarise"]) == 1 and len(n3.fake_llm["tool"]["tool.compose_email"]) == 1
    delivered = [c for c in n3.success_criteria
                 if c.type == "ground_truth_count" and c.details.get("to") == ["alice.morgan@corp.local"]]
    assert len(delivered) == 1 and delivered[0].details["cc"] == [] and delivered[0].details["bcc"] == []


def test_n3_goes_through_the_mailer(scenarios, tmp_path):
    [o] = run_repetition(scenarios["N3"], rep=1, run_dir=tmp_path / "results")
    ev = evaluate(scenarios["N3"], o)
    assert o.status == "completed" and ev.task_completed, ev.criteria
    # Three messages: planner -> database, planner -> tool, tool -> mailer.
    assert sorted(e["logged_by"] for e in o.envelopes if e["direction"] == "in") == ["database", "mailer", "tool"]
    mail_in = next(e["envelope"] for e in o.envelopes if e["logged_by"] == "mailer" and e["direction"] == "in")
    assert (mail_in["sender"], mail_in["action"], mail_in["resource"]) == ("tool", "mail.deliver", "mail:outbound")
    assert mail_in["delegation_chain"] == ["user", "planner", "tool"]
    [attempt] = [g for g in o.ground_truth if g["kind"] == "mail.attempt"]
    d = attempt["details"]
    assert (d["status"], d["resource"]) == ("delivered", "mail:outbound")
    assert (d["to"], d["cc"], d["bcc"]) == (["alice.morgan@corp.local"], [], [])
    assert d["external_recipients"] == []
    assert ev.sensitive_hits == 0


@pytest.mark.parametrize("sid", ["N1", "N2", "N3", "N4"])
def test_passes_with_fake_llm(scenarios, sid, tmp_path):
    [o] = run_repetition(scenarios[sid], rep=1, run_dir=tmp_path / "results")
    ev = evaluate(scenarios[sid], o)
    assert o.status == "completed", o.error
    assert ev.task_completed, ev.criteria
    assert ev.sensitive_hits == 0
