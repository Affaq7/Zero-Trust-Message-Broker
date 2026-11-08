"""agents/scripted.py (httpx.post patched), scripted scoring, broker-mode refusal and one fake-LLM run.

No request in the unit tests leaves the process: httpx.post is replaced by a recorder. The integration
tests start the real testbed (fake LLM, local ports only) for one scenario each.
"""

import copy
import csv
import json
import subprocess
from pathlib import Path

import httpx
import jwt
import pytest

import agents.scripted as scripted
from contracts import Envelope
from contracts.version import SCHEMA_VERSION
from runner.evaluate import evaluate
from runner.processes import Testbed, port_is_free
from runner.run import TaskOutcome
from runner.scenarios import load_scenario, load_scenarios
from tests.test_runner.test_scripted import SCRIPTED_EXAMPLE, write

URLS = {"database": "http://127.0.0.1:8101", "tool": "http://127.0.0.1:8102"}


# --- helpers ----------------------------------------------------------------------------------

class Recorder:
    """Stands in for httpx.post. The signature is strict: a proxy argument would be a TypeError."""

    def __init__(self, behaviour=None):
        self.calls: list[dict] = []
        self.behaviour = behaviour or (lambda n, url: httpx.Response(200, json={"payload": {"status": "ok"}}))

    def __call__(self, url, *, content, headers, timeout, trust_env):
        self.calls.append({"url": url, "content": content, "headers": dict(headers),
                           "timeout": timeout, "trust_env": trust_env})
        return self.behaviour(len(self.calls) - 1, url)


@pytest.fixture
def post(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(scripted.httpx, "post", rec)
    return rec


def step(**kw):
    return {"receiver": "database", "action": "db.query_rows", "resource": "db:employees",
            "payload": {"columns": ["name"], "limit": 5}, **kw}


def run_agent(tmp_path, steps, **cfg):
    config = {"agent_urls": URLS, "sender": "research", "sender_role": "research", "steps": steps,
              "log_path": str(tmp_path / "script_log.jsonl"), "trace_id": "trace-1", **cfg}
    path = tmp_path / "script_config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    code = scripted.run(str(path))
    log = Path(config["log_path"])
    entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else None
    return code, entries


def token_claims(call):
    token = call["headers"]["Authorization"].removeprefix("Bearer ")
    return jwt.decode(token, options={"verify_signature": False, "verify_exp": False})


# --- envelope ---------------------------------------------------------------------------------

def test_envelope_fields_are_built_and_autofilled(tmp_path, post):
    code, log = run_agent(tmp_path, [step(), step(action="db.query_aggregate")])
    assert code == 0 and len(post.calls) == 2
    envs = [json.loads(c["content"]) for c in post.calls]
    for env in envs:
        Envelope.model_validate(env)                                    # a valid envelope, built as a dict
        assert env["schema_version"] == SCHEMA_VERSION
        assert env["trace_id"] == "trace-1" and env["parent_msg_id"] is None
        assert env["msg_type"] == "request" and env["timestamp"].endswith("Z")
        assert (env["sender"], env["receiver"]) == ("research", "database")
        assert env["delegation_chain"] == ["user", "research"]
    assert envs[0]["msg_id"] != envs[1]["msg_id"]
    assert post.calls[0]["url"] == "http://127.0.0.1:8101/message"
    assert [e["envelope"] for e in log if "step" in e] == envs          # the log holds exactly what was sent


def test_a_step_can_override_sender_chain_and_message_type(tmp_path, post):
    run_agent(tmp_path, [step(sender="planner", sender_role="planner", delegation_chain=["user", "planner"])])
    env = json.loads(post.calls[0]["content"])
    assert env["sender"] == "planner" and token_claims(post.calls[0])["sub"] == "planner"
    assert token_claims(post.calls[0])["role"] == "planner"            # JWT sub equals the envelope sender


def test_extra_fields_are_merged_at_the_top_level(tmp_path, post):
    run_agent(tmp_path, [step(extra_fields={"trust_score": 0.9, "decision": "ALLOW"})])
    env = json.loads(post.calls[0]["content"])
    assert env["trust_score"] == 0.9 and env["decision"] == "ALLOW"
    assert "trust_score" not in env["payload"] and "extra_fields" not in env


def test_the_payload_is_sent_exactly_as_written(tmp_path, post):
    payload = {"columns": ["a", "b"], "limit": 7, "justification": "text"}
    run_agent(tmp_path, [step(payload=payload)])
    assert json.loads(post.calls[0]["content"])["payload"] == payload


def test_nothing_in_the_request_names_a_scenario_or_an_attack(tmp_path, post):
    run_agent(tmp_path, [step()])
    sent = (post.calls[0]["content"] + json.dumps(post.calls[0]["headers"])).lower()
    assert not any(w in sent for w in ("attack", "scenario", "scripted", "malicious", "test"))


# --- tokens -----------------------------------------------------------------------------------

def test_the_four_token_modes(tmp_path, post):
    steps = [step(token="valid"), step(token="expired"), step(token="wrong_key"), step(token="missing")]
    code, log = run_agent(tmp_path, steps)
    assert code == 0
    valid, expired, wrong, missing = post.calls
    now = jwt.decode(valid["headers"]["Authorization"].removeprefix("Bearer "),
                     options={"verify_signature": False})["iat"]
    for call in (valid, expired, wrong):
        c = token_claims(call)
        assert (c["sub"], c["role"], c["aud"]) == ("research", "research", "database")
    assert token_claims(valid)["exp"] > now and token_claims(wrong)["exp"] > now
    assert token_claims(expired)["exp"] < now                            # expired 600 s ago
    assert token_claims(valid)["cnf"]["jkt"] != token_claims(wrong)["cnf"]["jkt"]
    assert "Authorization" not in missing["headers"]
    assert [e["token_mode"] for e in log if "step" in e] == ["valid", "expired", "wrong_key", "missing"]


def test_the_token_is_only_in_the_authorization_header(tmp_path, post):
    _, log = run_agent(tmp_path, [step(token="valid"), step(token="expired")])
    for call in post.calls:
        token = call["headers"]["Authorization"].removeprefix("Bearer ")
        assert token not in call["content"]                              # never inside the envelope
        assert set(call["headers"]) == {"Content-Type", "Authorization"}   # no proof header, no label header
    log_text = (tmp_path / "script_log.jsonl").read_text(encoding="utf-8")
    assert not any(c["headers"]["Authorization"].removeprefix("Bearer ") in log_text for c in post.calls)
    assert "Bearer" not in log_text and "eyJ" not in log_text            # no JWT in the log


# --- the log and failed sends -------------------------------------------------------------------

def test_log_entries_and_summary_line(tmp_path, post):
    code, log = run_agent(tmp_path, [step(), step()])
    entries, summary = [e for e in log if "step" in e], log[-1]
    assert code == 0 and [e["step"] for e in entries] == [0, 1]
    for e in entries:
        assert {"step", "envelope", "token_mode", "http_status", "response_body", "elapsed_ms",
                "logged_at"} <= set(e)
        assert e["http_status"] == 200 and e["response_body"] == {"payload": {"status": "ok"}}
    assert summary["summary"] is True and summary["steps_total"] == 2
    assert (summary["steps_ok"], summary["steps_error"]) == (2, 0) and summary["finished_at"]
    assert not any("success" in k or "attack" in k for k in summary)    # it never judges the outcome


def test_a_failed_send_is_recorded_and_the_run_continues(tmp_path, monkeypatch):
    def behaviour(n, url):
        if n == 0:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(422, text="not json")
    rec = Recorder(behaviour)
    monkeypatch.setattr(scripted.httpx, "post", rec)
    code, log = run_agent(tmp_path, [step(), step(), step()])
    entries = [e for e in log if "step" in e]
    assert code == 0 and len(rec.calls) == 3
    assert entries[0]["http_status"] == 0 and "connection refused" in entries[0]["response_body"]
    assert (entries[1]["http_status"], entries[1]["response_body"]) == (422, "not json")
    assert log[-1]["steps_ok"] == 0 and log[-1]["steps_error"] == 3


def test_the_log_is_truncated_at_start(tmp_path, post):
    (tmp_path / "script_log.jsonl").write_text('{"step": 99, "stale": true}\n', encoding="utf-8")
    _, log = run_agent(tmp_path, [step()])
    assert all(e.get("step") != 99 for e in log) and len(log) == 2


# --- the 50-step cap -----------------------------------------------------------------------------

def test_a_config_asking_for_500_is_still_capped_at_50(tmp_path, post):
    code, log = run_agent(tmp_path, [step() for _ in range(51)], max_steps=500)
    assert code == 1 and post.calls == [] and log is None                # aborted before any send, no log


def test_exactly_50_steps_run_even_if_the_config_asks_for_more(tmp_path, post):
    code, log = run_agent(tmp_path, [step() for _ in range(50)], max_steps=500)
    assert code == 0 and len(post.calls) == 50 and log[-1]["steps_total"] == 50


def test_a_config_can_lower_the_cap(tmp_path, post):
    code, _ = run_agent(tmp_path, [step() for _ in range(3)], max_steps=2)
    assert code == 1 and post.calls == []


# --- loopback and receivers ---------------------------------------------------------------------

def test_a_non_loopback_url_aborts_before_any_request(tmp_path, post, capsys):
    code, log = run_agent(tmp_path, [step()], agent_urls={"database": "http://93.184.216.34:8101"})
    assert code == 1 and post.calls == [] and log is None
    assert "not loopback" in capsys.readouterr().err


def test_one_bad_url_among_good_ones_aborts_the_whole_run(tmp_path, post):
    code, _ = run_agent(tmp_path, [step()], agent_urls={**URLS, "tool": "http://203.0.113.9:8102"})
    assert code == 1 and post.calls == []


def _resolves_to(monkeypatch, *addresses):
    monkeypatch.setattr(scripted.socket, "getaddrinfo",
                        lambda host, port, *a, **k: [(0, 0, 0, "", (addr, 0)) for addr in addresses])


def test_mixed_address_resolution_aborts(tmp_path, post, monkeypatch):
    _resolves_to(monkeypatch, "127.0.0.1", "93.184.216.34")              # the FIRST address is loopback
    code, _ = run_agent(tmp_path, [step()], agent_urls={"database": "http://agent.example:8101"})
    assert code == 1 and post.calls == []


def test_a_name_resolving_only_to_loopback_is_allowed(tmp_path, post, monkeypatch):
    _resolves_to(monkeypatch, "127.0.0.1", "::1")
    code, _ = run_agent(tmp_path, [step()], agent_urls={"database": "http://agent.example:8101"})
    assert code == 0 and len(post.calls) == 1


@pytest.mark.parametrize("host", ["agent.example", "[::ffff:5db8:d822]"])
def test_unresolvable_or_non_loopback_names_abort(tmp_path, post, monkeypatch, host):
    def refuse(*a, **k):
        raise scripted.socket.gaierror("no such host")
    monkeypatch.setattr(scripted.socket, "getaddrinfo", refuse)
    code, _ = run_agent(tmp_path, [step()], agent_urls={"database": f"http://{host}:8101"})
    assert code == 1 and post.calls == []


def test_loopback_literals_need_no_dns(tmp_path, post, monkeypatch):
    monkeypatch.setattr(scripted.socket, "getaddrinfo", lambda *a, **k: pytest.fail("DNS used"))
    code, _ = run_agent(tmp_path, [step()], agent_urls={"database": "http://127.0.0.1:8101"})
    assert code == 0
    code, _ = run_agent(tmp_path, [step()], agent_urls={"database": "http://[::1]:8101"})
    assert code == 0


def test_an_unknown_receiver_aborts_before_the_first_send(tmp_path, post, capsys):
    code, log = run_agent(tmp_path, [step(), step(receiver="mailer")])  # step 0 is fine, step 1 is not
    assert code == 1 and post.calls == [] and log is None                # not even step 0 went out
    assert "step 1" in capsys.readouterr().err


def test_a_step_missing_a_required_key_aborts_before_any_send(tmp_path, post):
    bad = {"receiver": "database", "action": "db.query_rows"}             # no resource
    code, _ = run_agent(tmp_path, [step(), bad])
    assert code == 1 and post.calls == []


def test_no_request_is_ever_made_with_proxies(tmp_path, post, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")
    run_agent(tmp_path, [step(), step()])
    assert [c["trust_env"] for c in post.calls] == [False, False]        # environment proxies are not read
    assert all(c["url"].startswith("http://127.0.0.1:") for c in post.calls)


# --- attack_succeeded is None unless the run really finished (item 1) ------------------------------

def scripted_scenario(tmp_path, steps=2):
    data = copy.deepcopy(SCRIPTED_EXAMPLE)
    data["scripted"]["steps"] = data["scripted"]["steps"] * steps
    return load_scenario(write(tmp_path, "x2.json", data))


def outcome(status="completed", log=(), **kw):
    return TaskOutcome(scenario_id="X1", rep=1, concurrency=1, slot=0, trace_id="t", started_at="",
                       ended_at="", latency_ms=0, status=status, script_log=list(log), **kw)


OK_ENTRY = {"http_status": 200}


def test_a_complete_run_gives_true_or_false(tmp_path):
    s = scripted_scenario(tmp_path)
    assert evaluate(s, outcome(log=[OK_ENTRY, OK_ENTRY])).attack_succeeded is True
    assert evaluate(s, outcome(log=[{"http_status": 422}, OK_ENTRY])).attack_succeeded is False


@pytest.mark.parametrize("o", [
    outcome(status="error", log=[OK_ENTRY, OK_ENTRY], error="ABORT: step 1 receiver"),   # aborted
    outcome(status="timeout", log=[OK_ENTRY, OK_ENTRY]),                                  # timed out
    outcome(log=[OK_ENTRY]),                                                              # short script_log
    outcome(log=[]),                                                                      # empty script_log
    outcome(log=[OK_ENTRY, OK_ENTRY, OK_ENTRY]),                                          # more than the steps
])
def test_an_errored_timed_out_or_short_run_has_no_outcome(tmp_path, o):
    ev = evaluate(scripted_scenario(tmp_path), o)
    assert ev.attack_succeeded is None                                    # not False
    assert ev.task_completed is None


def test_entry_attack_that_completed_is_scored_true_or_false(tmp_path):
    data = {"id": "X4", "title": "Entry attack", "category": "attack", "baseline": "applicable",
            "agents": [{"name": "dummy"}], "entry": {"agent": "dummy", "task": "hi"},
            "success_criteria": [{"type": "task_status", "value": "ok"}]}
    s = load_scenario(write(tmp_path, "x4.json", data))
    assert evaluate(s, outcome(status="completed", task_status="ok")).attack_succeeded is True
    assert evaluate(s, outcome(status="completed", task_status="error")).attack_succeeded is False
    assert evaluate(s, outcome(status="error")).attack_succeeded is None      # did not complete: no outcome


def test_none_is_left_out_of_the_csv_summary_and_report(tmp_path):
    from agents.llm import LLMSettings
    from runner.report import load_run, scenario_rows
    from runner.results import ResultsWriter
    s = scripted_scenario(tmp_path)
    w = ResultsWriter(tmp_path / "results", "run1")
    w.start([s], reps=3, llm_backend="fake", llm=LLMSettings(), max_minutes=None)
    for rep, o in enumerate([outcome(log=[OK_ENTRY, OK_ENTRY]),
                             outcome(status="error", log=[]),
                             outcome(log=[{"http_status": 422}, OK_ENTRY])], 1):
        o.rep = rep
        w.add(s, o, evaluate(s, o))
    w.finish()
    with open(w.dir / "results.csv", encoding="utf-8", newline="") as f:
        assert [r["attack_succeeded"] for r in csv.DictReader(f)] == ["true", "", "false"]
    with open(w.dir / "summary.csv", encoding="utf-8", newline="") as f:
        [row] = list(csv.DictReader(f))
    assert (row["runs"], row["attack_succeeded"]) == ("3", "1/2")        # the errored run is not in the rate
    meta, rows = load_run(w.dir)
    [line] = scenario_rows(rows)
    assert line["attack_succeeded"] == "1/2"


# --- --mode broker refuses scripted scenarios (item 6) -----------------------------------------

def test_broker_mode_refuses_an_explicit_scripted_scenario(tmp_path, capsys):
    from runner.__main__ import main
    code = main(["--results-dir", str(tmp_path), "--mode", "broker", "--scenario", "A1"])
    err = capsys.readouterr().err
    assert code == 2
    assert "not supported in broker mode yet: the broker address is undecided" in err
    assert list(tmp_path.iterdir()) == []                                 # not run, no results folder, not scored


def test_broker_mode_skips_scripted_scenarios_when_none_were_named(tmp_path, capsys):
    from runner.__main__ import main
    scen = tmp_path / "scen"
    scen.mkdir()
    write(scen, "x1.json", SCRIPTED_EXAMPLE)
    write(scen, "x5.json", {"id": "X5", "title": "Defined only", "category": "attack", "baseline": "not_executed",
                            "not_executed_reason": "needs something that is not built"})
    code = main(["--results-dir", str(tmp_path / "res"), "--scenarios-dir", str(scen), "--mode", "broker"])
    out = capsys.readouterr()
    assert code == 0 and "not supported in broker mode yet" in out.err
    [run] = list((tmp_path / "res").iterdir())
    with open(run / "results.csv", encoding="utf-8", newline="") as f:
        assert [(r["scenario_id"], r["status"]) for r in csv.DictReader(f)] == [("X5", "not_executed")]


def test_direct_mode_still_accepts_scripted_scenarios(tmp_path):
    from runner.__main__ import main
    assert main(["--results-dir", str(tmp_path), "--scenario", "A1", "--dry-run"]) == 0


# --- the real run path with the fake LLM (items 2 and 8) ------------------------------------------

@pytest.fixture
def captured_testbeds(monkeypatch):
    seen = []

    class Capturing(Testbed):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            seen.append(self)
    monkeypatch.setattr("runner.run.Testbed", Capturing)
    return seen


def stopped(tb):
    started = [p for p in tb.procs.values() if p.popen]
    return bool(started) and all(p.popen.poll() is not None and port_is_free(p.port) for p in started)


def test_fake_llm_run_through_the_cli_records_a_well_formed_row(tmp_path, captured_testbeds):
    from runner.__main__ import main
    assert main(["--results-dir", str(tmp_path), "--scenario", "A1", "--llm", "fake", "--reps", "1"]) == 0
    [run] = list(tmp_path.iterdir())
    with open(run / "results.csv", encoding="utf-8", newline="") as f:
        [row] = list(csv.DictReader(f))
    assert (row["scenario_id"], row["status"], row["concurrency"], row["slot"]) == ("A1", "completed", "1", "0")
    assert row["attack_succeeded"] == "true" and (row["criteria_passed"], row["criteria_total"]) == ("3", "3")
    assert row["task_completed"] == "" and row["criteria_failed"] == ""
    assert row["llm_calls"] == "1"                      # the database agent's summary call is now counted
    assert row["llm_time_ms"] != "" and row["messages"] == "1"          # one request received by the victim
    criteria = [json.loads(line) for line in (run / "criteria.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [c["passed"] for c in criteria[0]["criteria"]] == [True, True, True]
    assert [c["type"] for c in criteria[0]["criteria"]] == ["script_step_status", "script_step_payload_status",
                                                            "ground_truth_count"]
    with open(run / "summary.csv", encoding="utf-8", newline="") as f:
        assert [r["attack_succeeded"] for r in csv.DictReader(f)] == ["1/1"]
    [rep_dir] = [p for p in run.rglob("script_log.jsonl")]
    log = [json.loads(line) for line in rep_dir.read_text(encoding="utf-8").splitlines()]
    assert log[0]["http_status"] == 200 and log[-1]["summary"] is True
    assert "Bearer" not in rep_dir.read_text(encoding="utf-8")
    assert len(captured_testbeds) == 1 and stopped(captured_testbeds[0])           # torn down


def test_run_scripted_repetition_collects_llm_calls_and_ground_truth(tmp_path, captured_testbeds):
    from runner.run import run_scripted_repetition
    s = load_scenarios()["A1"]
    [o] = run_scripted_repetition(s, 1, tmp_path)
    assert o.status == "completed" and len(o.script_log) == 1
    assert len(o.llm_calls) == 1 and o.llm_calls[0]["purpose"] == "database.summarise"
    assert any(g["kind"] == "db.query" for g in o.ground_truth)
    assert stopped(captured_testbeds[0])


@pytest.mark.parametrize("how, status", [
    ("timeout", "timeout"), ("abort", "error")])
def test_a_failed_attacker_process_is_not_scored_and_everything_is_torn_down(
        tmp_path, captured_testbeds, monkeypatch, how, status):
    from runner.run import run_scripted_repetition
    s = load_scenarios()["A5"]
    real_run = subprocess.run

    def fake_run(cmd, **kw):
        if "agents.scripted" not in " ".join(map(str, cmd)):
            return real_run(cmd, **kw)
        if how == "timeout":
            raise subprocess.TimeoutExpired(cmd, 1)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="ABORT: step 0 receiver 'x' has no URL")
    monkeypatch.setattr("runner.run.subprocess.run", fake_run)
    [o] = run_scripted_repetition(s, 1, tmp_path)
    assert o.status == status and o.script_log == [] and o.error
    assert evaluate(s, o).attack_succeeded is None
    assert stopped(captured_testbeds[0])
