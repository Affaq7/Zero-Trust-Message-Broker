"""F4 in the runner: a per-run read token for the broker's feeds (memory and process env only),
used for the runner's own /api/state and /api/events calls; the dashboard URL is printed without
the token; --hold keeps the broker up for a live demo."""

import builtins
import glob
import json
import re

import runner.run as run_module
from runner.processes import Testbed, TestbedConfig

AGENTS = [{"name": "planner"}, {"name": "database"}]


def test_the_read_token_reaches_the_broker_only(tmp_path):
    tb = Testbed(TestbedConfig(agents=AGENTS, run_dir=tmp_path, mode="broker", broker_real=["identity"]))
    tb._plan()
    try:
        token = tb.read_token
        assert token and len(token) >= 32 and token not in (tb.admin_token, tb.forward_token)
        assert tb.procs["broker"].env["BROKER_READ_TOKEN"] == token
        assert all("BROKER_READ_TOKEN" not in p.env for n, p in tb.procs.items() if n != "broker")
    finally:
        tb.stop()


def test_direct_mode_has_no_read_token(tmp_path):
    tb = Testbed(TestbedConfig(agents=AGENTS, run_dir=tmp_path))
    tb._plan()
    assert tb.read_token is None and all("BROKER_READ_TOKEN" not in p.env for p in tb.procs.values())


def test_collect_broker_sends_the_read_token(monkeypatch):
    calls = []

    class Resp:
        def __init__(self, data):
            self.data = data

        def json(self):
            return self.data

    def get(url, **kw):
        calls.append((url, kw.get("headers")))
        return Resp({"real": []} if url.endswith("/health") else {"events": []})

    monkeypatch.setattr(run_module.httpx, "get", get)
    run_module.collect_broker("http://broker.test", ["t1"], "read-placeholder")
    assert ("http://broker.test/api/events", {"X-Read-Token": "read-placeholder"}) in calls


def test_a9_broker_run_writes_broker_state_and_holds_for_the_demo(tmp_path, monkeypatch, capsys):
    from runner.__main__ import main
    prompts = []
    monkeypatch.setattr(builtins, "input", lambda *a: prompts.append(a) or "")
    assert main(["--results-dir", str(tmp_path), "--mode", "broker", "--llm", "fake", "--reps", "1",
                 "--scenario", "A9", "--hold"]) == 0
    out = capsys.readouterr().out
    urls = re.findall(r"broker dashboard: (\S+)", out)
    assert len(urls) == 1 and re.fullmatch(r"http://127\.0\.0\.1:\d+/dashboard", urls[0])   # no token in it
    token = re.search(r"the read token for the dashboard: (\S+)", out).group(1)
    assert len(prompts) == 3 and token not in urls[0]     # before the run, before the release, before stop
    assert "next: admin release of research by kissa" in out

    [state_file] = glob.glob(str(tmp_path / "*" / "**" / "broker_state.json"), recursive=True)
    state = json.loads(open(state_file, encoding="utf-8").read())
    assert {"counters", "agents", "pending_approvals", "trust_history"} <= set(state)
    # A9 quarantines research, then the scenario releases it (an admin step by kissa).
    assert state["counters"]["defence"]["quarantine"] == 1 and state["counters"]["defence"]["release"] == 1
    assert state["counters"]["reason_codes"]["AGENT_QUARANTINED"] >= 1
    assert [p[2] for p in state["trust_history"]["research"]][-1] == "Restricted"     # released into Restricted
    # The token is printed for the operator only: it is never written into the results.
    for path in glob.glob(str(tmp_path / "**" / "*"), recursive=True):
        try:
            assert token not in open(path, encoding="utf-8").read(), path
        except (IsADirectoryError, PermissionError, UnicodeDecodeError):
            pass
