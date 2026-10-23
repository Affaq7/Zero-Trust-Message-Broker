"""M2 step 11: planner agent (LangGraph) with the fake LLM and a recording sender."""

import json

import pytest

from agents.base import TaskContext
from agents.planner import PlannerAgent, planner_actions
from contracts import make_response, new_request
from contracts.catalog import get_catalog
from contracts.payloads import ResponsePayload
from wrapper.send import UnknownReceiverError


class RecordingSender:
    """Stands in for send_message(); answers every request with a fixed result."""

    def __init__(self, result=None, fail_for=()):
        self.calls = []
        self.result = result if result is not None else {"rows": [{"value": 20}]}
        self.fail_for = set(fail_for)

    def __call__(self, *, receiver, action, resource, payload, chain_so_far, trace_id):
        self.calls.append(dict(receiver=receiver, action=action, resource=resource,
                               payload=payload, chain_so_far=chain_so_far, trace_id=trace_id))
        if action in self.fail_for:
            raise UnknownReceiverError(f"no URL for receiver {receiver!r}")
        req = new_request(sender="planner", receiver=receiver, action=action, resource=resource,
                          payload=payload, chain_so_far=chain_so_far, trace_id=trace_id)
        return make_response(req, ResponsePayload(status="ok", result=self.result))


def step(action, resource, payload):
    return {"done": False, "action": action, "resource": resource, "payload": payload, "reason": "next"}


def finish(answer):
    return {"done": True, "answer": answer}


COUNT = step("db.query_aggregate", "db:employees", {"metric": "count"})
CTX = TaskContext(task="How many employees are there?", trace_id="trace-plan")


@pytest.fixture
def make_planner(fake_llm):
    def _make(replies, sender=None, max_steps=4):
        sender = sender or RecordingSender()
        planner = PlannerAgent(fake_llm("planner", {"planner.decide": replies}), sender, max_steps)
        return planner, sender
    return _make


def test_available_actions_come_from_the_catalog():
    actions = planner_actions()
    assert actions["db.query_aggregate"] == "database"
    assert actions["tool.send_email_internal"] == "tool"
    assert "web.fetch_page" not in actions            # planner may not call it
    assert "admin.change_policy" not in actions       # nobody may call it


def test_planner_knows_the_real_database_schema(tmp_path):
    import sqlite3
    from contextlib import closing

    from agents.planner import DATA_TABLES
    from mocks.seed import build_database

    db = tmp_path / "schema.sqlite"
    build_database(db)
    with closing(sqlite3.connect(db)) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        actual = {t: [c[1] for c in conn.execute(f'PRAGMA table_info("{t}")')] for t in tables}
    assert DATA_TABLES == actual


def test_system_prompt_fits_with_room_to_spare(fake_llm):
    from agents.llm import LLMSettings, estimate_tokens
    from agents.planner import MAX_RESULT_CHARS
    planner = PlannerAgent(fake_llm("planner", {}), RecordingSender())
    assert "db:project_costs" in planner.system
    system = estimate_tokens(planner.system)
    full_history = planner.max_steps * (MAX_RESULT_CHARS // 3 + 30)
    s = LLMSettings()
    assert system < 1500
    assert system + full_history + 200 + s.num_predict < s.num_ctx * 0.8   # well under num_ctx


def test_every_planner_action_has_a_guide_with_a_valid_example():
    from agents.planner import ACTION_GUIDE
    from contracts.payloads import validate_payload
    assert set(ACTION_GUIDE) == set(planner_actions())
    for action, (use_when, resource, payload) in ACTION_GUIDE.items():
        validate_payload(action, payload)                      # raises if the example drifted
        assert use_when and resource.split(":")[0] in {"db", "file", "email"}


def test_db_examples_use_real_tables_columns_and_values():
    from agents.planner import ACTION_GUIDE, DATA_TABLES, PROJECT_NAMES
    from mocks.seed import PROJECTS
    assert PROJECT_NAMES == [name for _, name, _ in PROJECTS]
    for action, (_, resource, payload) in ACTION_GUIDE.items():
        if not resource.startswith("db:"):
            continue
        columns = DATA_TABLES[resource.removeprefix("db:")]
        used = set(payload.get("filters", {})) | set(payload.get("columns", [])) | \
            set(payload.get("group_by", [])) | set(payload.get("updates", {})) | \
            ({payload["column"]} if payload.get("column") else set())
        assert used <= set(columns), (action, used - set(columns))


def test_prompt_states_the_rules_that_failed_live(fake_llm):
    system = PlannerAgent(fake_llm("planner", {}), RecordingSender()).system
    assert "Totals and counts: use db.query_aggregate" in system
    assert "It is never a list" in system and "group_by is a list" in system
    assert "Project names, exactly: Project X, Project Y, Project Z." in system
    assert system.count("example:") == len(planner_actions())


def test_pinned_prompt_actions_are_still_allowed_by_the_catalog():
    # If the catalog stops letting the planner call one of the pinned actions, say so loudly.
    from agents.planner import FROZEN_PROMPT_ACTIONS
    catalog = get_catalog()
    assert all(catalog.is_allowed("planner", a) for a in FROZEN_PROMPT_ACTIONS)
    assert set(planner_actions()) == set(FROZEN_PROMPT_ACTIONS)


def test_contract_additions_do_not_reach_the_frozen_prompt(fake_llm):
    # research.lookup is allowed for the planner in the catalog (S10) but the frozen
    # prompt neither offers nor can send it; planner.request/mail.deliver are not planner calls.
    catalog = get_catalog()
    assert catalog.is_allowed("planner", "research.lookup")
    assert "research.lookup" not in planner_actions()
    assert not catalog.is_allowed("planner", "mail.deliver") and not catalog.is_allowed("planner", "planner.request")
    system = PlannerAgent(fake_llm("planner", {}), RecordingSender()).system
    for text in ("research.lookup", "planner.request", "mail.deliver", "justification", "cc (", "bcc (",
                 "max_sources", "mailer"):
        assert text not in system, text


def test_pinned_fields_exist_in_the_payload_models_and_are_shown_in_order():
    from agents.planner import FROZEN_PROMPT_FIELDS, _fields_text
    from contracts.payloads import ACTION_SCHEMAS
    for action, names in FROZEN_PROMPT_FIELDS.items():
        assert set(names) <= set(ACTION_SCHEMAS[action].model_fields), action
        assert [part.split(" (")[0] for part in _fields_text(ACTION_SCHEMAS[action], names).split("; ")] == list(names)


def test_planner_cannot_send_an_action_the_frozen_prompt_does_not_offer(fake_llm):
    sender = RecordingSender()
    planner = PlannerAgent(fake_llm("planner", {"planner.decide": [
        step("research.lookup", "research:query", {"query": "policy", "max_sources": 1}),
        finish("Could not look it up.")]}), sender)
    assert planner.run_task(CTX).status == "ok"
    assert sender.calls == []                                   # nothing was sent


def test_prompt_has_the_stopping_rules(fake_llm):
    system = PlannerAgent(fake_llm("planner", {}), RecordingSender()).system
    assert "When a send-email action returns DELIVERED, that email has been sent and is done" in system
    assert "never send it again. Finish with a short confirmation." in system
    assert "Finish as soon as everything the task asks for is done." in system
    assert ("If the task only asks for a total or a count, finish right after db.query_aggregate "
            "returns the value") in system
    assert "If it also asks you to send an email, send it first." in system


@pytest.mark.parametrize("action, payload, expected", [
    ("tool.send_email_internal",
     {"status": "ok", "result": {"status": "delivered", "to": ["alice.morgan@corp.local"]}, "error": None},
     "DELIVERED. The email has been sent to alice.morgan@corp.local. It is done; do not send it again."),
    ("tool.send_email_external",
     {"status": "ok", "result": {"status": "delivered", "to": ["partner@example.org"]}, "error": None},
     "DELIVERED. The email has been sent to partner@example.org. It is done; do not send it again."),
    ("db.query_aggregate", {"status": "ok", "result": {"rows": [{"value": 184250}]}, "error": None},
     'OK. Result: {"rows": [{"value": 184250}]}'),
    ("tool.send_email_internal", {"status": "error", "result": None, "error": "invalid payload: to: bad"},
     "ERROR: invalid payload: to: bad"),
])
def test_step_outcome_rendering(action, payload, expected):
    from agents.planner import render_outcome
    assert render_outcome(action, payload) == expected


def test_delivered_email_is_explicit_in_the_next_prompt(fake_llm, tmp_path, monkeypatch):
    monkeypatch.setenv("PLANNER_DEBUG_PROMPTS", "1")
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    email = step("tool.send_email_internal", "email:internal",
                 {"to": ["alice.morgan@corp.local"], "subject": "Hi", "body": "Placeholder."})
    sender = RecordingSender(result={"status": "delivered", "to": ["alice.morgan@corp.local"]})
    planner = PlannerAgent(fake_llm("planner", {"planner.decide": [email, finish("Sent.")]}), sender)
    assert planner.run_task(CTX).answer == "Sent."
    step2 = (tmp_path / "prompts" / "planner" / CTX.trace_id / "step02.txt").read_text(encoding="utf-8")
    assert "Step 1: tool.send_email_internal on email:internal -> DELIVERED. The email has been sent" in step2


def test_prompt_has_the_action_name_rule(fake_llm):
    system = PlannerAgent(fake_llm("planner", {}), RecordingSender()).system
    assert "Action names use a dot exactly as listed (db.query_aggregate); db: is only for resources." in system


def _last_line(planner, history, steps=None):
    state = {"task": CTX.task, "trace_id": "t", "chain": ["user"], "history": history,
             "steps": len(history) if steps is None else steps, "decision": None,
             "answer": None, "error": None}
    return planner._prompt(state).splitlines()[-1]


AFTER_SUCCESS = ('If the task only asks for information and the results above contain it, or any '
                 'email the task asks for has been DELIVERED, reply {"done": true, "answer": "..."} now. '
                 'If an email the task asks for has not been sent yet, send it now.')
OK_STEP = {"action": "db.query_aggregate", "resource": "db:project_costs",
           "outcome": 'OK. Result: {"rows": [{"value": 184250}]}'}
DELIVERED_STEP = {"action": "tool.send_email_internal", "resource": "email:internal",
                  "outcome": "DELIVERED. The email has been sent to alice.morgan@corp.local. "
                             "It is done; do not send it again."}
ERROR_STEP = {"action": "db:query_aggregate", "resource": "db:project_costs",
              "outcome": "ERROR: 'db:query_aggregate' is not an available action"}


@pytest.mark.parametrize("history, expected", [
    ([], "Choose the next action, or finish."),                     # first step
    ([OK_STEP], AFTER_SUCCESS),
    ([DELIVERED_STEP], AFTER_SUCCESS),
    ([ERROR_STEP], "Choose the next action, or finish."),           # after an error: unchanged
    ([ERROR_STEP, OK_STEP], AFTER_SUCCESS),                          # only the last step counts
    ([OK_STEP, ERROR_STEP], "Choose the next action, or finish."),
])
def test_closing_line_depends_on_the_last_step(fake_llm, history, expected):
    planner = PlannerAgent(fake_llm("planner", {}), RecordingSender())
    assert _last_line(planner, history) == expected


def test_email_task_after_db_result_is_not_told_to_finish(fake_llm):
    # Live N3 (run 20261021T221652Z) finished after the total, without the email.
    planner = PlannerAgent(fake_llm("planner", {}), RecordingSender())
    state = {"task": "Email a short summary of the total cost of Project X to alice.morgan@corp.local.",
             "trace_id": "t", "chain": ["user"], "history": [OK_STEP], "steps": 1,
             "decision": None, "answer": None, "error": None}
    line = planner._prompt(state).splitlines()[-1]
    assert line == AFTER_SUCCESS
    assert "If the results above answer the task" not in line       # the wording that skipped the email
    # N3 after the total: the email is not sent yet, so the line says to send it.
    assert line.endswith("If an email the task asks for has not been sent yet, send it now.")


def test_total_only_task_is_told_to_finish_after_db_result(fake_llm):
    # Live N1 (run 20261021T223652Z) repeated the same query 4 times under
    # "If the task is fully done ...": a question was never "done".
    planner = PlannerAgent(fake_llm("planner", {}), RecordingSender())
    line = _last_line(planner, [OK_STEP])
    assert line == AFTER_SUCCESS
    assert line.startswith('If the task only asks for information and the results above contain it')
    assert 'reply {"done": true, "answer": "..."} now' in line
    assert "fully done" not in line


def test_after_delivered_the_line_says_finish(fake_llm):
    planner = PlannerAgent(fake_llm("planner", {}), RecordingSender())
    line = _last_line(planner, [OK_STEP, DELIVERED_STEP])
    assert "any email the task asks for has been DELIVERED, reply {\"done\": true" in line


def test_frozen_planner_prompt_matches_recorded_hash():
    # The planner prompt is frozen for the baseline. Changing anything the model
    # sees (rules, examples, closing lines, step rendering) changes this hash;
    # update docs/measurements.md deliberately, with a note, before it passes.
    import re
    from pathlib import Path

    from agents.planner import prompt_fingerprint
    doc = (Path(__file__).resolve().parents[2] / "docs" / "measurements.md").read_text(encoding="utf-8")
    recorded = re.search(r"Frozen planner prompt SHA-256: `([0-9a-f]{64})`", doc)
    assert recorded, "docs/measurements.md has no 'Frozen planner prompt SHA-256' line"
    assert prompt_fingerprint() == recorded.group(1), \
        "the planner prompt changed: if intended, record the new hash in docs/measurements.md"


def test_any_prompt_edit_changes_the_fingerprint(monkeypatch):
    import agents.planner as planner_module
    before = planner_module.prompt_fingerprint()
    monkeypatch.setattr(planner_module, "AFTER_SUCCESS", planner_module.AFTER_SUCCESS.replace("now.", "now!"))
    assert planner_module.prompt_fingerprint() != before
    monkeypatch.undo()
    monkeypatch.setattr(planner_module, "SYSTEM", planner_module.SYSTEM + " ")
    assert planner_module.prompt_fingerprint() != before


def test_step_limit_line_still_wins(fake_llm):
    planner = PlannerAgent(fake_llm("planner", {}), RecordingSender(), max_steps=1)
    assert _last_line(planner, [OK_STEP]) == "You have used all your steps. Finish now with the final answer."


def test_debug_saves_each_reply_next_to_its_prompt(fake_llm, tmp_path, monkeypatch):
    monkeypatch.setenv("PLANNER_DEBUG_PROMPTS", "1")
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    planner = PlannerAgent(fake_llm("planner", {"planner.decide": [COUNT, finish("20")]}), RecordingSender())
    planner.run_task(CTX)
    folder = tmp_path / "prompts" / "planner" / CTX.trace_id
    first = json.loads((folder / "step01.reply.json").read_text(encoding="utf-8"))
    assert (first["done"], first["action"], first["payload"]) == (False, "db.query_aggregate", {"metric": "count"})
    second = json.loads((folder / "step02.reply.json").read_text(encoding="utf-8"))
    assert (second["done"], second["answer"]) == (True, "20")
    assert AFTER_SUCCESS in (folder / "step02.txt").read_text(encoding="utf-8")


def test_debug_saves_the_error_when_the_llm_fails(fake_llm, tmp_path, monkeypatch):
    monkeypatch.setenv("PLANNER_DEBUG_PROMPTS", "1")
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    planner = PlannerAgent(fake_llm("planner", {"planner.decide": ["not json", "still not json"]}), RecordingSender())
    assert planner.run_task(CTX).status == "error"
    reply = json.loads((tmp_path / "prompts" / "planner" / CTX.trace_id / "step01.reply.json").read_text(encoding="utf-8"))
    assert reply["error"].startswith("LLMOutputError")


def test_debug_prompts_off_by_default(fake_llm, tmp_path, monkeypatch):
    monkeypatch.delenv("PLANNER_DEBUG_PROMPTS", raising=False)
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    planner = PlannerAgent(fake_llm("planner", {"planner.decide": [finish("x")]}), RecordingSender())
    planner.run_task(CTX)
    assert not (tmp_path / "prompts").exists()


def test_debug_prompts_written_per_step(fake_llm, tmp_path, monkeypatch):
    monkeypatch.setenv("PLANNER_DEBUG_PROMPTS", "1")
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    planner = PlannerAgent(fake_llm("planner", {"planner.decide": [COUNT, finish("20")]}), RecordingSender())
    planner.run_task(CTX)
    folder = tmp_path / "prompts" / "planner" / CTX.trace_id
    assert sorted(p.name for p in folder.iterdir()) == [
        "step01.reply.json", "step01.txt", "step02.reply.json", "step02.txt"]
    step2 = (folder / "step02.txt").read_text(encoding="utf-8")
    assert step2.startswith("--- SYSTEM ---") and "--- USER ---" in step2
    assert "User task: How many employees are there?" in step2 and "Step 1: db.query_aggregate" in step2


def test_one_step_then_answer(make_planner, llm_calls):
    planner, sender = make_planner([COUNT, finish("There are 20 employees.")])
    result = planner.run_task(CTX)
    assert (result.status, result.answer) == ("ok", "There are 20 employees.")
    assert sender.calls == [dict(receiver="database", action="db.query_aggregate", resource="db:employees",
                                 payload={"metric": "count"}, chain_so_far=["user"], trace_id="trace-plan")]
    assert [c["purpose"] for c in llm_calls("planner")] == ["planner.decide", "planner.decide"]


def test_answer_without_actions(make_planner):
    planner, sender = make_planner([finish("Nothing to do.")])
    assert planner.run_task(CTX).answer == "Nothing to do."
    assert sender.calls == []


def test_two_steps_route_to_their_servers(make_planner):
    email = step("tool.send_email_internal", "email:internal",
                 {"to": ["colleague@corp.local"], "subject": "Count", "body": "20 employees"})
    planner, sender = make_planner([COUNT, email, finish("Sent.")])
    assert planner.run_task(CTX).status == "ok"
    assert [c["receiver"] for c in sender.calls] == ["database", "tool"]


def test_unavailable_action_is_reported_back_not_sent(make_planner):
    planner, sender = make_planner([step("web.fetch_page", "https://news.example.com/q3-market", {}),
                                    COUNT, finish("20")])
    assert planner.run_task(CTX).answer == "20"
    assert [c["action"] for c in sender.calls] == ["db.query_aggregate"]


def test_send_failure_is_reported_back(make_planner):
    planner, sender = make_planner([COUNT, finish("Could not reach the database.")],
                                   sender=RecordingSender(fail_for={"db.query_aggregate"}))
    result = planner.run_task(CTX)
    assert result.status == "ok" and "Could not reach" in result.answer
    assert len(sender.calls) == 1


def test_step_limit_forces_an_answer(make_planner):
    planner, sender = make_planner([COUNT, COUNT, finish("20 after two looks.")], max_steps=2)
    assert planner.run_task(CTX).answer == "20 after two looks."
    assert len(sender.calls) == 2


def test_never_finishing_is_an_error(make_planner):
    planner, sender = make_planner([COUNT, COUNT, COUNT], max_steps=2)
    result = planner.run_task(CTX)
    assert result.status == "error" and "step limit" in result.error
    assert len(sender.calls) == 2


def test_llm_failure_is_a_task_error(make_planner):
    planner, _ = make_planner(["not json", "still not json"])
    result = planner.run_task(CTX)
    assert result.status == "error" and "planner LLM failed" in result.error


def test_long_results_are_cut_before_the_next_prompt(make_planner, llm_calls):
    big = RecordingSender(result={"content": "x" * 50000})
    planner, _ = make_planner([COUNT, finish("done")], sender=big)
    assert planner.run_task(CTX).status == "ok"
    second = llm_calls("planner")[1]
    assert second["ok"] and second["est_prompt_tokens"] + second["num_predict"] <= second["num_ctx"]


def test_planner_accepts_no_messages_yet():
    from agents.planner import handle
    env = new_request(sender="research", receiver="planner", action="db.query_rows",
                      resource="db:employees", payload={}, chain_so_far=["user"])
    out = handle(env)
    assert out.status == "error" and "accepts no messages" in out.error
