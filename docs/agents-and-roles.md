# Agents and roles

Generated from `contracts/action_catalog.yaml` (v0.2, with the provisional
Q11 caller changes and the additive changes S10-S15 agreed by Kissa and Amna
on 2026-10-24; `schema_version` is still "0.2") and `wrapper/registry.py`.
The catalog is enforced by the broker only; direct mode ignores it.

| Agent | Role | Actions it may call | Actions it serves | Built and registered? |
|---|---|---|---|---|
| planner | planner | `db.query_aggregate`, `db.query_rows`, `db.update_records`, `file.read_internal`, `file.delete`, `tool.send_email_internal`, `tool.send_email_external`, `research.lookup` | `planner.request` | yes: message handler (still replies with an error, since it has no handler for `planner.request` yet) and task handler (`POST /task`, the entry point). The frozen prompt offers only the first seven actions: it neither offers nor sends `research.lookup` (S17) |
| research | research | `db.query_aggregate`, `file.read_internal`, `web.fetch_page`, `planner.request` | `research.lookup` | message handler only (`agents/research.py`, LangGraph; no `/task`). It reads the sources the planner names (`file:/...` or http(s)) through the tool agent, makes one LLM call to answer, and may take one extra action. It does not use `planner.request`: calling back into the agent that waits for its reply is not built. Not yet offered by the planner (the frozen prompt does not know `research.lookup`). Its prompt is NOT frozen yet: `agents.research.prompt_fingerprint()` (system prompt plus five fixed sample states) is the value to record and test when it is declared stable. `RESEARCH_DEBUG_PROMPTS=1` (set by `--debug-prompts`) writes each decision's prompt and reply to `logs/prompts/research/` |
| database | database | none | `db.query_aggregate`, `db.query_rows`, `db.update_records` | yes: message handler |
| tool | tool | `mail.deliver` | `file.read_internal`, `file.delete`, `web.fetch_page`, `tool.send_email_internal`, `tool.send_email_external`; also handles `admin.change_policy` when a scenario sends it there (M4), although the catalog serves it nobody | yes: message handler. Files, web pages and policy changes go to the mock services; **email is drafted with the LLM and sent to the mailer as a `mail.deliver` message** (it never calls the mail sink itself) |
| mailer | mailer | none | `mail.deliver` | yes: message handler, deterministic, no LLM, no `/task`. Applies no access rule: in direct mode it accepts `mail.deliver` from any sender, passes the message to the mock mail sink and returns the sink's answer, as the wrapper does for every other agent (the catalog says only the tool may call `mail.deliver`; the broker enforces that). It refuses only an action other than `mail.deliver`, which it cannot perform. **It is the only thing that calls the sink.** A scenario whose tool sends mail must list `mailer` among its agents |
| malicious | the victim's role (it runs as `AGENT_NAME=<victim>`, so `AGENT_ROLE` is unset and defaults to the victim's catalog role) | as a **compromised responder** it serves the victim's own actions, reusing the honest code path (`agents/malicious.py`); it applies one data-driven deviation from the scenario's `behaviour` block (A2: append a leak query to an aggregate reply; A4: add one external recipient to the mail.deliver) | the victim's actions | **yes** (built 2026-11-08): message handler, registered in `wrapper/registry.py`. Deterministic, no own LLM decision, loopback only, honest with no behaviour data. Used by A2 (`database`) and A4 (`tool`) |

Every action in the catalog, with its caller and server:

| Action | Class | Caller | Served by | Resource |
|---|---|---|---|---|
| `db.query_aggregate` | Permitted | planner, research | database | `db:<table>` |
| `db.query_rows` | Conditional | planner | database | `db:<table>` |
| `db.update_records` | Conditional | planner | database | `db:<table>` |
| `file.read_internal` | Permitted | planner, research | tool | `file:/<path>` |
| `file.delete` | Conditional | planner | tool | `file:/<path>` |
| `web.fetch_page` | Permitted | research | tool | the URL |
| `tool.send_email_internal` | Permitted | planner | tool | `email:internal` |
| `tool.send_email_external` | Conditional | planner | tool | `email:external` |
| `research.lookup` | Permitted | planner | research | `research:query` |
| `planner.request` | Permitted | research | planner | `planner:request` (my choice, S11) |
| `mail.deliver` | Permitted | tool | mailer | `mail:outbound` (my choice, S12) |
| `admin.change_policy` | Prohibited | nobody | nobody | `policy:<id>` (M15) |

The catalog has no field for resources or risk ratings; resource names
live in this table and in `docs/open-questions.md`, ratings in S16.

Optional payload fields added without changing who may call anything:
`justification` (max 500 characters) on `db.query_rows`, `db.update_records`,
`file.delete` and `tool.send_email_external` only (S13); `cc` and `bcc`
(lists, same limits as `to`) on both email actions and `mail.deliver`, with
every recipient list normalised by `normalize_address` (strip, lowercase)
and aliases unsupported (S14).

How a mail flows (direct mode): planner -> tool (`tool.send_email_internal` /
`tool.send_email_external`) -> mailer (`mail.deliver`, resource `mail:outbound`,
sender `tool`, delegation chain `user, planner, tool`) -> mock mail sink (plain
HTTP, recorded as a `mail.attempt`: `delivered` or `failed`, with the
normalised `to`, `cc` and `bcc`). The tool normalises the recipient lists with
`normalize_address` and always states `cc` and `bcc` (empty if none were
requested); fields that belong to the request only, such as `justification`,
are not forwarded. The sink never knows the intended recipients: the scenario
file does.

Not in the catalog:

| Name | Notes |
|---|---|
| dummy | Test agent in the registry only (fixed reply, accepts tasks). Not a catalog agent and has no role, so it cannot mint tokens unless `AGENT_ROLE` is set. |

How the role is chosen at runtime (`wrapper/app.py`): `AGENT_ROLE` if set,
otherwise `AGENT_NAME` when it is a catalog role (planner, research,
database, tool, mailer), otherwise no role.
