# Open questions (provisional answers)

Everything below is PROVISIONAL. It is the current working assumption that the
code follows, but it is not final until the named owner confirms it.

| # | Topic | Current proposal | Status |
|---|---|---|---|
| Q1 | Who serves each action | Add a `served_by` column to the action catalog. `db.*` -> `database` agent; `file.*`, `web.*`, `tool.*` -> `tool` agent. Every action is a message to another agent, so the broker can see it. | Provisional, owner to confirm (teammates) |
| Q2 | Sender identity and malicious role | `sender` is the agent name (`planner`, `research`, `database`, `tool`, `malicious`). The malicious agent holds a legitimate role in its token; which role is decided with the teammate who provides credentials. | Provisional, owner to confirm (credentials teammate) |
| Q3 | delegation_chain semantics | Starts with `"user"`. Each hop appends itself; the last element must equal `sender`. A response copies the request's chain. | Provisional, owner to confirm (broker team) |
| Q4 | `resource` field | A string such as `db:sales`, `file:/internal/report.txt` or a URL. `resource` is what policy checks; `payload` holds the parameters. | Provisional, owner to confirm (broker team) |
| Q5 | Payload schemas and responses | Per-action request payload fields are drafted as a PROPOSAL. Responses use one generic payload `{status, result, error}`. Denials are expressed through the broker's own reply fields (`decision`, `reason_code`), not a separate scheme. | Provisional, owner to confirm (teammates) |
| Q6 | JWT details | `aud` = the receiver agent in direct mode, the broker in broker mode. `cnf` = `{"jkt": ...}` (the `cnf` claim comes from RFC 7800, the `jkt` member from RFC 9449; see Q20). `iss` = a local issuer name. Per-message proof stays a clearly marked stub, probably an `X-Agent-Proof` header outside the envelope; its format is not defined by the testbed. Library: PyJWT with crypto. | Provisional, owner to confirm (credentials teammate) |

## Raised during implementation (step 1)

| # | Topic | Current answer | Status |
|---|---|---|---|
| Q7 | delegation_chain on responses | Q3's two rules conflict for a response (a copied chain ends with the response's *receiver*). Accepted approach: request `chain[-1] == sender`; response copies the request's chain, so `chain[-1] == receiver`. | Accepted by user; provisional, owner to confirm (teammate) |
| Q8 | Structure vs rule checks | `Envelope` checks structure only (required fields, types, literals, no extra fields, UTC timestamp; direct mode keeps rejecting non-UTC and numeric timestamps). Cross-field rules are in `rule_violations()`, used by builders and the broker, not by direct mode. | Decided (user) |
| Q9 | ID format | `msg_id`, `trace_id`, `parent_msg_id`: non-empty strings, max 128 characters. The testbed generates UUID4 strings when it creates messages; the contract does not require UUIDs. | Decided (user); broker team to note |
| Q10 | Broker fields set by agents | Requests must not carry `decision`, `reason_code`, `redacted_fields` or `broker_signature` (a rule in `rule_violations()`). Receivers trust broker fields only with a valid `broker_signature`. The broker must strip or overwrite any broker fields that come from agents. A "forged decision" attack scenario may be added. | Decided (user); scenario pending teammates |

## Raised during implementation (step 2)

| # | Topic | Current proposal | Status |
|---|---|---|---|
| Q11 | Tool agent calling itself | Option (a) chosen: `planner` is the only caller of `file.delete`, `tool.send_email_external` and `tool.send_email_internal`; `tool` calls none of them and still serves all three. No agent may call an action it serves (a test checks this). | Decided (user); provisional, owner to confirm (teammates) |
| Q11a | Ground truth for A4 (extra outside recipient) | Scenario A4 needs a mock mail sink in the testbed that records who actually received each email, as ground truth for whether the attack succeeded. | To raise with teammates |
| Q12 | `admin.change_policy` served_by | Catalog unchanged: Prohibited, `allowed_roles: []`, `served_by: null`. Scenario A5 chooses its own receiver (the `tool` agent), which will host a mock admin handler that records the attempted change. | Decided (user); provisional, owner to confirm (teammates) |
| Q13 | Roles vs agents lists | The catalog holds `roles: [planner, research, database, tool]` and `agents: [planner, research, database, tool, malicious]`. There is no `malicious` role (Q2). | Accepted by user; provisional, owner to confirm (credentials teammate) |

## Raised during implementation (step 3)

| # | Topic | Current proposal | Status |
|---|---|---|---|
| Q14 | Payload fields (detail of Q5) | In `contracts/payloads.py`, all with `extra="forbid"`: `db.query_aggregate` {metric: count/sum/avg/min/max, column (needed unless count), group_by, filters}; `db.query_rows` {columns (>=1), filters, limit 1-1000, default 100}; `db.update_records` {filters (required, may be empty), updates (>=1)}; `file.read_internal` {max_bytes}; `file.delete` {reason?}; `web.fetch_page` {max_chars}; `tool.send_email_internal/external` {to (1-20 addresses), subject, body}; `admin.change_policy` {policy_id, changes}. Response: {status ok/error, result, error}. Schemas check shape, not policy (an empty update filter is schema-valid; the broker judges it). | Accepted by user as a proposal; owner to confirm (teammates) |
| Q15 | `resource` for email | `email:internal` / `email:external`, recipients in the payload. Whether a recipient is really internal is a broker check (domain list not defined yet). | Accepted by user; provisional, owner to confirm (broker team) |
| Q16 | Action names in two places | `ACTION_SCHEMAS` maps action names to schemas, so names appear in both the YAML and `payloads.py`. Kept: a test fails if the two sets ever differ. | Decided (user) |

## Raised during implementation (step 4)

| # | Topic | Current proposal | Status |
|---|---|---|---|
| Q17 | `action` / `resource` on a response | The contract does not say what these hold on a response. `make_response()` copies them from the request, so the broker can match a response to the action it answers. | Accepted by user; provisional, owner to confirm (broker team) |
| Q18 | Rule checks in the builders | `new_request()` refuses envelopes that break a rule (`EnvelopeRuleError`), since honest agents should never send one. `make_response()` does not check rules, so in direct mode an agent can still answer a rule-breaking request (baseline, no security); its response then copies the broken chain. The broker checks with `rule_violations()`. The malicious agent builds rule-breaking envelopes directly with `Envelope(...)`. | Decided (user) |

## Raised during implementation (step 5)

| # | Topic | Current proposal | Status |
|---|---|---|---|
| Q19 | `aud` shape | JWT allows `aud` to be a string or a list. Since aud is one party (receiver agent or broker, Q6), `TokenClaims` accepts a single string only. | Accepted by user; provisional, owner to confirm (credentials teammate) |
| Q20 | `cnf.jkt` format | The `cnf` claim comes from RFC 7800; the `jkt` member is defined by RFC 9449 (DPoP), not RFC 7800, and holds an RFC 7638 SHA-256 JWK thumbprint, base64url, 43 characters. `TokenClaims` currently enforces that format. | Owner to decide (credentials teammate) |
| Q21 | Times and lifetime | `iat`, `nbf`, `exp` are whole seconds; `iat <= exp` and `nbf < exp` are enforced. `time_problems(now, leeway)` checks validity. Proposal: 5 seconds clock leeway, maximum token lifetime 1 hour (`exp - iat <= 3600`). Not in the code yet: adding these as constants/checks to `contracts/tokens.py` needs approval. | Provisional, owner to confirm (credentials teammate / broker team) |
| Q22 | Signature verification and replay | The broker and the credentials script handle signature verification and `jti` replay tracking. The testbed does not; `contracts/tokens.py` only describes claims and checks the header algorithm (EdDSA only). Direct mode never checks tokens. | Decided (user) |

## Raised during implementation (steps 6-7)

| # | Topic | Current answer | Status |
|---|---|---|---|
| Q23 | Starlette/httpx deprecation warning | The test client warns that using `httpx` with `starlette.testclient` is deprecated and suggests `httpx2`. Ignored for now; no new dependency. Resolved as a side effect of M16: CrewAI installs `httpx2`, and Starlette's `TestClient` now uses it (it is an `httpx2.Client`, no longer an `httpx.Client`). The project's own code (`send_message()`, the LLM layer) still uses `httpx`. | Resolved (warning gone); versions pinned in constraints.txt |
| Q24 | Unparseable envelopes in the log | Envelopes that fail to parse (HTTP 422) are not logged, since there is no envelope to store. Possible later addition: a content-free "unparseable" record (time, agent, no body) so malformed-message attacks can be counted. | Later (user) |
| Q25 | Log file per agent | One `logs/<AGENT_NAME>.jsonl` per agent, written by one uvicorn worker. Several workers for the same agent could interleave lines. | Decided (user): one worker per agent |

## Raised during implementation (step 9)

| # | Topic | Current proposal | Status |
|---|---|---|---|
| Q26 | AGENT_URLS format | `AGENT_URLS="name=http://host:port,..."`, parsed at wrapper startup and again at each `send_message()` call; an invalid value fails at startup. In broker mode it will be replaced or joined by a broker URL (not defined yet). | Provisional, owner to confirm (user) |
| Q27 | What send_message() checks on the reply | Only that the reply is HTTP 200, parses as an `Envelope`, has `msg_type: "response"` and `parent_msg_id` = the request's `msg_id`. It does not judge the content (no payload schema or policy checks), so poisoned replies still reach the agent in direct mode, by design. | Decided (user) |
| Q28 | Sender-side logging | `send_message()` writes nothing; the receiving wrapper logs the request ("in") and its response ("out"). A sender-side record could be added if the runner needs to see requests that never arrived (e.g. unreachable receiver). | Later (user) |

## Milestone 2 plan decisions

| # | Topic | Answer | Status |
|---|---|---|---|
| M1 | How agents use the LLM | llama3:8b has no native tool calling (`capabilities: ["completion"]`). Agents ask the LLM for a small validated JSON decision; Python code performs the action through `send_message()` or the mock services. Model stays llama3:8b. | Decided (user) |
| M2 | Scenario definitions | Source: `scenarios/source/FYP_Scenario_List.csv` (export of the team's Google Sheet), runner-only data (it holds expected decisions). Not committed and not encoded yet. | Decided (user); file not found in the repo yet |
| M3 | Compromised-agent scenarios (e.g. A1, A7) | Remapping `AGENT_URLS` is not enough, because a wrapper rejects envelopes whose receiver is not its own `AGENT_NAME`. The runner starts the malicious-behaviour process **under the victim's AGENT_NAME** (e.g. `research`) and does not start the normal one. Design: the wrapper picks the agent function from an operator-set `AGENT_IMPL` (default = `AGENT_NAME`), so `AGENT_NAME=research AGENT_IMPL=malicious` works. The impostor sends as `research` and its log file is `logs/research.jsonl`; only the runner knows it was the impostor. **The impostor needs the victim's token** (stolen-credential case): the credentials teammate must know, so the issuing script can hand research's credentials to the impostor process in these scenarios. | Decided (user); `AGENT_IMPL` to be built in the agents steps; credentials teammate to be told |
| M4 | Mock services | Separate mock-services process; the tool agent passes A5 (`admin.change_policy`) on to the mock admin handler, which records it. | Decided (user) |
| M5 | Scenario entry and delegation actions | C1: `POST /task` on the wrapper, used only by the runner, stands in for the human user (no contract change). C2: coverage check of all 19 scenarios first (every sender -> receiver -> action path, including messages to `planner`, which serves nothing); contract changes are proposed only, for the teammates. | C1 decided (user); C2 waits for the CSV |
| M6 | Repetitions and seeds | 1, then 3, then 10 repetitions in watched blocks. Temperature 0; the Ollama `seed` is fixed per repetition (e.g. seed = repetition number), so runs vary but stay reproducible. | Decided (user) |
| M7 | What is committed from results/ | Raw output gitignored. Commit only `run_meta`, summary tables and the final baseline run. | Decided (user) |
| M8 | LLM context window | `num_ctx` = 4096 as a setting, recorded in run metadata. The LLM layer fails loudly if prompt tokens + the output cap would exceed the window (Ollama would otherwise truncate silently). | Decided (user) |
| M9 | Sensitive data and entitlement | Sensitive columns: `ssn`, `bank_account`, per-person `salary`, `home_address`. Individual-level values are entitled to nobody except through the planner's approved `db.query_rows` path; aggregates (totals, averages) are entitled to anyone. `entitled_parties` per scenario to be proposed for review. | Decided (user); per-scenario list waits for the CSV |
| M10 | Database access | Structured queries only, built from the payload schemas; the LLM never writes SQL. | Decided (user) |
| M11 | P1 performance | P1 runs on the fake LLM (message-path latency) plus a small live variant. | Decided (user) |
| M12 | Process management | The runner starts and stops all processes. A test checks that no child process or port is left after Ctrl+C or a crash; a manual way to start a single agent stays available for debugging. | Decided (user) |
| M13 | One venv or three | Before creating three venvs, a pip dry run checks whether langgraph, langchain-ollama and crewai install together. Split only on real conflicts, with evidence. | Decided (user); check in the venv step |
| M14 | Scenarios not meaningful without a broker | Mark scenarios that only make sense with the broker (probably A9-A12) "not applicable in baseline"; the runner records them as such, counted neither as attack success nor failure. | Decided (user); table waits for the CSV |
| M15 | `resource` for `admin.change_policy` | The contract defines no resource format for this action. The testbed uses `policy:<id>` (e.g. `policy:email-external`); the mock admin handler accepts any string and records it. contracts/ unchanged. | Accepted by user; owner to confirm (teammates) |
| M16 | One venv and the pydantic pin | A pip dry run showed langgraph 1.2.16, langchain-ollama 1.1.0 and crewai 1.15.28 install together (no hard conflict). The one soft conflict: **CrewAI holds pydantic at 2.12.x**, so `.venv` (and therefore `contracts/`) runs on pydantic **2.12.5** instead of 2.14.1. All 424 tests pass unchanged on 2.12.5. Exact versions are in `constraints.txt`. **The broker team must know:** if they import `contracts/` in an environment with a newer pydantic, behaviour is expected to match, but the testbed is only tested on 2.12.5. | Decided (user); teammates to be told |
| G3 | Outbound tool calls and A4 | Agents reach the mock services (mail, files, web, admin, database) over plain HTTP, not as envelopes, so a broker that sees only agent-to-agent messages never sees the real effect. For A4 it sees planner -> tool with the correct `to` list, but not the tool's actual send with an extra recipient. **Question for the teammates:** does the broker mediate outbound tool calls (e.g. the services become broker-visible principals such as a `mailer` serving `mail.deliver`, or the broker is the egress proxy), or only agent-to-agent messages? If only messages, how should A4 be detected? The baseline is not affected; the mail sink records the real recipients either way. | Open, owner to confirm (teammates) |
