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
| Q6 | JWT details | `aud` = the receiver agent in direct mode, the broker in broker mode. `cnf` = RFC 7800 `{"jkt": ...}`. `iss` = a local issuer name. Per-message proof stays a clearly marked stub, probably an `X-Agent-Proof` header outside the envelope; its format is not defined by the testbed. Library: PyJWT with crypto. | Provisional, owner to confirm (credentials teammate) |

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
| Q11 | Tool agent calling itself | With the Q1 `served_by`, the only allowed callers of `file.delete` and `tool.send_email_external` are `tool`, which also serves them (same for `tool` calling `tool.send_email_internal`). That would be a message from `tool` to `tool`, which breaks the "sender != receiver" rule and the Q1 idea that every action goes to *another* agent. Options: (a) `planner` becomes the caller of these actions; (b) a separate executor agent serves them; (c) self-messages are allowed for `tool`. The catalog is unchanged for now; the conflict is only recorded. | Open, owner to confirm (teammates) |
| Q12 | `admin.change_policy` served_by | Prohibited, so `served_by: null` and `allowed_roles: []`. The loader enforces this for every Prohibited action. A scenario that *sends* it still needs a receiver; the scenario picks one. | Provisional, owner to confirm (teammates) |
| Q13 | Roles vs agents lists | The catalog holds `roles: [planner, research, database, tool]` and `agents: [planner, research, database, tool, malicious]`. There is no `malicious` role (Q2). | Provisional, owner to confirm (credentials teammate) |

## Raised during implementation (step 3)

| # | Topic | Current proposal | Status |
|---|---|---|---|
| Q14 | Payload fields (detail of Q5) | In `contracts/payloads.py`, all with `extra="forbid"`: `db.query_aggregate` {metric: count/sum/avg/min/max, column (needed unless count), group_by, filters}; `db.query_rows` {columns (>=1), filters, limit 1-1000, default 100}; `db.update_records` {filters (required, may be empty), updates (>=1)}; `file.read_internal` {max_bytes}; `file.delete` {reason?}; `web.fetch_page` {max_chars}; `tool.send_email_internal/external` {to (1-20 addresses), subject, body}; `admin.change_policy` {policy_id, changes}. Response: {status ok/error, result, error}. Schemas check shape, not policy (an empty update filter is schema-valid; the broker judges it). | Provisional, owner to confirm (teammates) |
| Q15 | `resource` for email | Q4 gives no example for email. Proposal: `email:internal` / `email:external`, recipients in the payload. Whether a recipient is really internal is a broker check (domain list not defined yet). | Provisional, owner to confirm (broker team) |
| Q16 | Action names in two places | `ACTION_SCHEMAS` maps action names to schemas, so names appear in both the YAML and `payloads.py`. A test fails if the two sets ever differ. Alternative: a `payload_schema` key in the YAML. | Provisional, owner to confirm (user) |
