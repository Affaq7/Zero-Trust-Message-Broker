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

| # | Topic | Current proposal | Status |
|---|---|---|---|
| Q7 | delegation_chain on responses | Q3 says the last element must equal `sender` AND a response copies the request's chain. Both cannot hold for a response: the copied chain ends with the request's sender, which is the response's *receiver*. Current code: request `chain[-1] == sender`, response `chain[-1] == receiver`. | Provisional, owner to confirm (broker team) |
| Q8 | Structure vs rule checks | `Envelope` checks structure only (required fields, types, literals, no extra fields, UTC timestamp). Cross-field rules (chain start/end, `parent_msg_id` vs `msg_type`, sender != receiver) are in a separate `rule_violations()`, so direct mode can accept rule-breaking envelopes while builders and the broker still check them. | Provisional, owner to confirm (user) |
| Q9 | ID format | `msg_id` and `trace_id` are non-empty strings. The testbed will generate UUID4 strings, but the contract does not require UUIDs. | Provisional, owner to confirm (broker team) |
| Q10 | Broker fields set by agents | `decision`, `reason_code`, `redacted_fields`, `broker_signature` are optional on any envelope, so an agent (e.g. malicious) can put `decision: "ALLOW"` in its own message. Proposal: the broker always overwrites/strips them, and receivers trust them only with a valid `broker_signature`. Also open: are they allowed on requests (e.g. a SANITIZEd forwarded request) or only on responses? Current code allows both. | Provisional, owner to confirm (broker team) |
