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
