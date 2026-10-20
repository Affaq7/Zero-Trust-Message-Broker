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
