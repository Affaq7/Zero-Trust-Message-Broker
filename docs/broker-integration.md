# Broker integration: what the testbed does today

For Kissa. This describes only what exists in the testbed now (contracts
v0.2, Milestone 2). Everything marked **OPEN** is the broker's decision; the
testbed will follow it. Contract details are in `contracts/`; provisional
items and their numbers are in `docs/open-questions.md`.

## 1. Where the broker sits

Every agent (planner, database, tool, ...) runs behind the same HTTP wrapper
(`wrapper/`). Agents talk to each other only by sending an **envelope** with
`wrapper.send.send_message()` to another agent's `POST /message`.

```
MODE=direct (today):   planner --POST /message--> database
MODE=broker (planned): planner --> BROKER --> database      (decision on every message)
```

Not envelopes, so not seen by a broker today:

- the runner's `POST /task` to the entry agent (the stand-in for the human
  user; decision C1);
- an agent's calls to the mock services (database, files, web, admin
  handler) over plain HTTP. **Mail is different**: since the mailer agent
  exists, the tool agent sends a `mail.deliver` message to the mailer
  (caller `tool`, served by `mailer`, section 8), and only the mailer talks to
  the mock mail sink. So the final recipient lists (`to`, `cc`, `bcc`) are in
  an envelope a broker can see. **OPEN (G3):** do the other outbound calls
  (files, web, admin, database) also become broker-visible messages, or does
  the broker see only agent-to-agent messages?

## 2. What MODE=broker does in the testbed now

`MODE` is set only by the operator (environment / Docker Compose); no message
can change it.

| Piece | MODE=direct | MODE=broker (today) |
|---|---|---|
| Wrapper `POST /message` | parses the envelope, checks `receiver == AGENT_NAME`, runs the agent, returns the response envelope; no other checks | returns **HTTP 501** `{"error": "MODE=broker is not implemented yet"}` before reading the body |
| `send_message()` | posts to the receiver's URL from `AGENT_URLS` | raises `BrokerModeNotImplementedError` before building the envelope; nothing is sent |
| Wrapper `POST /task` | runs the agent's task | still runs; any agent-to-agent send fails as above |
| `GET /health` | `{"status": "ok", "agent": ..., "mode": "direct"}` | same, with `"mode": "broker"` |

Direct mode deliberately provides **no security**: no payload schema check,
no token check, no catalog/RBAC, no default-deny, no envelope rule checks.
All of that is the broker's job (`contracts/catalog.py`,
`contracts/payloads.py`, `contracts/envelope.py: rule_violations()`,
`contracts/tokens.py` are ready to use).

## 3. Environment variables, ports, headers

Environment of each agent wrapper (set by the operator or the runner):

| Variable | Meaning |
|---|---|
| `MODE` | `direct` or `broker` |
| `AGENT_NAME` | this agent's name; the envelope `sender` and token `sub` |
| `AGENT_IMPL` | which agent code runs under `AGENT_NAME` (default: same) |
| `AGENT_ROLE` | role in this process's tokens (default: `AGENT_NAME` when it is a catalog role) |
| `AGENT_URLS` | `name=http://host:port,...`: where each agent's wrapper listens (direct mode) |
| `MOCKS_URL` | the mock services (default `http://127.0.0.1:8090`) |
| `LOG_DIR` | message log folder (`<LOG_DIR>/<AGENT_NAME>.jsonl`) |

**OPEN (Q26):** how an agent finds the broker in broker mode (a
`BROKER_URL` variable, or `AGENT_URLS` pointing every name at the broker).

Ports: none are fixed. The runner gives each process a free local port and
builds `AGENT_URLS` from them; manual examples use 8001 for an agent and
8090 for the mock services. **OPEN:** the broker's port.

Headers on every agent-to-agent request:

| Header | Value today |
|---|---|
| `Content-Type` | `application/json` |
| `Authorization` | `Bearer <JWT>`, minted by the sender (see section 5) |
| `X-Agent-Proof` | `PROOF-STUB-NOT-IMPLEMENTED`, a placeholder. **OPEN:** proof format. |

The wrapper never logs headers, tokens or the proof.

## 4. Envelopes in and out

A request as `send_message()` builds it (`contracts.new_request()`):

```json
{
  "schema_version": "0.2",
  "msg_id": "e1dd1217-c16f-408d-8916-74f3ec775458",
  "trace_id": "9068ff64-1e23-4b27-8038-d82c952aeda1",
  "parent_msg_id": null,
  "msg_type": "request",
  "sender": "planner",
  "receiver": "database",
  "action": "db.query_aggregate",
  "resource": "db:project_costs",
  "payload": {"metric": "sum", "column": "amount", "filters": {"project": "Project X"}},
  "delegation_chain": ["user", "planner"],
  "timestamp": "2026-10-22T11:39:56.501326Z",
  "decision": null,
  "reason_code": null,
  "redacted_fields": null,
  "broker_signature": null
}
```

The response the receiving wrapper returns (`contracts.make_response()`):
new `msg_id`, same `trace_id`, `parent_msg_id` = the request's `msg_id`,
sender and receiver swapped, `action`, `resource` and `delegation_chain`
copied, payload `{status, result, error}`:

```json
{
  "schema_version": "0.2",
  "msg_id": "c94e4d03-65cb-4601-93b6-de30568bc1c2",
  "trace_id": "9068ff64-1e23-4b27-8038-d82c952aeda1",
  "parent_msg_id": "e1dd1217-c16f-408d-8916-74f3ec775458",
  "msg_type": "response",
  "sender": "database",
  "receiver": "planner",
  "action": "db.query_aggregate",
  "resource": "db:project_costs",
  "payload": {"status": "ok",
              "result": {"rows": [{"value": 184250}], "summary": "Project X cost items add up to 184,250."},
              "error": null},
  "delegation_chain": ["user", "planner"],
  "timestamp": "2026-10-22T11:39:56.501326Z",
  "decision": null,
  "reason_code": null,
  "redacted_fields": null,
  "broker_signature": null
}
```

Rules already in `contracts/envelope.py`:

- Unknown fields are rejected (`extra="forbid"`); trust scores and test
  labels can therefore never travel in an envelope.
- `timestamp` must be UTC; ids are non-empty strings of at most 128 chars.
- `rule_violations()` checks the cross-field rules: the chain starts with
  `"user"`; a request's chain ends with its sender, a response's with its
  receiver (Q7); requests have `parent_msg_id = null`; sender != receiver;
  **a request must not carry broker fields** (Q10).

## 5. Tokens

EdDSA JWT in `Authorization: Bearer`, claims checked by
`contracts.tokens.TokenClaims` (no extra claims allowed). A stub token minted
today by the planner for the database agent:

```json
header: {"alg": "EdDSA", "typ": "JWT"}
claims: {"sub": "planner", "role": "planner", "iss": "https://broker.ztbroker.local",
         "aud": "database", "iat": 1792669196, "nbf": 1792669196, "exp": 1792669496,
         "jti": "db915a0b-87f8-4e09-b413-fdb9581a354f",
         "cnf": {"jkt": "3kfH3YF27CcCIs56Y1_8eSfGPlcTWok9EfNCBIDb-z8"}}
```

- `iss` = `BROKER_ISSUER` and, in broker mode, `aud` = `BROKER_AUDIENCE`
  (`"ztbroker"`), both constants in `contracts/tokens.py` (S9). In direct
  mode `aud` is the receiver's name. The contract does not check `iss` or
  `aud` values; the broker does.
- `cnf.jkt` is an RFC 7638 SHA-256 thumbprint (43 base64url chars).
- Today every wrapper signs with a throwaway in-memory key (5-minute tokens,
  one per receiver); nothing verifies them. Real credentials come from the
  credentials script. **OPEN (Q21, Q22):** lifetime, clock leeway, signature
  verification and `jti` replay tracking are the broker's.

## 6. What the testbed expects back

`send_message()` accepts a reply only if it is **HTTP 200**, parses as an
`Envelope`, has `msg_type: "response"` and `parent_msg_id` equal to the
request's `msg_id`. Anything else becomes an error for the calling agent
(`BadResponseError` with the HTTP status). It does not judge the content
(Q27).

The envelope already has room for the broker's reply fields, all `null`
today:

| Field | Type in the contract |
|---|---|
| `decision` | one of `ALLOW`, `SANITIZE`, `HITL`, `DENY`, `QUARANTINE` |
| `reason_code` | string |
| `redacted_fields` | list of strings |
| `broker_signature` | string |

Agreed so far (Q10): requests must not carry these fields; the broker strips
or overwrites any that agents set; receivers trust them only with a valid
`broker_signature`.

**OPEN, for the broker to decide:**

- How a denial reaches the sender: a response envelope with
  `decision: "DENY"` and `reason_code` (HTTP 200), or an HTTP error status.
  Today a non-200 reply is an error for the agent; a 200 envelope is
  accepted whatever its decision.
- How SANITIZE is shown (`redacted_fields` on the forwarded request, the
  response, or both), and what HITL looks like while waiting for approval
  (timeouts today: `send_message()` waits 60 s per hop by default, the runner
  900 s per scenario task; a HITL wait longer than 60 s would need a change).
- QUARANTINE semantics (A9) and how later messages are rejected.
- `broker_signature` format and key.
- Whether the broker forwards the original envelope unchanged to the
  receiver's `/message` or re-issues it; and whether receivers accept
  messages only from the broker (A12 network isolation).
- Transport protection between agents and broker (A11).
- How the runner learns each decision for its results (`broker_decision` and
  `detected` columns exist in `results.csv`, empty in direct mode): from the
  decision fields in the logged envelopes, or a broker decision log.

## 7. Related open items

G3 for the outbound calls other than mail, A8's target (Q-S2: the database
agent with `justification`, or the planner via `planner.request`), Q2 (the
malicious agent's role), Q6/Q19-Q22 (token details), Q26 (broker URL), S16
(whether the catalog should carry risk ratings). Answered since the first
version of this document: G1, G2, G4 and S8 (S10-S14, section 8).
See `docs/open-questions.md` and `docs/scenario-coverage.md`.

## 8. Contract additions of 2026-10-24 (agreed by Kissa and Amna)

Additive, same `schema_version` "0.2". Nothing existing changed; all of it
is in `contracts/` and covered by tests. Details and open points are S10-S17
in `docs/open-questions.md`.

**New actions** (all Permitted; the catalog has no field for resources or
risk ratings, so those are documented, not enforced):

| Action | Caller | Served by | Resource | Payload |
|---|---|---|---|---|
| `research.lookup` | planner | research | `research:query` | `query` (1-500 chars), `sources` (optional, max 5), `max_sources` (1-3, required) |
| `planner.request` | research | planner | `planner:request` | `request` (1-500), `suggested_action` (optional, 1-100) |
| `mail.deliver` | tool only | mailer | `mail:outbound` | `to` (1-20), `cc`, `bcc` (0-20 each), `subject`, `body` |

`planner:request` and `mail:outbound` were chosen by the testbed side; please
confirm them. Risk ratings (the catalog has no field for them, so they are in
S16): `research.lookup` and `planner.request`, both Reversibility L, Real-time
Impact L, Data Sensitivity M, External Communication L, Privilege L, Autonomy
M, Impact Scope M. `mail.deliver` has no ratings yet (waiting for Amna).

**New roles/agents:** `mailer` (role and agent). `research` was already a role.

**Optional `justification`** (max 500 characters) on `db.query_rows`,
`db.update_records`, `file.delete` and `tool.send_email_external` only. It is
free text written by the requesting agent; it never changes who may call an
action, and anything it says is for the broker or an approver to judge, not
to trust. **OPEN (Kissa):** whether and how a decision uses it (for example
shown to the HITL approver).

**`cc` / `bcc`** are optional lists on both email actions and on
`mail.deliver`, with the same limits as `to` (up to 20 each, so up to 60
recipients in one message). Every recipient list is normalised by
`contracts.payloads.normalize_address` (strip, then lowercase) before the
shape is checked, so validating a payload yields exactly the addresses a
mailer would use. Use the validated model, not the raw dictionary, when
comparing recipients. **Aliases and groups are unsupported**: an address is
taken literally and never expanded. Plus-tags are kept and duplicates are not
removed (not discussed).

An example `mail.deliver` request, in the form the tool agent now sends it to
the mailer (it normalises the recipient lists and always states `cc` and
`bcc`; here `cc` is filled in to show the shape):

```json
{
  "schema_version": "0.2", "msg_id": "<uuid>", "trace_id": "<uuid>", "parent_msg_id": null,
  "msg_type": "request", "sender": "tool", "receiver": "mailer",
  "action": "mail.deliver", "resource": "mail:outbound",
  "payload": {"to": ["alice.morgan@corp.local"], "cc": ["boss@corp.local"], "bcc": [],
              "subject": "Project X cost", "body": "The total is 184,250."},
  "delegation_chain": ["user", "planner", "tool"], "timestamp": "<utc>",
  "decision": null, "reason_code": null, "redacted_fields": null, "broker_signature": null
}
```

**What the testbed does with this today:**

- **The mail path (S12, S18).** planner -> tool (`tool.send_email_internal` or
  `tool.send_email_external`) -> mailer (`mail.deliver`, resource
  `mail:outbound`, sender `tool`, delegation chain `user, planner, tool`, same
  `trace_id`) -> mock mail sink. The tool drafts subject and body with the
  LLM, normalises the recipients, and sends only `to`, `cc`, `bcc`, `subject`
  and `body`; request-only fields such as `justification` are not forwarded.
  N3 runs this way: 3 messages instead of 2.
- **The mailer** is deterministic (no LLM) and the only caller of the sink. It
  applies **no access rule** in direct mode: it accepts `mail.deliver` from
  any sender, passes it to the sink and returns the answer, exactly as the
  wrapper does for every other agent. "Only the tool agent may call
  `mail.deliver`" is in the catalog and is **for the broker to enforce**
  (a message from any other sender reaches the sink in the baseline). The
  mailer refuses only an action it cannot perform (anything but
  `mail.deliver`). **OPEN (Kissa):** the broker's identity and delegation
  checks on this hop (is `tool` really the sender, does the chain end with it).
- **The sink** records every attempt (`delivered` or `failed`) with the
  normalised `to`, `cc` and `bcc`, and counts an outside address in any of the
  three as an external recipient (ground truth for A4-style scenarios). It
  never knows the intended recipients; the scenario file lists them. It
  accepts `mail:outbound` (the `mail.deliver` schema) and, for manual checks,
  `email:internal` / `email:external`.
- The planner prompt is frozen for the baseline. The planner does not offer
  or send `research.lookup`, and `justification`, `cc` and `bcc` are not shown
  to the model (S17). There is no research agent and no planner handler for
  `planner.request` yet, so no scenario uses those two actions so far.
- Direct mode still checks none of it; payload validation against these
  schemas is the broker's job.

## 9. Plug-in checklist and where the baseline is (2026-11-03)

How to switch `MODE`, what to run to reproduce the baseline and where the results go are in
`docs/README.md`; the baseline itself (all 19 scenarios, with the expected decision of each) is in
`docs/baseline-report.md`. In short:

1. `MODE=broker` is one environment variable per agent process, read once at start. Today the wrapper
   answers HTTP 501 (`wrapper/app.py`) and `send_message()` raises `BrokerModeNotImplementedError`
   (`wrapper/send.py`); those two branches are where the broker goes.
2. The scenario runner sets `MODE` for every process with `--mode direct|broker` (default `direct`)
   and records it in `run_meta.json`. `--mode broker` works as a switch today (tasks fail with the 501 /
   `BrokerModeNotImplementedError` above); the broker address still has to be passed through once Q26
   (how an agent reaches the broker) is decided.
3. Compare against `results\<run_id>\` of the baseline runs: N1-N4 live (run `20261103T164223Z`, 12/12
   passed) and P1 (run `20261103T175957Z`, fake LLM). The planner prompt (v2) and the research prompt
   are frozen, so the same scenarios give comparable runs; a broker run should use the same planner
   prompt version.
4. Direct mode has no attack results to compare with: A9, A10, A11, A12 and A14 are not applicable
   there, and A1-A8 and A13 are defined but not executed (a scripted attacker sender is not built).
