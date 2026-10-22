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
- an agent's calls to the mock services (database, files, web, mail, admin
  handler) over plain HTTP. **OPEN (G3):** does the broker also mediate
  these outbound tool calls? A4 depends on it.

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

G1 (planner -> research action), G2 (an action served by planner), G3
(outbound tool calls), G4 (free text for justification), S8 (cc/bcc), Q2
(the malicious agent's role), Q6/Q19-Q22 (token details), Q26 (broker URL).
See `docs/open-questions.md` and `docs/scenario-coverage.md`.
