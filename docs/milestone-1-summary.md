# Milestone 1 summary

Milestone 1 builds the plumbing of the testbed: shared contracts, one HTTP
wrapper for every agent, a dummy agent, and a helper for agent-to-agent
messages. There are no LLM agents and no broker yet. Many contract details
are provisional; see [open-questions.md](open-questions.md).

## What exists

| Part | Files | What it does |
|---|---|---|
| Contracts v0.2 | `contracts/` | `Envelope` (structure checks) and `rule_violations()` (cross-field rules); `new_request()` / `make_response()`; action catalog as data (`action_catalog.yaml`, with `served_by`) and its loader (`catalog.py`); per-action payload schemas and the generic `{status, result, error}` response payload (`payloads.py`, proposal); JWT claim model, EdDSA-only header check and the per-message PROOF STUB (`tokens.py`). |
| Wrapper | `wrapper/` | FastAPI app per agent: `POST /message`, `GET /health`. Settings (`MODE`, `AGENT_NAME`, `AGENT_URLS`, `LOG_DIR`) come only from the environment; invalid values stop it at startup. JSONL log of every envelope in and out (`logs/<agent>.jsonl`). |
| send_message() | `wrapper/send.py` | Builds a request and posts it to the receiver's wrapper (direct mode). Attaches the caller's token and the proof stub. Broker mode raises "not implemented". |
| Dummy agent | `agents/dummy.py` | Returns a fixed text. |
| Manual test | `examples/dummy_request.json`, `scripts/print_stub_token.py`, README | Two-terminal curl.exe test on Windows PowerShell (verified). The token script signs with a throwaway in-memory key. |

## How a message flows (MODE=direct)

```
agent code (planner)
  └─ send_message(receiver="dummy", action, resource, payload, chain_so_far, token)
       ├─ reads MODE, AGENT_NAME, AGENT_URLS from the environment
       ├─ new_request(): UUID msg_id/trace_id, UTC timestamp, chain + sender
       └─ HTTP POST {AGENT_URLS[dummy]}/message
            headers: Authorization: Bearer <token>, X-Agent-Proof: <stub>
                         │
dummy wrapper            ▼
  ├─ MODE=broker? -> 501
  ├─ parse Envelope (structure only) ── fails -> 422, not logged
  ├─ log "in" (full envelope, no headers)
  ├─ receiver != AGENT_NAME or not a request -> 400
  ├─ call agent function -> ResponsePayload (crash -> status "error")
  ├─ make_response(): same trace_id, parent_msg_id = request msg_id, swapped
  └─ log "out", return response envelope
                         │
send_message()           ▼
  └─ checks HTTP 200, valid Envelope, msg_type response, parent_msg_id match
     -> returns the response envelope to the agent code
```

Direct mode is the **no-security baseline**: the wrapper does not validate
payloads, does not look at the token, and does not apply the catalog, RBAC,
default-deny or the envelope rules. Those are the broker's job.

## What the tests cover (317 tests, all passing)

| Area | Tests | Main points |
|---|---|---|
| Envelope | 51 | required fields, types, no extra fields (trust scores, labels, token), UTC-only timestamps, 128-char IDs; chain, parent and broker-field rules |
| Builders | 11 | UUIDs, chain appending, trace continuation, response rules, answering a rule-breaking request |
| Catalog | 70 | matches the agreed table, every role x action, default-deny, no agent serves an action it may call, malformed catalogs rejected |
| Payloads | 66 | valid/invalid payload per action, extra fields rejected, schemas and catalog stay in sync, response payload |
| Tokens | 38 | claims, roles, times, `cnf.jkt`, sub = sender, EdDSA-only, proof stub; keys only in memory |
| Wrapper | 35 | happy path; direct mode accepts schema-invalid, unknown, Prohibited, forged and token-less messages; parse errors; wrong receiver; broker 501; startup failures |
| Message log | 10 | full envelopes in/out, token and proof never logged, labels cannot reach it, broker mode writes nothing |
| send_message | 26 | planner-to-dummy and user -> planner -> dummy over in-process transports (one trace end to end); unknown receiver, unreachable, bad replies, broker mode, bad environment, AGENT_URLS parsing |
| Manual-test files and smoke | 10 | example request valid; token script output; nothing written to disk; venv and path with a space |

## Open questions still unresolved

Full details in [open-questions.md](open-questions.md).

- **Teammates / broker team:** served_by (Q1); delegation-chain rules (Q3, Q7);
  `resource` format (Q4, Q15); payload fields (Q5, Q14); ID format note (Q9);
  "forged decision" scenario (Q10); planner as caller of tool actions (Q11);
  A4 mail sink (Q11a); A5 receiver and mock admin handler (Q12); response
  action/resource (Q17).
- **Credentials teammate:** malicious agent's role (Q2, Q13); `aud`, `iss`,
  `cnf` (Q6, Q19); `jkt` format (Q20); 5 s leeway and 1 h lifetime (Q21);
  proof format (Q6).
- **Later (ours):** httpx2 warning (Q23); "unparseable" log record (Q24);
  AGENT_URLS and the broker URL (Q26); what send_message() checks (Q27);
  sender-side logging (Q28).

## What Milestone 2 should contain

1. **Real agents** behind the same wrapper: planner, research, database,
   tool and malicious, on Ollama llama3:8b at temperature 0, split between
   LangGraph and CrewAI (which agent uses which is still to decide). Each uses
   `send_message()` and the catalog's `served_by` to pick receivers.
2. **Mock services** so runs are repeatable and give ground truth:
   a seeded database for the database agent; an internal file store; fixture
   web pages (including prompt-injection pages) instead of the real web; a
   mail sink recording real recipients (A4); a mock admin handler on the tool
   agent recording attempted policy changes (A5).
3. **Credentials:** plug in the teammate's issuing script (tokens per agent,
   keys in gitignored `keys/`).
4. **Scenarios:** N1-N4, A1-A14 and P1 as JSON/CSV in `scenarios/`, with
   labels and expected outcomes kept there, never in envelopes or tokens.
5. **Scenario runner:** starts or targets the wrappers, sends each scenario's
   first request, collects logs by `trace_id`, reads the mock services' ground
   truth, and writes a results file (labels joined in by the runner).
6. **Baseline runs** of all scenarios in `MODE=direct`, ready to compare with
   broker runs later.

Docker Compose, the broker integration, the dashboard and the Xu et al.
scenarios stay out of scope unless agreed otherwise.
