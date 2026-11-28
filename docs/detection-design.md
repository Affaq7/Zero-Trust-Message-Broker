# Violation detection design (A-R2)

Owner: Amna. Status: FINAL for FYP-I, 25 Nov 2026. Reviewed by Kissa and Afaq,
who agree with V1 to V5 and the numbers. One item pending agreement: the
`sanitize_reply` signature change (section 3, point 2). PROVISIONAL: every
number is a starting value, tuned in A-R1. Feeds A2 (trust engine) and K-R2.

Sources: Amna's Research and Design Plan (the "plan"), the action catalog,
`contracts/payloads.py`, `docs/scenario-coverage.md`, the A1 risk ratings
(`broker/trust/risk_ratings.yaml`).

## 1. Rules in the FYP-I demo (rule-based, no learning)

All rules run in the broker after the hard gates (steps 1 to 4). They use only
broker-side data: the verified identity, the envelope, the policy result and
the broker's own clock. A rule never trusts a value an agent wrote about itself
(for example the envelope `timestamp`). Hits go to the trust engine (A2) and the
audit log, never into an envelope, a token or the message log.

| # | Rule | Fires when | Input | Plan |
|---|---|---|---|---|
| V1 | Denial rate | 5 DENY decisions for one agent within 60 s (both configurable) puts it in Quarantined. Only denials where identity was verified count (`IdentityResult.ok` and `agent` set); an identity failure has `agent=None` and is never counted against the claimed sender, so forged messages "from research" cannot quarantine the real research agent (Kissa, 25 Nov) | decisions the broker made, IdentityResult, broker clock | 5.3; scenario A9 |
| V2 | Action unusual for the role | the policy step denies an action the agent's role may not call (catalog `allowed_roles`), or any agent in the delegation chain (`delegation_chain`) may not call the action (A7; Kissa's `DELEGATION_EXCEEDS_DELEGATOR`) | PolicyResult, `delegation_chain` | 4.2, 5 (Suspicious: "meaningful anomaly") |
| V3 | Injection cue | K4's `injection_cue` is true for a request; free-text fields are `justification`, `query`, `request`, `suggested_action`, email `subject` and `body` | ValidationResult | 2.5 (AgentDojo, AgentArmor) |
| V4 | Message burst | one agent sends more than 10 requests within one task (same `trace_id`); configurable | envelope `sender`, `trace_id` | not a rule in the plan; rate limiting is in TrustGate (3.2) |
| V5 | Individual-level data request | a request asks for individual-level personal data (M9): `db.query_rows` (A1 `individual_data: true`), or a request naming a sensitive column (ssn, bank_account, salary, home_address) | envelope, A1 ratings | 4.2, 5 (Quarantine: "critical violation") |

**What each rule does (Amna, 25 Nov; plan section 8, item 3):**
- V1 is the only rule that quarantines straight away.
- An agent is also quarantined when its trust score falls below the Restricted
  band (T < 0.40, A2). The defence manager logs that once, with reason
  `TRUST_QUARANTINED`, like a V1 quarantine. It mostly covers a responder whose
  replies keep being cut (about 13 cut replies in a row with the current settings).
- V2, V3 and V5 lower T through the decay rule (plan 4.4). Their severities are set in A2.
- V4 moves the agent to Suspicious.
- **Count once (plan 4.4):** a DENY counts once towards V1 and once as a T drop.
  V2 adds nothing more for the same message.

**Why V4 is per task, with 10 as the limit.** One P1 run in direct mode with the
fake model (run 20261125T171301Z, 61 of 61 tasks completed) gave these peaks for
one agent: planner 41 requests in 1 s and 150 in 10 s at 50 tasks at once, but
never more than 3 requests from one agent in one task. A per-agent rate limit
would have to sit above P1's rate. Per task, the code caps the planner at 5
actions (planner prompt v2) and research at 4 steps; one `planner.request` relay
can add another 5 planner actions to the same task. So 10 is the most a normal
agent can send in one task, and V4 fires above that. Limit: `trace_id` is set by
the sender, so an attacker (or a hijacked agent) can start a new trace for every
message and V4 will not see it. V1, the policy step and the trust score still
apply to every message, whatever its `trace_id`. Possible fixes, for FYP-II: count
how many new traces one agent starts per minute (a normal agent only starts one
when it is given a task), or let the broker hand out trace ids so that an agent
cannot pick its own.

## 2. Moved to FYP-II

| Method | What it would detect | Data it needs |
|---|---|---|
| Isolation Forest | unusual single messages (sender, receiver, action, resource, time, size) | 500 to 1,000 normal events from complete runs |
| Autoencoder | unusual messages, learned from the same features | the same normal events, more if possible |
| Sequence analysis | unusual orders of actions within one trace | complete traces, grouped by `trace_id` |

Who produces the data: Amna, from N1 to N4 runs in direct mode (`python -m runner
--mode direct --scenario N1 --llm fake --reps 3`, also used for A-R1), then Afaq's
evaluation runs in broker mode (F5). Two limits: `events.jsonl` keeps no payloads,
so models get metadata only; and fake-LLM runs repeat almost the same messages, so
live-model runs or more varied tasks are needed for realistic variety.

## 3. Conflicts found in `contracts/payloads.py` and `docs/scenario-coverage.md`

1. **V5 and aggregates.** `db.query_aggregate` is rated `individual_data: false`,
   but its schema allows `group_by` on any column and any `filters`. A sum of
   salary grouped by name, or filtered to one id, returns a per-person value.
   V5 must also check `group_by` and `filters` on aggregates, not only the action.
   **Resolved (Afaq):** F3's `minimum_necessary(action, payload)` flags `group_by`
   or `filters` on aggregates that touch ssn, bank_account, salary, home_address
   or one person's id, and returns a V5 flag. A2 only consumes the flag.
2. **V3 sees requests only.** In A3 the injection is in a reply (the content of
   `file.read_internal`), and `web.fetch_page` returns raw HTML. A request-side
   cue misses both. Reply content is Afaq's F3, so the reply scan must report
   its cue to A2 as well.
   **Resolved (Afaq):** the reply check returns a cue flag with the sanitized
   reply, and the pipeline calls `TrustEngine.update` with it after step 9. It
   affects the agent's next message, not the one already forwarded. **Pending:**
   this changes the frozen `sanitize_reply` signature to
   `(Envelope, list[str], bool)`; needs Kissa's and Amna's agreement.
3. **V3 false positives.** Email `body` and `justification` are free text by
   design (N3 summaries, A8's "emergency" text that the HITL approver is meant to
   read). A cue there should lower T, not deny on its own.
4. **V2 counts twice.** A role violation is already a hard DENY at step 4, and
   that DENY also counts towards V1. The plan (4.4) says not to count one event
   twice. Decided: the DENY counts once in V1 and once as a T decrease, and V2
   adds nothing more for the same message.
5. **V4 and P1.** P1 sends up to 50 tasks at once on purpose, so V4 counts per
   task (`trace_id`), not per second. Resolved, see section 1.
6. **A2 and A4 are reply-side.** The leak in A2 is in the database's reply and
   the extra recipient in A4 is added on the tool to mailer hop. None of V1 to V5
   catches them on the first request; they depend on F3 and on `mail.deliver`
   being checked like any other request.
   **Resolved (Afaq):** F3's request check runs on every hop, including tool to
   mailer. A2 is handled by the reply sanitiser (SANITIZE) and A4 by the recipient
   check (DENY, `RECIPIENT_NOT_APPROVED`, Afaq's code). Both hits are sent to A2.
7. **V4's figures.** The limit of 10 rests on the planner cap (5 actions), the
   research cap (4 steps) and `events.jsonl` keeping no payloads.
   **Resolved (Afaq, cross-check in the code):** the planner allows 5 actions
   with the default prompt v2 (`V2_MAX_STEPS`) and 4 with prompt v1; research
   allows 4 actions in total (`DEFAULT_MAX_STEPS`), with at most 1 extra action.
   The operator can change both with `PLANNER_MAX_STEPS` and `RESEARCH_MAX_STEPS`.
   `events.jsonl` holds only ids, time, direction, message type, sender,
   receiver, action, resource and decision, never a payload. In his P1 run
   20261108T194721Z (3 repetitions) no agent sent more than 3 requests in one
   trace (the planner in N4 and P1), so "more than 10" leaves a clear margin over
   normal traffic and over both caps. That run used the fake model; a live-model
   run should be checked the same way before the numbers are final. The
   `trace_id` caveat is in section 1.

No conflict found with: the A9 numbers (5 in 60 s), labels and trust scores
staying broker-side, or the catalog roles.

## 4. Reason codes (in `docs/identity-spec.md` section 8)

Kissa added these to section 8 (her PR #6, 25 Nov). None of them clash with an
existing code. If the two lists ever differ, section 8 is the reference.

| Code | Rule | Decision | Module |
|---|---|---|---|
| `AGENT_QUARANTINED` | step 3, already listed | QUARANTINE | `broker/defence/quarantine.py` (A3) |
| `DENIAL_RATE_EXCEEDED` | V1 | QUARANTINE (the denial that crosses 5 in 60 s) | `broker/defence/quarantine.py` (A3) |
| `TRUST_QUARANTINED` | trust score below 0.40 (A2) | none on its own; the quarantine event in the audit log, then QUARANTINE / `AGENT_QUARANTINED` at step 3 (to be added to section 8 by Kissa) | `broker/defence/quarantine.py` (A3) |
| (none new) | V2 | DENY with Kissa's `ROLE_NOT_ALLOWED` or `DELEGATION_EXCEEDS_DELEGATOR` (count once) | `broker/policy/engine.py` (K3) |
| `INJECTION_CUE` | V3 | none on its own; lowers T, audit log | `broker/trust/trust.py` (A2) |
| `BURST_DETECTED` | V4 | none on its own; state Suspicious, audit log | `broker/trust/rules.py` (A2) |
| `INDIVIDUAL_DATA_REQUEST` | V5 | none on its own; lowers T, audit log | `broker/trust/trust.py` (A2) |
| `REPLY_SANITIZED` | A2 scenario (F3 reply check) | none on its own; lowers the responder's T, audit log | `broker/trust/trust.py` (A2) |
| `TRUST_TOO_LOW` | step 6 | DENY when T is below `required_trust` (A1) | `broker/trust/trust.py` (A2) |

## 5. Still to decide

- The severity of V2, V3 and V5 for the decay formula (in A2, then A-R1).
- Team: confirm these rules with Kissa (K-R2) and Afaq (F3 reply checks, section 3).
