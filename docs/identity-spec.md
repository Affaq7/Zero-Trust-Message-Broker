# Identity and authorisation specification (K-R1)

Owner: Kissa. Version 1, 2026-11-25. Status: **proposal for team review**.
Afaq confirms the sender side (credentials, proof, `wrapper/`), Amna confirms
the registry calls and the reason codes she returns.

This document fixes, for the broker pipeline steps 1, 2 and 4:

- what a token contains and who signs it (section 2);
- the per-message proof that replaces the `# PROOF STUB` (section 3);
- lifetimes and clock rules (section 4);
- the registry, the epoch rule and revocation (section 5);
- the delegation rule (section 6);
- the order of checks and every reason code with the module that returns it
  (sections 7 and 8).

Nothing here changes `contracts/` by itself. The one contract change it needs
(an `epoch` claim) is proposed in section 9 and logged in
`docs/open-questions.md` until all three of us agree.

## 1. Principals and names

| Term | Value | Example |
|---|---|---|
| agent name | catalog agent, equal to envelope `sender` and token `sub` | `research` |
| `agent_uri` | registry key; in FYP-I it is the agent name itself | `research` |
| `instance_id` | one running copy of an agent with its own key | `research-1`, `research-2` |
| role | catalog role, taken from the **registry**, never trusted from a message | `research` |
| `user` | the human principal at the start of every delegation chain; not an agent, has no token | `user` |

Five agents are registered: planner, research, database, tool, mailer. Research
has two instances (`research-1`, `research-2`); every other agent has one
(`<agent>-1`). The `malicious` agent has **no identity of its own** (answers Q2):
an attacker process either holds a copied credential file (stolen-credential
cases) or has no valid credential at all. A token whose `sub` is not registered
is refused with `UNKNOWN_AGENT`.

## 2. Token

An EdDSA JWT in `Authorization: Bearer <token>`. It is **signed by the agent
instance's own Ed25519 key**. The broker's registry holds each instance's
public key and is the trust anchor; there is no separate issuer key.

Header:

```json
{"alg": "EdDSA", "typ": "JWT", "kid": "<cnf.jkt of this instance>"}
```

Claims:

| Claim | Type | Value | Checked by the broker |
|---|---|---|---|
| `iss` | string | `https://broker.ztbroker.local` (`contracts.tokens.BROKER_ISSUER`) | equal, else `WRONG_ISSUER` |
| `aud` | string, never a list (Q19) | `ztbroker` (`contracts.tokens.BROKER_AUDIENCE`) | equal, else `WRONG_AUDIENCE` |
| `sub` | string | agent name | equals envelope `sender`, else `SUB_MISMATCH` |
| `role` | string | catalog role of the agent | equals registry role, else `ROLE_MISMATCH` |
| `iat` | int seconds | issue time | not in the future beyond leeway |
| `nbf` | int seconds | equal to `iat` | `now + 5 >= nbf` |
| `exp` | int seconds | `iat + 3600` | `now - 5 < exp`, else `TOKEN_EXPIRED` |
| `jti` | string | UUID4 | identifies the token; **not** replay-tracked (one token is reused for its whole life) |
| `epoch` | int >= 0 | registry epoch of the agent at issue time | equals registry epoch, else `STALE_EPOCH` |
| `cnf` | object | `{"jkt": "<RFC 7638 SHA-256 thumbprint, base64url, 43 chars>"}` (Q20) | equals header `kid`; names the key the proof must be signed with |

No other claims are allowed (`TokenClaims` uses `extra="forbid"`). Trust scores,
scenario labels and instance labels never appear in a token.

One token per instance, with `aud = ztbroker`. It is issued by
`scripts/issue_credentials.py` and stored in the credential file (section 5).
The same token is sent to every receiver. Direct mode never checks tokens, so
this is harmless there. It replaces the old direct-mode rule "aud = receiver
name" from Q6.

`cnf.jkt` is computed exactly as `wrapper.credentials.jwk_thumbprint()` does
today: SHA-256 over `{"crv":"Ed25519","kty":"OKP","x":"<base64url raw key>"}`
with sorted keys and no spaces.

## 3. Per-message proof

Header `X-Agent-Proof: <proof JWT>` on every agent request. It replaces
`PROOF-STUB-NOT-IMPLEMENTED`. It is made by `broker.identity.client.make_proof(env,
token, private_key)`, which Afaq calls from `wrapper/send.py`.

Header:

```json
{"alg": "EdDSA", "typ": "ztb-proof+jwt"}
```

Claims (all required, no others):

| Claim | Value |
|---|---|
| `jti` | new UUID4 per message |
| `iat` | int seconds, time the proof was made |
| `aud` | `ztbroker` |
| `ath` | base64url (no padding) of SHA-256 over the token's ASCII bytes |
| `msg_hash` | base64url (no padding) of SHA-256 over the canonical envelope bytes (below) |
| `trace_id` | the envelope's `trace_id` |

Signed with the **private key of the instance named by the token's `cnf.jkt`**.
The broker verifies the signature with the registry public key whose thumbprint
is `cnf.jkt`, so a thief who has the token but signs with their own key fails
with `PROOF_KEY_MISMATCH` (A14).

**Canonical envelope bytes** (one shared function, `envelope_hash()` in
`broker/identity/client.py`, used by both sides):

```python
body = env.model_dump(mode="json", exclude=set(BROKER_FIELDS))
raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
msg_hash = base64url_nopad(sha256(raw))
```

The four broker fields (`decision`, `reason_code`, `redacted_fields`,
`broker_signature`) are left out on purpose: step 1 strips any that an agent
sets, and the hash must not change because of that. The hash was checked to be
equal before sending and after the broker parses the wire JSON (timestamps
serialise as `...Z` both times).

Responses carry no token and no proof in FYP-I. A response is the HTTP reply to
the request the broker forwarded, so the broker already knows which receiver
answered. The reply is checked by step 9 (content), not by identity.

## 4. Lifetimes and clocks

| Item | Value | Where |
|---|---|---|
| Token lifetime | 3600 s (`exp - iat`), maximum 3600 s (Q21) | issue script; broker rejects longer as `TOKEN_MALFORMED` |
| Expired test token (`--expired`, for A6) | `iat = now - 7200`, `exp = now - 3600` | issue script |
| Clock leeway | 5 s on `exp`, `nbf` and `iat` (Q21) | `broker/identity/verify.py` |
| Proof validity | accepted only if `now - 30 <= iat <= now + 5` | `verify.py` |
| Proof `jti` replay window | each accepted `jti` kept 60 s (longer than 30 s + leeway, so a proof is remembered for its whole life) | `broker/identity/replay.py` |
| Envelope `timestamp` | older than 60 s is `STALE_MESSAGE`; more than 5 s in the future is also `STALE_MESSAGE` | `broker/intercept/validate.py` |
| Envelope `msg_id` dedupe window | each `msg_id` kept 120 s (longer than the 60 s stale window) | `validate.py` |

All times are whole seconds from `time.time()`. State is in memory only; a
broker restart clears both caches (Redis is FYP-II).

## 5. Registry, credential files and the epoch rule

`broker/identity/registry.py` keeps, per agent:

| Field | Meaning |
|---|---|
| `agent_uri` | agent name |
| `role` | catalog role |
| `status` | `active`, `suspended` or `revoked` |
| `epoch` | int, starts at 0 |
| `instances` | `instance_id -> public key (and its jkt)` |

Calls for Amna's revocation code (all take the agent name, all are idempotent):

| Call | Effect | Old tokens afterwards |
|---|---|---|
| `suspend(agent)` | status `suspended` | refused with `AGENT_SUSPENDED`; valid again after `restore()` |
| `revoke(agent)` | status `revoked`, **epoch + 1** | refused with `AGENT_REVOKED`; after `restore()` still refused with `STALE_EPOCH` until a new token is issued with the new epoch |
| `restore(agent)` | status `active`, epoch unchanged | see above |

**Epoch rule:** a token is valid only while its `epoch` equals the registry
epoch of its agent. Revocation therefore kills every token issued before it,
for every instance, without a token blacklist.

**Credential files.** `scripts/issue_credentials.py` writes 7 files into `keys/`
(gitignored):

| File | Content |
|---|---|
| `planner.json`, `research.json`, `database.json`, `tool.json`, `mailer.json` | instance `<agent>-1` |
| `research-2.json` | second research instance: same agent, own key, own token |
| `research-stolen.json` | byte copy of `research.json` (attacker holds key and token) |

Each file: `{"agent", "role", "instance_id", "epoch", "private_key" (base64url raw
32 bytes), "public_jwk", "token"}`. The broker loads only the public parts to
build the registry. The copied file has the same `instance_id` and key as
`research.json`, so it adds nothing to the registry.

## 6. Delegation rule (policy, step 4)

Checked by `broker/policy/engine.py` against the **registry**, never against
roles claimed in the message:

1. The chain starts with `user` and ends with the sender (structure, already in
   `contracts.envelope.rule_violations()`, so step 1 returns `RULE_VIOLATION`).
2. At most 3 agents after `user` (chain length 4 or less), else `DELEGATION_TOO_DEEP`.
3. Every agent in the chain after `user` is registered, and its registry role is
   in the action's `allowed_roles`, else `DELEGATION_EXCEEDS_DELEGATOR`. A
   delegate can never do more than any agent that delegated to it.

Example A7: chain `user, research, planner`, action `db.query_rows`. The planner
may call it, research may not, so `DELEGATION_EXCEEDS_DELEGATOR`.

`justification` text is never read by policy (A8 gets the same decision as A1).

## 7. Order of checks in `verify_identity(headers, env)`

Header names are matched case-insensitively. The first failing check returns
its code and `ok=False`. Success returns `ok=True` with `agent`, `role`,
`instance_id` and `epoch` from the registry and `reason_code=None`.

| # | Check | Code on failure |
|---|---|---|
| 1 | `Authorization: Bearer <token>` present | `TOKEN_MISSING` |
| 2 | header decodes as a JWT | `TOKEN_MALFORMED` |
| 3 | `alg` is `EdDSA` | `BAD_ALGORITHM` |
| 4 | unverified `sub` is a registered agent | `UNKNOWN_AGENT` |
| 5 | `kid` is a registered key of that agent and the signature verifies with it | `BAD_SIGNATURE` |
| 6 | claims fit `TokenClaims`, `epoch` present, `cnf.jkt == kid`, `exp - iat <= 3600` | `TOKEN_MALFORMED` |
| 7 | `iss` | `WRONG_ISSUER` |
| 8 | `aud` | `WRONG_AUDIENCE` |
| 9 | `exp` (5 s leeway) | `TOKEN_EXPIRED` |
| 10 | `nbf` and `iat` not in the future (5 s leeway) | `TOKEN_NOT_YET_VALID` |
| 11 | `sub == env.sender` (`contracts.tokens.sub_matches_sender`) | `SUB_MISMATCH` |
| 12 | `role ==` registry role | `ROLE_MISMATCH` |
| 13 | `X-Agent-Proof` present and not the stub value | `PROOF_MISSING` |
| 14 | proof decodes, `typ` is `ztb-proof+jwt`, `alg` is `EdDSA` | `PROOF_MALFORMED` |
| 15 | proof signature verifies with the registry key named by `cnf.jkt`; then exactly the six claims, `iat` a whole number, the rest non-empty strings (else `PROOF_MALFORMED`) | `PROOF_KEY_MISMATCH` |
| 16 | proof `iat` within 30 s (5 s future leeway) | `PROOF_STALE` |
| 17 | proof `aud` is `ztbroker` | `WRONG_AUDIENCE` |
| 18 | `ath` matches the token | `PROOF_TOKEN_MISMATCH` |
| 19 | `msg_hash` matches the envelope and `trace_id` equals `env.trace_id` | `MSG_HASH_MISMATCH` |
| 20 | proof `jti` not seen in the last 60 s (then recorded) | `PROOF_REPLAY` |
| 21 | registry status is not `revoked` | `AGENT_REVOKED` |
| 22 | registry status is not `suspended` | `AGENT_SUSPENDED` |
| 23 | token `epoch ==` registry epoch | `STALE_EPOCH` |

The proof `jti` is recorded only after the proof's signature and freshness
pass, so unsigned junk cannot fill the cache.

## 8. Reason codes

One code per failure, upper snake case. A code means the same thing in every
module and in the audit log. **To add a code, add a row here in the same
change.**

### Step 1, interception: `broker/intercept/validate.py` (Kissa, K4)

| Code | Meaning |
|---|---|
| `MALFORMED_JSON` | body is not a JSON object |
| `PAYLOAD_TOO_LARGE` | payload over 64 KB (65,536 bytes of compact JSON) |
| `BAD_SCHEMA_VERSION` | `schema_version` is not `"0.2"` |
| `BAD_ENVELOPE` | fails the `Envelope` structure (missing, wrong type or extra field) |
| `RULE_VIOLATION` | `rule_violations()` is not empty |
| `STALE_MESSAGE` | timestamp older than 60 s or more than 5 s ahead |
| `BAD_PAYLOAD` | payload fails its action schema in `contracts/payloads.py` (including extra fields) |
| `DUPLICATE_MSG` | `msg_id` already seen in the last 120 s |

Forged broker fields on a request are **removed, not rejected**:
`validate_envelope` returns `ok=True` with `reason_code="BROKER_FIELDS_STRIPPED"`
as a note for the audit log. An unknown action skips the payload check and is
refused by policy with `UNKNOWN_ACTION`. The injection-cue scan never blocks;
it only sets `injection_cue=True`. It reads only the free-text fields of Amna's
rule V3 (`justification`, `query`, `request`, `suggested_action`, `subject`,
`body`). Step 1 accepts requests only: a `response` sent to the broker is
`BAD_ENVELOPE` (replies are checked in step 9). A `msg_id` is recorded only
when the whole message passes, so a rejected message does not use up its id.

### Step 2, identity: `broker/identity/verify.py` (Kissa, K2)

`TOKEN_MISSING`, `TOKEN_MALFORMED`, `BAD_ALGORITHM`, `UNKNOWN_AGENT`,
`BAD_SIGNATURE`, `WRONG_ISSUER`, `WRONG_AUDIENCE`, `TOKEN_EXPIRED`,
`TOKEN_NOT_YET_VALID`, `SUB_MISMATCH`, `ROLE_MISMATCH`, `PROOF_MISSING`,
`PROOF_MALFORMED`, `PROOF_KEY_MISMATCH`, `PROOF_STALE`, `PROOF_TOKEN_MISMATCH`,
`MSG_HASH_MISMATCH`, `AGENT_REVOKED`, `AGENT_SUSPENDED`, `STALE_EPOCH` (meanings
in section 7), and `PROOF_REPLAY`, which comes from `broker/identity/replay.py`
through `verify.py`.

### Step 4, policy: `broker/policy/engine.py` (Kissa, K3)

| Code | Verdict | Meaning |
|---|---|---|
| `UNKNOWN_ACTION` | DENY | action not in the catalog (default deny) |
| `PROHIBITED_ACTION` | DENY | action class Prohibited |
| `ROLE_NOT_ALLOWED` | DENY | sender's registry role not in `allowed_roles` |
| `WRONG_RECEIVER` | DENY | receiver is not the action's `served_by` |
| `DELEGATION_TOO_DEEP` | DENY | more than 3 agents in the chain |
| `DELEGATION_EXCEEDS_DELEGATOR` | DENY | an agent in the chain may not call the action |
| `NEEDS_APPROVAL` | ALLOW, `needs_human=True` | Conditional action that needs a human (`tool.send_email_external`) |
| `POLICY_ALLOW` | ALLOW | all policy checks passed |

Defence in depth: if policy is ever called with a failed identity it denies
with that identity code; with an identity for another agent, `SUB_MISMATCH`;
with an envelope that breaks `rule_violations()`, `RULE_VIOLATION` (same
meaning as in step 1). The Conditional rules and the delegation limit
(`max_delegation_agents: 3`) live in `broker/policy/rules.yaml`, which can
only narrow the catalog, never widen it.

### Other steps (proposed, owners to confirm)

| Code | Step | Owner |
|---|---|---|
| `AGENT_QUARANTINED` | 3, quarantine check | Amna |
| `HITL_PENDING`, `HITL_REJECTED`, `HITL_TIMEOUT` | 7, approval queue (F3) | Afaq |

### Steps 3 and 6, quarantine and trust (Amna, A2 and A3; rules V1 to V5 in `docs/detection-design.md`)

| Code | Kind | Rule | Effect | Module |
|---|---|---|---|---|
| `AGENT_QUARANTINED` | decision | step 3 | QUARANTINE for every message from a quarantined agent | `broker/defence/quarantine.py` (A3) |
| `DENIAL_RATE_EXCEEDED` | decision | V1 | QUARANTINE on the denial that makes 5 in 60 s (verified identity only) | `broker/defence/quarantine.py` (A3) |
| `TRUST_TOO_LOW` | decision | step 6 | DENY when T is below `required_trust` (A1) | `broker/trust/trust.py` (A2) |
| `INJECTION_CUE` | event | V3 | lowers T (severity 0.5), audit log; from K4 (request) or F3 (reply) | `broker/trust/trust.py` (A2) |
| `BURST_DETECTED` | event | V4 | state Suspicious for 20 messages, audit log; more than 10 requests per agent per trace | `broker/trust/rules.py` (A2) |
| `INDIVIDUAL_DATA_REQUEST` | event | V5 | lowers T (severity 1.0), audit log; flag from F3 `minimum_necessary` | `broker/trust/trust.py` (A2) |
| `REPLY_SANITIZED` | event | A2 scenario | lowers the responder's T (severity 0.5), audit log; from F3 | `broker/trust/trust.py` (A2) |

A decision code is the `reason_code` of the broker's reply. An event code never
decides on its own: it is passed to `TrustEngine.update(events=...)` and written
to the audit log. V2 adds no code: it uses `ROLE_NOT_ALLOWED` and
`DELEGATION_EXCEEDS_DELEGATOR` (step 4), counted once.

### Expected identity codes for the scenarios (input to K-R2)

| Scenario | Code |
|---|---|
| A6 expired token | `TOKEN_EXPIRED` |
| A10 token used after revocation | `AGENT_REVOKED` (`STALE_EPOCH` once the agent is restored without a new token) |
| A14 stolen token, thief signs the proof with own key | `PROOF_KEY_MISMATCH` |

A1, A8 and A13 pass identity and are refused by policy with `ROLE_NOT_ALLOWED`;
A5 with `PROHIBITED_ACTION`; A7 with `DELEGATION_EXCEEDS_DELEGATOR`. K-R2 fixes
the final single decision per scenario.

## 9. Contract change needed (proposal, needs all three)

**C-ID1: add `epoch` to `TokenClaims`.** The token must carry `epoch`, but
`TokenClaims` forbids unknown claims, so today a token with `epoch` fails the
frozen contract. Proposal: add `epoch: int` (strict, `>= 0`) with default `0`.
This is additive: existing stub tokens and all tests stay valid. The broker
itself requires the claim to be present (check 6). Logged in
`docs/open-questions.md`. Until it is agreed, the broker uses its own
`broker.identity.tokens.IdentityClaims` (TokenClaims plus `epoch`), so K1 works
without touching `contracts/`; only code that validates issued tokens with the
plain `TokenClaims` would reject them.

Not a contract change: the leeway, lifetime, proof window and cache sizes live
as constants in `broker/identity/`. The `# PROOF STUB` block in
`contracts/tokens.py` can stay until `wrapper/send.py` uses `make_proof`, then
be removed with team agreement.

## 10. For Afaq: what changes on the sender side

1. `wrapper/credentials.py` loads `keys/<file>.json` and returns its token for
   every receiver (built in K1). It is **opt-in**: the operator sets
   `AGENT_CREDENTIALS=<file name>` per process (for example `research-2`, or
   `research-stolen` for an impostor running as `research`); `AGENT_KEYS_DIR`
   overrides the folder. Without the variable the old stub is used, so direct
   runs and their tests are unchanged. A file whose agent or role differs from
   the process fails at startup. The runner strips every `AGENT_` variable from
   the parent environment, so it needs one line to pass `AGENT_CREDENTIALS` per
   agent (Afaq's change).
2. Tokens last 60 minutes from issue time: run `scripts/issue_credentials.py --force`
   shortly before a broker-mode run.
3. `wrapper/send.py` sets `X-Agent-Proof: make_proof(request, token, private_key)`
   instead of `make_proof_stub(request)`; the key is `FileCredentials.private_key`.
4. Scripted attacks: A6 uses a token from `--expired`; A14 uses
   `research-stolen.json`'s token with a freshly generated key for the proof.

## 11. Changes from the proof of concept (report Appendix A, for K-R3)

`broker/identity/verify.py` grew from the 138-line proof of concept and keeps
its structure (token, then proof, then state) and its 9 cases, which are now
pytest cases in `tests/test_broker/test_identity.py`. Decided on 2026-11-25
(this spec wins over the proof of concept):

| Point | Proof of concept | Broker (this spec) | Why |
|---|---|---|---|
| Token signer | broker issuer key, `typ` `at+jwt`, `kid` `broker-1` | the agent instance's own key, checked against the registry | registry is the trust anchor; 7 credential files, no issuer key to protect |
| Proof `aud` | the receiver | `ztbroker` | the broker is the only party that checks proofs |
| `msg_hash` | payload bytes only | the whole envelope without broker fields | receiver, action, resource and chain are signed too |
| Leeway | 30 s | 5 s on token times; proof accepted for 30 s | tighter replay window |
| Claims | `scope`, token deny list | neither (`extra="forbid"`); revocation through the epoch | one revocation mechanism |
| Epoch | starts at 1 | starts at 0 | matches `revoke()` tests |
| Replay set | kept forever | 60 s window | bounded memory |
| Result | exception text | one reason code (section 8) | audit log and teammates use the codes |
| Signature check | PyJWT `decode` | each JWT parsed once, Ed25519 checked with `cryptography`, strict base64url | PyJWT re-parsed every token on each call |

Case 5 of Table 8 ("wrong receiver, audience does not match") now fails with
`MSG_HASH_MISMATCH`, because the receiver is inside the signed envelope hash.

Measured on the development machine (`scratch` benchmark, 5 runs of 2000
checks, token and proof made in advance, in process): median 448 microseconds
per check, worst run 461. The proof of concept measured 299 microseconds for a
smaller check set. A test fails if the average goes over 1 ms.
