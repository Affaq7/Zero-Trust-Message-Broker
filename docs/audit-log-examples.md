# Audit log examples (task A4)

One line from `logs/broker_audit.jsonl` for each decision (ALLOW, SANITIZE,
HITL, DENY, QUARANTINE), plus the A3 events (quarantine, release, revoke). For
Afaq's dashboard (F4) and the report.

**How these lines were made.** The broker pipeline is not on main yet, so the
entries were built by hand from the scenarios and written by the real A4 code
(`python -m broker.audit.examples`) with a throwaway key. The eight lines form
one valid chain, and a test checks that they verify with the public key below.
Replace them with lines from a broker run once the pipeline (F1) exists. T
values follow the A2 formula with the PROVISIONAL settings.

## Fields

| Field | Meaning |
|---|---|
| `kind` | `decision` for a message, or `quarantine`, `release`, `revoke`, `restore` for an A3 event |
| `ts` | broker clock, UTC |
| `seq` | line number, 1 for the first line |
| `trace_id`, `msg_id`, `parent_msg_id`, `msg_type` | from the envelope |
| `sender`, `receiver`, `action`, `resource` | from the envelope |
| `payload_hash` | SHA-256 of the payload in canonical JSON; the payload itself is never stored |
| `identity` | step 2 result: `ok`, `agent`, `role`, `instance_id`, `epoch`, `reason_code` |
| `trust` | `T_before`, `T_after`, `state_before`, `state_after` (broker-side only, never in an envelope) |
| `risk`, `compound_high` | A1 risk vector (R T D E P A S) and the compound high flag |
| `decision`, `reason_code` | the decision and its code (`docs/identity-spec.md` section 8) |
| `events` | event codes that fed the trust engine (`INJECTION_CUE`, `BURST_DETECTED`, `INDIVIDUAL_DATA_REQUEST`, `REPLY_SANITIZED`) |
| `redacted_fields` | fields cut by SANITIZE |
| `agent`, `by`, `denials` | A3 events: which agent, who did it, the denial times for V1 |
| `prev_hash` | `entry_hash` of the line before (64 zeros for the first line) |
| `entry_hash` | SHA-256 of the line's canonical JSON without `entry_hash` and `signature` |
| `signature` | broker Ed25519 signature of `entry_hash`, base64url |

No line ever holds a payload, a token, a key or a scenario label: `append()` refuses
any field not in this table.

## Checking the log

```
python -m broker.audit.verify                       # logs/broker_audit.jsonl, keys/broker_signing.pub
python -m broker.audit.verify path/to/file.jsonl --public-key path/to/key.pub
```

It prints `OK: N lines verified` (exit 0) or `FAIL: line N: reason` for the first
bad line (exit 1). Create the broker key once with
`python -m broker.audit.signing_key create` (writes `keys/broker_signing.key` and
`keys/broker_signing.pub`; keys/ is gitignored).

**Why the signature matters.** With the hash chain alone, anyone who can write
the file could change a line and recompute every later hash, and the chain would
still verify. Re-signing the lines needs the broker's private key. Known limit:
cutting lines off the end leaves a shorter valid chain, which the file alone
cannot show (for FYP-II: publish the latest `entry_hash` somewhere else).

## Public key used for these examples

```json
{"kty": "OKP", "crv": "Ed25519", "x": "nXx3SLGEpTDI-NM4aX4baBxO8YwrPyPNpU4K2SZ66-k"}
```

## 1. ALLOW (N1)

The planner asks the database for the Project X total. Identity and policy pass (`POLICY_ALLOW`), the risk is low and T stays 1.0, so the message is forwarded.

```jsonl
{"action":"db.query_aggregate","compound_high":false,"decision":"ALLOW","entry_hash":"c8ca828ba1d06275acb54cb8ab828d329ec2a857dae90b77e2e57d2cd2560e6d","events":[],"identity":{"agent":"planner","epoch":0,"instance_id":"planner-1","ok":true,"reason_code":null,"role":"planner"},"kind":"decision","msg_id":"9b2e7c40-3f1a-4d2b-8c6e-5a9d0e1f2b31","msg_type":"request","parent_msg_id":null,"payload_hash":"b1f7a18d0f17b2926e3777ac309e140aebd2e9333896d3f9097f06cd43a6fc51","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","reason_code":"POLICY_ALLOW","receiver":"database","redacted_fields":null,"resource":"db:project_costs","risk":{"A":"M","D":"M","E":"L","P":"L","R":"L","S":"L","T":"L"},"sender":"planner","seq":1,"signature":"yoWZhF4S-FWMWJ5J_7prM2hM65N2GnPtTOm8hq9-pBXjvdVK8_EBQui43uMC_BHIjqeJkIoPSj3gffoylSPGBQ","trace_id":"4f1c2a9e-0d6b-4b8e-9a51-2f7c1e0b6a11","trust":{"T_after":1.0,"T_before":1.0,"state_after":"Active","state_before":"Active"},"ts":"2026-11-25T19:00:00.000+00:00"}
```

## 2. SANITIZE (A2)

The reply to that request comes from a compromised database and carries individual salaries. The reply check (F3) cuts the extra field, so `redacted_fields` lists it and the event `REPLY_SANITIZED` lowers the database's T (severity 0.5: 1.0 to 0.9086). Afaq's F3 decides the final `reason_code` and field names for SANITIZE; this line leaves `reason_code` empty until then.

```jsonl
{"action":"db.query_aggregate","compound_high":false,"decision":"SANITIZE","entry_hash":"1570e0af065ce5b4172c0f81337e68abad51f71872723a26fadbe75593034669","events":["REPLY_SANITIZED"],"identity":{"agent":"database","epoch":0,"instance_id":"database-1","ok":true,"reason_code":null,"role":"database"},"kind":"decision","msg_id":"c3d4e5f6-1a2b-4c3d-9e8f-7a6b5c4d3e21","msg_type":"response","parent_msg_id":"9b2e7c40-3f1a-4d2b-8c6e-5a9d0e1f2b31","payload_hash":"77823f70c14105ecbd3269780fbbcc0de4b0522daaae561b46f751d1e52f5565","prev_hash":"c8ca828ba1d06275acb54cb8ab828d329ec2a857dae90b77e2e57d2cd2560e6d","reason_code":null,"receiver":"planner","redacted_fields":["rows"],"resource":"db:project_costs","risk":{"A":"M","D":"M","E":"L","P":"L","R":"L","S":"L","T":"L"},"sender":"database","seq":2,"signature":"Q7Uvh7MCOJTebvddASJOgrPgsxhN_f3TztAI67TXmyfegCZ7jdJzjTrwxsHENgOSzyIMzh-2lKdbkJGy2OxAAw","trace_id":"4f1c2a9e-0d6b-4b8e-9a51-2f7c1e0b6a11","trust":{"T_after":0.9086,"T_before":1.0,"state_after":"Active","state_before":"Active"},"ts":"2026-11-25T19:00:01.000+00:00"}
```

## 3. HITL (external mail)

The planner asks the tool to send mail outside the company. `tool.send_email_external` is Conditional and needs a human (`NEEDS_APPROVAL` in policy), so the message waits: decision HITL with `HITL_PENDING` (Afaq's F3 code, proposed in identity-spec section 8). The risk vector is compound high (three H).

```jsonl
{"action":"tool.send_email_external","compound_high":true,"decision":"HITL","entry_hash":"58db862baa04c8263e9c22cdf979758a28d61387063cda9d227aebbacf02aee4","events":[],"identity":{"agent":"planner","epoch":0,"instance_id":"planner-1","ok":true,"reason_code":null,"role":"planner"},"kind":"decision","msg_id":"0e1f2a3b-4c5d-4e6f-8a7b-9c0d1e2f3a41","msg_type":"request","parent_msg_id":null,"payload_hash":"47dff06b70fe9c1c3190b62a8f4418d52001b28e5ad58ec5984c33efbd3ac1b2","prev_hash":"1570e0af065ce5b4172c0f81337e68abad51f71872723a26fadbe75593034669","reason_code":"HITL_PENDING","receiver":"tool","redacted_fields":null,"resource":"email:external","risk":{"A":"M","D":"M","E":"H","P":"M","R":"H","S":"H","T":"M"},"sender":"planner","seq":3,"signature":"FtPUEY_48b-ncze9mtYX53DsxsSiCIyqvGX1Wu0o18V_ZmmiYEZ6lySMQNEFywdskKwCHTIVhU-RSAOQdNtMAw","trace_id":"7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c01","trust":{"T_after":1.0,"T_before":1.0,"state_after":"Active","state_before":"Active"},"ts":"2026-11-25T19:00:02.000+00:00"}
```

## 4. DENY (A1)

The research agent asks for employee rows, which only the planner may do. Policy refuses with `ROLE_NOT_ALLOWED`; the request also asks for individual-level data, so the event `INDIVIDUAL_DATA_REQUEST` is logged. One DENY moves T from 1.0 to 0.857 (still Active). This denial also counts once towards V1.

```jsonl
{"action":"db.query_rows","compound_high":false,"decision":"DENY","entry_hash":"b763859ffeda24b5d7d4f4a5859bb1117751320ec0cd08661597072f7c757b0b","events":["INDIVIDUAL_DATA_REQUEST"],"identity":{"agent":"research","epoch":0,"instance_id":"research-1","ok":true,"reason_code":null,"role":"research"},"kind":"decision","msg_id":"5d6e7f80-9a1b-4c2d-8e3f-4a5b6c7d8e91","msg_type":"request","parent_msg_id":null,"payload_hash":"bb3b28b1f1da87e9b0c509d009a4fa640e466d5b8c5e0f7e0a93d724e6baf384","prev_hash":"58db862baa04c8263e9c22cdf979758a28d61387063cda9d227aebbacf02aee4","reason_code":"ROLE_NOT_ALLOWED","receiver":"database","redacted_fields":null,"resource":"db:employees","risk":{"A":"M","D":"H","E":"L","P":"M","R":"L","S":"M","T":"L"},"sender":"research","seq":4,"signature":"tSmBq5Fluh5_Mgys0jJfAIFApriZRiUMk4ajab2-M6kpDNbpB8MbnzxkCfWE-WbUPOfGVAG5oK6kF0G_00glBg","trace_id":"2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d61","trust":{"T_after":0.857,"T_before":1.0,"state_after":"Active","state_before":"Active"},"ts":"2026-11-25T19:00:03.000+00:00"}
```

## 5. Quarantine event (A9, rule V1)

Not a message decision: the fifth DENY within 60 s from the same verified agent. `denials` holds the broker-clock times of the five denials, and `by` is `broker` because the rule did it on its own.

```jsonl
{"agent":"research","by":"broker","denials":[1764097204.0,1764097205.0,1764097206.0,1764097207.0,1764097208.0],"entry_hash":"096a75df45ffa628f8ca526dc07dc4dae7f3c0327baeba308ec990bb65c02b00","kind":"quarantine","prev_hash":"b763859ffeda24b5d7d4f4a5859bb1117751320ec0cd08661597072f7c757b0b","reason_code":"DENIAL_RATE_EXCEEDED","seq":5,"signature":"xeYlWPRn2NHcv_JY6udCmBb0XC5YlZGfjirhHBA1Ix8cfitMv73hTrzFEyM4pIINOfl2oR5z6pe9eLI0cgboDA","ts":"2026-11-25T19:00:08.000+00:00"}
```

## 6. QUARANTINE (A9)

The next message from the quarantined agent. Step 3 stops it before policy, so the line has no risk vector; nothing is forwarded. T after five DENY is 0.5996 (Restricted); the block comes from V1, not from T.

```jsonl
{"action":"db.query_rows","compound_high":null,"decision":"QUARANTINE","entry_hash":"afb3e102eef7804a1385545bd8019f1bc84b98cc699c5dcec63967bdf61af5a2","events":[],"identity":{"agent":"research","epoch":0,"instance_id":"research-1","ok":true,"reason_code":null,"role":"research"},"kind":"decision","msg_id":"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c81","msg_type":"request","parent_msg_id":null,"payload_hash":"7e307b2166341d0ca9bc1d25fc7ea9699a445a9c63a9edf9a65fb3f9465e7355","prev_hash":"096a75df45ffa628f8ca526dc07dc4dae7f3c0327baeba308ec990bb65c02b00","reason_code":"AGENT_QUARANTINED","receiver":"database","redacted_fields":null,"resource":"db:payroll","risk":null,"sender":"research","seq":6,"signature":"lSjQXU3G0EgcoYvXKX7Xgs5-2cvvsYJPjfztsB7AgZNyi0ZEn33sKXm4Op1gA8JSwLXxTkIqDXfn0I7z_qpBCw","trace_id":"8c9d0e1f-2a3b-4c4d-9e5f-6a7b8c9d0e71","trust":{"T_after":0.5996,"T_before":0.5996,"state_after":"Restricted","state_before":"Restricted"},"ts":"2026-11-25T19:00:09.000+00:00"}
```

## 7. Release event (A9)

A reviewer from the allowed list (`amna`, `kissa`, `afaq`) releases the agent. The trust engine restarts it in Restricted at T = 0.50.

```jsonl
{"agent":"research","by":"kissa","denials":null,"entry_hash":"6937c4c026527ecc17422e59c43ad9e4320ec198503811b84c6484cf1705b3cc","kind":"release","prev_hash":"afb3e102eef7804a1385545bd8019f1bc84b98cc699c5dcec63967bdf61af5a2","reason_code":null,"seq":7,"signature":"f5MqBPVDwfCALYZgNoXtiKhgYBMvc5eNAOxl2xdmGi1lEIrEVAZNbgPfKw4f-dnGIbV7EUtH6jQTF_LxuzTLBw","ts":"2026-11-25T19:05:00.000+00:00"}
```

## 8. Revoke event (A10)

An operator revokes the tool agent mid-session (registry status revoked, epoch + 1). Its next message, with a token issued before the revoke, fails identity with `STALE_EPOCH` (epoch checked first; a new token while still revoked gets `AGENT_REVOKED`), which the pipeline would log as a decision line with that identity code.

```jsonl
{"agent":"tool","by":"amna","denials":null,"entry_hash":"eebc047aeefdebc7fdd51d1e5f57f3a62172b6a506baffc616ea7bdb61e204c5","kind":"revoke","prev_hash":"6937c4c026527ecc17422e59c43ad9e4320ec198503811b84c6484cf1705b3cc","reason_code":null,"seq":8,"signature":"XOjY880YZr179pZxcq-CveRlqLSOdhJ4lcap2701eIltOvYFa2SDQx4V3LJ-0OjUKgRzK_rHIfd7cXiuMQgrDg","ts":"2026-11-25T19:06:00.000+00:00"}
```
