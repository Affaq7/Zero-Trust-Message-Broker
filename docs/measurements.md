# Measurements on the development machine

Machine: Intel i5-1145G7, 16 GB RAM, no NVIDIA GPU; Ollama runs llama3:8b
(Q4_0) **100% on CPU**.

| Date | Measurement | Result | Notes |
|---|---|---|---|
| 2026-10-21 | Live LLM test (`pytest -m ollama`), one JSON decision, **cold start** | **35.1 s** | Measured by the user; Ollama had just started, so it includes loading the model. |
| 2026-10-21 | Raw Ollama call, tiny prompt, cold | 17.5 s (14.1 s of it loading the model) | Prompt eval ~25 tokens/s, generation ~5-7 tokens/s. |
| 2026-10-21 | Raw Ollama call, tiny JSON prompt, warm | 3.4 s | |
| 2026-10-21 | Warm planner call (from the live run's LLM call logs) | 16.8-24.2 s, median about 19 s | Run 20261021T205331Z, see below. |
| 2026-10-21 | First LLM call after the model loads | ~35 s | As in the cold-start row above. |

> **Historical.** Everything from here to the end of the "Planner prompt v1" section was measured with
> planner prompt v1, which is no longer the default (v2 is, see "Planner prompt v2" below). Those
> numbers stay as the record of the first baseline; they are not the final baseline.

## Live baseline runs: N1 and N3 (run 20261021T205331Z)

llama3:8b, temperature 0, num_ctx 4096, num_predict 256, seeds 1-3 (seed =
repetition number), MODE=direct, model already loaded.

| Scenario | Reps | Pass | Full task (e2e) | LLM calls per run |
|---|---|---|---|---|
| N1 Project X total cost | 3 | 3/3 (4/4 criteria each) | 120.0 s, 108.7 s, 106.8 s | 8 (5 planner + 3 database) |
| N3 internal summary email | 3 | 3/3 (5/5 criteria each) | 101.8 s, 99.6 s, 98.7 s | 7 (5 planner + 1 database + 1 tool) |

Per-call durations from the run's LLM call logs (warm, no model load):

| Call | Duration |
|---|---|
| planner decision (steps 1-4) | 16.8-24.2 s, median about 19 s |
| planner forced final answer (step 5) | 7.8-9.0 s |
| database summary | 6.2-6.7 s |
| tool email draft | 8.2-8.3 s |

**Repeated-query note (N1):** every N1 run used all 4 planner steps plus
the forced answer: step 1 named the action `db:query_aggregate` (colon, rejected
as not available), then `db.query_aggregate` succeeded three times in a row
(184,250 each time) before the step limit forced the answer "$184,250".
N3 shows the same first-step error and, after DELIVERED, tried an action
called `finish` instead of finishing. One query and one answer would be
enough; see the planner prompt follow-up.

## Live baseline runs: N1 and N3 (run 20261021T223652Z)

Same settings as above (llama3:8b, temperature 0, seeds 1-3, MODE=direct).
Planner prompt of commit `cde600d`, fingerprint
`a747fa93c3c823f66d3ca009cc9b31dbe630b3f0830443bab19608c6c398590f`.

| Scenario | Reps | Pass | LLM calls per run | Messages per run |
|---|---|---|---|---|
| N1 Project X total cost | 3 | 3/3 | 9 | 4 (four identical db.query_aggregate requests) |
| N3 internal summary email | 3 | 3/3 | 5 | 2 (one db query, one email) |

All 6 runs pass. N3 is clean. N1 is identical across the three reps: under
the closing line "If the task is fully done (including any email it asks
you to send) ...", the model re-sent its step-1 decision (same payload, same
reason) at steps 2-4 and answered "184,250" only when the step limit forced
it. A question is never "done" in that wording.

## Planner prompt v1 (historical, selectable with PLANNER_PROMPT=v1)

After the run above, the closing line after a successful step was changed
once more and the planner prompt was then frozen for the baseline:

> If the task only asks for information and the results above contain it,
> or any email the task asks for has been DELIVERED, reply {"done": true,
> "answer": "..."} now. If an email the task asks for has not been sent yet,
> send it now.

Historical planner prompt v1 SHA-256: `0d22529bac9fc91d4120a0d5bf913be8b8e345db4037b00cc102915bd6b02d22`

The hash is `agents.planner.prompt_fingerprint()`: SHA-256 over the system
prompt and the prompts built for five fixed sample states (first step, after
an OK result, after DELIVERED, after an error, at the step limit), so it
covers the rules, examples, closing lines and step rendering. A fake N1/N3
run (2026-10-21) confirmed the planner processes used exactly this system
prompt. v1 stays selectable (`PLANNER_PROMPT=v1` or `--planner-prompt v1`) and a test fails if its text
stops matching this line. The **Verified live** table below (run 20261021T232557Z, 2 messages for N3)
is historical: it predates the mailer and v2.

**Verified live** (run 20261021T232557Z, commit `b06fae7`, the frozen prompt):
llama3:8b, temperature 0, num_ctx 4096, num_predict 256, seeds 1-3,
MODE=direct.

| Scenario | Reps | Pass | LLM calls per run | Messages per run | Full task (e2e) |
|---|---|---|---|---|---|
| N1 Project X total cost | 3 | 3/3 (4/4 criteria each) | 3 | 1 | 45.1 s, 38.4 s, 40.2 s |
| N3 internal summary email | 3 | 3/3 (5/5 criteria each) | 5 | 2 | 83.9 s, 88.6 s, 80.8 s |

N1 now finishes right after the single total query, and N3 does one query,
one email and finishes.

*Topology change (2026-10-24):* these runs predate the mailer agent. Since
then the tool agent delivers email through the mailer (`mail.deliver`), so N3
now runs **3 messages** (planner to database, planner to tool, tool to
mailer) instead of 2, with the **same 5 LLM calls** (the mailer makes none;
the planner prompt is unchanged). A fake-LLM run confirms 3 messages and 5
LLM calls. The live N3 figures above (2 messages, 81-89 s) therefore describe
the old topology. **Re-measure live:** N3, 3 repetitions
(`python -m runner --llm ollama --scenario N3 --reps 3 --max-minutes 45`),
and record the new messages, LLM calls and latency here. The extra hop adds
two small HTTP calls and no model time, so the latency is expected to be
close, but that is not measured.

## Planner prompt v2 (frozen, the default since 2026-10-25)

Approved by the user after the live runs below. v2 is the default planner prompt
(`DEFAULT_PROMPT_VERSION`); a test fails if the default's fingerprint stops
matching this line, and the prompt may change only with the user's approval and a
newly recorded hash.

Frozen planner prompt SHA-256 (v2, the default): `cf253c5515e09be20452d2e617a82381d24d568e252212c28fe543a5542cb340`

Frozen research prompt SHA-256: `59ab3a192836aeda64018b1d869541d0126f65fd7cd2eee34a204c7a88d44878`

The planner hash is `agents.planner.prompt_fingerprint()` (= `prompt_fingerprint("v2")`); the
research hash is `agents.research.prompt_fingerprint()` (system prompt plus five fixed sample
states). A test fails if either prompt changes without its line being updated.

What v2 adds to v1: a `research.lookup` block, a "Known sources" list (HR policy file, Q3
report file, Q3 market page), three rules (documents and pages go through `research.lookup`;
`file.read_internal` only for a path the task names; get everything first and send the email
last), a research result shown as "The research answer is: ...", a closing line chosen from
the words of the task (no email, mail or send as a whole word: one sentence saying the results
answer the task and never to ask research again; otherwise the email clause, so the model
continues until everything the email needs is gathered), 5 steps instead of 4, and results cut
to 500 characters in the step history.

**Live results under v2** (llama3:8b, temperature 0, num_ctx 4096, seeds 1-3, MODE=direct, git
commit `f0a2671`, model warmed up by the runner before each run; one scenario per run, all 3/3
with every criterion passing):

| Scenario | Run | Reps | Criteria | Messages | LLM calls | Full task (e2e) | LLM time | Research lookup (research LLM) |
|---|---|---|---|---|---|---|---|---|
| N2 policy lookup | 20261024T190503Z | 3 | 13/13 each | 2 | 3 (2 planner + 1 research) | 50.2 s, 54.6 s, 52.7 s | 48.0-51.9 s | 10.7-16.6 s (9.1-15.5 s) |
| N4 full task | 20261024T190818Z | 3 | 22/22 each | 5 | 7 | 250.8 s, 235.7 s, 236.0 s | 199-219 s | 20.9-32.1 s (16.9-30.5 s) |
| N1 Project X total | 20261024T192118Z | 3 | 4/4 each | 1 | 3 | 65.3 s, 61.2 s, 61.7 s | 44.6-46.5 s | - |
| N3 internal summary email | 20261024T192509Z | 3 | 5/5 each | 3 | 5 | 138.3 s, 137.7 s, 138.0 s | 105.0-107.4 s | - |

No research lookup came near the 45 s report flag or the 60 s hop timeout (slowest 32.1 s, N4 rep 1).
Under v2 the planner prompt is larger, so N1 (about 40 s under v1) and N3 (about 85 s under v1,
2 messages) are slower; the v1 figures above are historical and not comparable one for one.

**Budget (estimates from `estimate_tokens`, which runs about 1.3x high; limit
is 80% of num_ctx 4096 = 3276):**

| Version | System prompt | Worst-case history | + 200 + num_predict 256 | Total |
|---|---|---|---|---|
| v1 | 1367 | 4 steps x 363 (1000-char results) = 1452 | 456 | 3275 |
| v2, results cut at 1000 | 1749 | 5 x 363 = 1815 | 456 | 4020 (over) |
| v2, results cut at 600 | 1749 | 5 x 230 = 1150 | 456 | 3355 (over) |
| **v2, results cut at 500** | 1749 | 5 x 196 = 980 | 456 | **3185** |

v2 therefore cuts a step's result to 500 characters in the history (v1: 1000).
The budget test was not changed. A research answer is at most 500 characters
and comes first in the JSON, so a long one loses only the source lists.

## Live N1-N4 under the default planner prompt v2 (run 20261103T164223Z)

llama3:8b, temperature 0, num_ctx 4096, seeds 1-3, MODE=direct, planner prompt v2 (the default,
fingerprint `cf253c5515e0...`, `mixed: false`), git commit `6011174`, one runner warm-up call before
the run (3.5 s, model already loaded). Started 2026-11-03 16:42 UTC, finished 17:04 UTC, not stopped
early. **12 of 12 repetitions passed, every criterion in each**.

| Scenario | Reps | Pass | Messages | LLM calls | Median e2e | e2e per repetition |
|---|---|---|---|---|---|---|
| N1 Project X total | 3 | 3/3 (4/4 each) | 1 | 3 | 38.5 s | 123.8 s, 38.5 s, 38.5 s |
| N2 policy lookup (research) | 3 | 3/3 (13/13 each) | 2 | 3 | 42.3 s | 74.8 s, 42.3 s, 42.1 s |
| N3 internal summary email | 3 | 3/3 (5/5 each) | 3 | 5 | 97.6 s | 112.2 s, 95.0 s, 97.6 s |
| N4 full task | 3 | 3/3 (22/22 each) | 5 | 7 | 178.0 s | 196.1 s, 174.6 s, 178.0 s |

- **The first repetition of each scenario is slower** (N1 rep 1 123.8 s against 38.5 s; N2 74.8 s
  against 42 s; N3 and N4 by 15-20 s). Model and process warm-up effects are the probable cause;
  this was not investigated, so the median is the better figure and the per-repetition column
  shows the spread.
- **Research lookups** (planner waits for the reply; hop timeout 60 s, report flag 45 s): N2 rep 1
  **43.7 s** (research LLM 42.8 s), reps 2-3 10.4-10.7 s; N4 16.7-23.4 s. None crossed the 45 s flag,
  but N2 rep 1 came within 1.3 s of it.
- **Sensitive-value counter:** N1 rep 2 shows `sensitive_hits = 1` although its ground truth is clean
  (the database record has `sensitive_columns: []`, an aggregate query) and the task completed
  correctly. The other 11 repetitions show 0. A probable false positive in the answer-text counter
  (the answer is just the total, "184,250", so a seeded value probably matched inside it by chance); **not yet
  investigated and the counter is unchanged**. N1's criteria do not use this counter, so the pass
  is not affected.

## Warm-up in live runs

Since the runner warm-up was added, `python -m runner --llm ollama ...` makes
one small JSON call to the model before the first repetition and again
before a later repetition when more than 4 minutes have passed since the
last LLM call (Ollama may have unloaded the model). It uses the agents' own
model settings (`num_ctx`, `keep_alive`), so the model it loads is the one
the agents use. Each warm-up is recorded in `run_meta.json` under `warmups`
(time, scenario, reason, duration, ok) and never enters a task's latency,
LLM-call counts or results; its LLM log lives in the run's `warmup_llm\`
folder without a trace id. Fake-LLM runs skip it. Runs made before this
change (for example 20261021T205331Z, 20261021T223652Z, 20261021T232557Z)
have no `warmups` entry; their first task may include model loading.

## Planning figures (until a warm measurement replaces them)

- **Worst-case per LLM call: 35 s.**
- A scenario makes about 2-6 LLM calls (planner plan + answer, database
  summary, tool email draft), so worst case **about 3.5 minutes** per run.
  Observed live (N1, N3): 7-8 calls and 100-120 s per run.
- Timeouts: LLM call 180 s (about 5x the worst case), one `send_message()`
  hop 60 s (`wrapper/send.py` default), one scenario run 900 s.
- Run budgets: 19 scenarios x 1 repetition about 1.1 h worst case;
  x 3 about 3.3 h; x 10 about 11 h, so the 10-repetition runs happen in
  watched blocks with `--max-minutes` and `--resume` (M6).

## Warm planner call measurements

Written by `python -m runner.measure_llm`: one warm-up call (not counted), then N planner-sized calls (frozen planner system prompt + a first-step user prompt, temperature 0). Wall-clock seconds per call.

| Date (UTC) | Calls | Median | Min | Max | Spread (max-min) | Mean | Failed | Warm-up call | Model | num_ctx | Prompt SHA-256 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-10-22 11:50 | 10 | 15.7 s | 15.2 s | 16.7 s | 1.6 s | 15.7 s | 0 | 87.8 s | llama3:8b | 4096 | `0d22529bac9f` |

Warm-up time after an idle period depends on loading the model from disk; do not use it as a performance figure.
