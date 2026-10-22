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

## Frozen planner prompt

After the run above, the closing line after a successful step was changed
once more and the planner prompt was then frozen for the baseline:

> If the task only asks for information and the results above contain it,
> or any email the task asks for has been DELIVERED, reply {"done": true,
> "answer": "..."} now. If an email the task asks for has not been sent yet,
> send it now.

Frozen planner prompt SHA-256: `0d22529bac9fc91d4120a0d5bf913be8b8e345db4037b00cc102915bd6b02d22`

The hash is `agents.planner.prompt_fingerprint()`: SHA-256 over the system
prompt and the prompts built for five fixed sample states (first step, after
an OK result, after DELIVERED, after an error, at the step limit), so it
covers the rules, examples, closing lines and step rendering. A fake N1/N3
run (2026-10-21) confirmed the planner processes used exactly this system
prompt. A test fails if the prompt changes without this line being updated.

**Verified live** (run 20261021T232557Z, commit `b06fae7`, the frozen prompt):
llama3:8b, temperature 0, num_ctx 4096, num_predict 256, seeds 1-3,
MODE=direct.

| Scenario | Reps | Pass | LLM calls per run | Messages per run | Full task (e2e) |
|---|---|---|---|---|---|
| N1 Project X total cost | 3 | 3/3 (4/4 criteria each) | 3 | 1 | 45.1 s, 38.4 s, 40.2 s |
| N3 internal summary email | 3 | 3/3 (5/5 criteria each) | 5 | 2 | 83.9 s, 88.6 s, 80.8 s |

N1 now finishes right after the single total query, and N3 does one query,
one email and finishes.

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
