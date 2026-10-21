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

## Planning figures (until a warm measurement replaces them)

- **Worst-case per LLM call: 35 s.**
- A scenario makes about 2-6 LLM calls (planner plan + answer, database
  summary, tool email draft), so worst case **about 3.5 minutes** per run.
  Observed live (N1, N3): 7-8 calls and 100-120 s per run.
- Timeouts: LLM call 180 s (about 5x the worst case), one `send_message()`
  hop 600 s, one scenario run 900 s.
- Run budgets: 19 scenarios x 1 repetition about 1.1 h worst case;
  x 3 about 3.3 h; x 10 about 11 h, so the 10-repetition runs happen in
  watched blocks with `--max-minutes` and `--resume` (M6).
