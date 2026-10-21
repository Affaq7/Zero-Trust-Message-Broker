# Measurements on the development machine

Machine: Intel i5-1145G7, 16 GB RAM, no NVIDIA GPU; Ollama runs llama3:8b
(Q4_0) **100% on CPU**.

| Date | Measurement | Result | Notes |
|---|---|---|---|
| 2026-10-21 | Live LLM test (`pytest -m ollama`), one JSON decision, **cold start** | **35.1 s** | Measured by the user; Ollama had just started, so it includes loading the model. |
| 2026-10-21 | Raw Ollama call, tiny prompt, cold | 17.5 s (14.1 s of it loading the model) | Prompt eval ~25 tokens/s, generation ~5-7 tokens/s. |
| 2026-10-21 | Raw Ollama call, tiny JSON prompt, warm | 3.4 s | |
| later | Live LLM test, warm | to be measured | |

## Planning figures (until a warm measurement replaces them)

- **Worst-case per LLM call: 35 s.**
- A scenario makes about 2-6 LLM calls (planner plan + answer, database
  summary, tool email draft), so worst case **about 3.5 minutes** per run.
- Timeouts: LLM call 180 s (about 5x the worst case), one `send_message()`
  hop 600 s, one scenario run 900 s.
- Run budgets: 19 scenarios x 1 repetition about 1.1 h worst case;
  x 3 about 3.3 h; x 10 about 11 h, so the 10-repetition runs happen in
  watched blocks with `--max-minutes` and `--resume` (M6).
