# Documentation index and the broker hand-over

Start here if you are plugging the broker into the testbed (Kissa, Amna). The testbed's own setup and
every command is in the repo-root `README.md`; everything below is from the repo root.

## Where to read what

| File | What is in it |
|---|---|
| `docs/broker-integration.md` | **For the broker developer.** Where the broker sits, what `MODE=broker` does today, environment variables, envelopes in and out, tokens, what the testbed expects back, the plug-in checklist (section 9) |
| `docs/baseline-report.md` | the direct-mode baseline: status of all 19 scenarios, expected broker decision, measured numbers (and what was **not** executed) |
| `docs/measurements.md` | timings, every live run with its numbers, the frozen prompt hashes, the P1 concurrency run |
| `docs/scenario-coverage.md` | message paths per scenario, which apply in direct mode, entitled parties, gaps G1-G4 |
| `docs/agents-and-roles.md` | which agents exist, their roles, what each may call and serve |
| `docs/open-questions.md` | every contract or design question with its status (S1-S20, Q1-Q28, M1-M16) |
| `contracts/` | the shared definitions (envelope, action catalog, payloads, token claims); not changed without the user's approval |

## 1. Switching MODE

`MODE` is **only** read from the environment of each agent process (`direct` or `broker`). No message,
token or agent can change it. The wrapper reads it once at start (`wrapper/config.py`).

| | `MODE=direct` (the baseline) | `MODE=broker` (today) |
|---|---|---|
| Wrapper `POST /message` | parses the envelope, checks `receiver == AGENT_NAME`, runs the agent | HTTP 501 (`wrapper/app.py`, the `settings.mode == "broker"` branch) |
| `send_message()` | posts straight to the receiver in `AGENT_URLS` | raises `BrokerModeNotImplementedError` (`wrapper/send.py`, the `settings.mode == "broker"` branch) |

Run one agent by hand in either mode:

```powershell
$env:MODE="direct"; $env:AGENT_NAME="planner"; & ".\.venv\Scripts\python.exe" -m uvicorn wrapper.main:app --port 8001
```

**The scenario runner sets `MODE` for every agent process with `--mode direct|broker`** (default
`direct`; `runner/processes.py` puts it in each process's environment, never in a message, and the
runner ignores any `MODE` it inherited). The mode is written to `run_meta.json` (`"mode"`) and shown in
the report; a run keeps its mode, so `--resume` continues with the mode the run started with and
refuses `--mode`.

```powershell
# the baseline (same as leaving --mode out)
& ".\.venv\Scripts\python.exe" -m runner --mode direct --scenario N1 --reps 3
# every agent process with MODE=broker
& ".\.venv\Scripts\python.exe" -m runner --mode broker --scenario N1 --reps 3
```

Today `--mode broker` only proves the switch: the broker is not built, so the wrappers answer HTTP 501
and `send_message()` raises, and every task that sends a message ends in error (the run still
finishes and records it; the runner prints a note). Not-applicable scenarios are recorded the same way
in both modes (they have no executable definition yet). How an agent reaches the broker
(`BROKER_URL`, or `AGENT_URLS` pointing every name at the broker) is still open (Q26). Plugging the
broker in means: (1) implement the two broker branches above; (2) pass the broker address from the
runner to the processes (the mode is already passed); (3) run the same scenarios with `--mode broker`
and compare with the direct-mode runs.

## 2. Reproduce the baseline

```powershell
# one-time: .venv with the pinned packages (repo-root README, "Setup")
& ".\.venv\Scripts\python.exe" -m pytest                       # the fake suite, about 10 minutes

# the scenario list (checks the files, starts nothing)
& ".\.venv\Scripts\python.exe" -m runner --dry-run

# fake LLM: scripted replies, checks the whole pipeline (seconds to a minute per scenario)
& ".\.venv\Scripts\python.exe" -m runner --scenario N1 --scenario N2 --scenario N3 --scenario N4 --reps 3

# live LLM: start Ollama with llama3:8b first; planner prompt v2 is the default and frozen
& ".\.venv\Scripts\python.exe" -m runner --llm ollama --scenario N1 --scenario N2 --scenario N3 --scenario N4 --reps 3 --max-minutes 90

# P1: N4 at 1, 10 and 50 concurrent tasks (fake LLM only)
& ".\.venv\Scripts\python.exe" -m runner --scenario P1 --reps 1

# the report for one or more runs
& ".\.venv\Scripts\python.exe" -m runner.report <run_id> [<run_id> ...]
```

A final baseline run uses **one planner prompt version for every scenario** (the default, v2;
`--planner-prompt v1` reproduces the historical first baseline). `run_meta.json` records the version
and fingerprint, and a run that mixes versions is flagged. Interrupted runs continue with
`--resume <run_id>`.

## 3. Where the results go

`results\<run_id>\` (the run id is a UTC timestamp, printed when the run starts; the folder is
gitignored and never committed):

| File | What |
|---|---|
| `run_meta.json` | settings, git commit, planner prompt version and fingerprint, warm-ups, scenario checksums, the N/A scenarios |
| `results.csv` | one row per task: status, latency, messages, LLM calls, research timings, criteria passed/failed |
| `summary.csv` | per scenario and concurrency level: runs, completed, median/mean/p95/max latency, messages, wall time, throughput |
| `criteria.jsonl` | every success check of every task, with the final answer |
| `events.jsonl`, `ground_truth.jsonl` | one line per logged envelope (no payloads); the mock services' record of what really happened |
| `report.md`, `report.csv` | made by `python -m runner.report` |
| `<scenario>\c<level>\repNN\` | that repetition's logs (`logs\*.jsonl` message logs), process logs and fake scripts |

Scenario labels, expected decisions and trust values stay in the scenario files and these results;
they never appear in an envelope, a token or a message log.

## 4. Comparing with the broker later

The baseline numbers to compare against are in `docs/baseline-report.md`: N1-N4 task success and
latency (live), P1 throughput (fake LLM), and the expected decision of every scenario. Attack
attacks A1, A5, A6, A7, A8, A13 (scripted attacker sender; A7 relays through the planner via
`planner.request`) and A2, A4 (compromised-responder double) are encoded and run in direct mode; A3 is
encoded and runs with the **live model only** (a document prompt-injection; 10 live reps, temperature 0
with fixed seeds, llama3:8b did not follow the injection — reproducibility for this model and injection,
not a rate). Attack success needs the response payload status plus a ground-truth record, never HTTP 200
alone, and the attack-success figures are in the baseline report (section 3a; A3's live result in
section 3b).
