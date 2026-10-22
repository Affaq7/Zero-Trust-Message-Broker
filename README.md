# zt-broker-testbed

Test environment for a Zero Trust Message Broker for Agentic AI: the agents,
a common HTTP wrapper, a scenario runner, and baseline runs without a broker
(`MODE=direct`). See `CLAUDE.md` for project rules and `docs/open-questions.md`
for contract details that are still provisional.

All data is fictional and everything runs on this machine (localhost): the
agents talk to each other and to a mock company (database, files, web pages,
mail sink, admin handler); nothing is sent to a real service or person.

## Quick start

1. [Set up the virtual environment](#setup-windows-powershell) and run the tests.
2. [Run N1 and N3 with the fake LLM](#scenario-runner): a few seconds each, no model needed.
3. [Run them with the live LLM](#scenario-runner): needs Ollama with llama3:8b.
4. [Write a report](#scenario-runner) from the run, and [resume](#scenario-runner) an interrupted run.
5. Read the [documentation map](#documentation) and the [known limits](#known-limits-of-the-testbed).

## Setup (Windows, PowerShell)

Requires Windows with PowerShell, Git and Python 3.12
(`winget install --id Python.Python.3.12 -e`). Live runs also need Ollama
(https://ollama.com) with the model pulled once: `ollama pull llama3:8b`
(it serves on `http://localhost:11434`; set `LLM_BASE_URL` if yours differs).

The repo path contains a space, so always quote paths. All commands below are
run from the repo root.

```powershell
# 0. Work from the repo root (VS Code terminals open there; otherwise Set-Location to it)
Get-Location   # must print the repo root (the zt-broker-testbed folder)

# 1. Create the virtual environment (once)
py -3.12 -m venv ".venv"

# 2. Verify the interpreter is the .venv one. Stop if it is not.
& ".\.venv\Scripts\python.exe" -c "import sys; print(sys.prefix)"

# 3. Install the project, dev tools and agent frameworks (LangGraph, CrewAI)
#    into .venv with the pinned versions. Takes several minutes the first time.
#    Re-run after adding a new top-level package such as wrapper/ or agents/.
& ".\.venv\Scripts\python.exe" -m pip install -e ".[dev,agents]" -c "constraints.txt"

# 4. Run the tests (several hundred, about 5 minutes; some start real processes)
& ".\.venv\Scripts\python.exe" -m pytest
```

Everything should pass; one test is skipped (the live Ollama test below).

Optional live LLM test (skipped by default; start Ollama with llama3:8b first):

```powershell
$env:RUN_OLLAMA_TESTS = "1"
& ".\.venv\Scripts\python.exe" -m pytest -m ollama -v -s
Remove-Item Env:RUN_OLLAMA_TESTS
```

Instead of the full paths you can activate the venv for the current shell
with `& ".\.venv\Scripts\Activate.ps1"`. If PowerShell blocks the script, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

Never install packages globally; everything goes into `.venv`.

`constraints.txt` holds the exact versions of every package. CrewAI holds
pydantic at 2.12.x, so the whole project (including `contracts/`) runs on
pydantic 2.12.5. CrewAI, LangChain and ChromaDB telemetry is switched off by
`agents/telemetry.py`.

## Configuration

Copy `.env.example` to `.env`. `MODE` is set only by the operator, never by an
agent. Do not put secrets in `.env.example`.

## Manual test: dummy agent with curl.exe (VS Code, two PowerShell terminals)

Uses `examples\dummy_request.json` and `scripts\print_stub_token.py`. The
token is a STUB, signed with a throwaway in-memory key; direct mode never
checks it. Nothing secret is written to disk.

### 0. Open two terminals and confirm they are PowerShell

Open the integrated terminal (`` Ctrl+` ``), then a second one with the `+`
button. In **each** terminal run:

```powershell
$PSVersionTable.PSEdition
```

It must print `Desktop` (Windows PowerShell 5.1) or `Core` (PowerShell 7).
If you get an error or nothing, the terminal is cmd or Git Bash: pick
**PowerShell** from the `v` menu next to `+` and try again.

### 1. Terminal 1: start the dummy agent

```powershell
Get-Location   # must print the repo root (the zt-broker-testbed folder)
& ".\.venv\Scripts\python.exe" -c "import sys; print(sys.prefix)"
$env:MODE = "direct"
$env:AGENT_NAME = "dummy"
& ".\.venv\Scripts\python.exe" -m uvicorn wrapper.main:app --host 127.0.0.1 --port 8001
```

The `sys.prefix` line must print the repo's `.venv` folder; stop if it does
not. Expected server output (the process number differs):

```
INFO:     Started server process [8720]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8001 (Press CTRL+C to quit)
```

Leave this terminal running. Each request appears here as one line, e.g.
`INFO:     127.0.0.1:57334 - "POST /message HTTP/1.1" 200 OK`.

### 2. Terminal 2: send requests

```powershell
Get-Location   # must print the repo root (the zt-broker-testbed folder)

# a) Health check
curl.exe -s "http://127.0.0.1:8001/health"
```
Expected: `{"status":"ok","agent":"dummy","mode":"direct"}`

```powershell
# b) Get a stub token (one line, starts with eyJ)
$token = & ".\.venv\Scripts\python.exe" "scripts\print_stub_token.py"
$token
```

```powershell
# c) Send the example request, pretty-printed
curl.exe -s -X POST "http://127.0.0.1:8001/message" -H "Content-Type: application/json" -H "Authorization: Bearer $token" --data-binary "@examples/dummy_request.json" | ConvertFrom-Json | ConvertTo-Json -Depth 5
```

Expected (msg_id and timestamp differ on every call; timestamps are UTC):

```
{
    "schema_version":  "0.2",
    "msg_id":  "<new UUID>",
    "trace_id":  "22222222-2222-4222-8222-222222222222",
    "parent_msg_id":  "11111111-1111-4111-8111-111111111111",
    "msg_type":  "response",
    "sender":  "dummy",
    "receiver":  "planner",
    "action":  "db.query_aggregate",
    "resource":  "db:sales",
    "payload":  {
                    "status":  "ok",
                    "result":  {
                                   "text":  "Hello from the dummy agent."
                               },
                    "error":  null
                },
    "delegation_chain":  [
                             "user",
                             "planner"
                         ],
    "timestamp":  "<now, UTC, ends in Z>",
    "decision":  null,
    "reason_code":  null,
    "redacted_fields":  null,
    "broker_signature":  null
}
```

Leave out `| ConvertFrom-Json | ConvertTo-Json -Depth 5` to see the raw
one-line JSON.

```powershell
# d) Invalid body: expect the error JSON, then "HTTP 422"
curl.exe -s -w "`nHTTP %{http_code}`n" -X POST "http://127.0.0.1:8001/message" -H "Content-Type: application/json" --data-binary "not json"

# e) Same request with the absolute path ($PWD = repo root, which contains a space): expect "HTTP 200"
curl.exe -s -o NUL -w "HTTP %{http_code}`n" -X POST "http://127.0.0.1:8001/message" -H "Content-Type: application/json" --data-binary "@$PWD\examples\dummy_request.json"
```

```powershell
# f) Look at the message log: last two lines are your request ("in") and the
#    response ("out"). The second command must print nothing (no token logged).
Get-Content ".\logs\dummy.jsonl" -Tail 2
Select-String -Path ".\logs\dummy.jsonl" -Pattern "Bearer|eyJhbGci"
```

Quoting notes: always use `curl.exe` (plain `curl` is an alias for
`Invoke-WebRequest` in Windows PowerShell); keep URLs, headers and the
`"@file"` argument in double quotes; `` `n `` inside double quotes is
PowerShell's newline. Send JSON from a file with `--data-binary "@..."`,
not inline: Windows PowerShell 5.1 strips inner quotes from arguments to
native programs.

### 3. Stop the server and clean up

In terminal 1 press `Ctrl+C` (expect `Shutting down` ... `Finished server
process`). On Windows a `KeyboardInterrupt`/`CancelledError` traceback after
Ctrl+C is harmless: the server has stopped normally. The `$env:` variables
stay set in that terminal until you close it, or remove them with:

```powershell
Remove-Item Env:MODE, Env:AGENT_NAME
```

Optional check that a bad MODE stops the server at startup (terminal 1):

```powershell
$env:MODE = "bogus"; $env:AGENT_NAME = "dummy"
& ".\.venv\Scripts\python.exe" -m uvicorn wrapper.main:app --port 8001
```

Expected: a traceback ending in
`wrapper.config.ConfigError: MODE must be one of ('direct', 'broker'), got 'bogus'`
and no "Uvicorn running" line. Then run `Remove-Item Env:MODE, Env:AGENT_NAME`.

## Agent-to-agent messages (send_message)

Agents send requests with `wrapper.send.send_message()`. The operator tells
each wrapper where the other agents are with `AGENT_URLS` (comma-separated
`name=url` pairs), for example:

```powershell
$env:AGENT_URLS = "dummy=http://127.0.0.1:8001,tool=http://127.0.0.1:8004"
```

The runner starts work with `POST /task` (`{"task": "...", "trace_id": "..."}`),
standing in for the human user; it accepts no other fields. Each wrapper mints
its own STUB tokens (one throwaway key per process, one token per receiver).
`AGENT_IMPL` runs different code under a name, e.g. an impostor:
`$env:AGENT_NAME = "research"; $env:AGENT_IMPL = "malicious"`.

The sender is the wrapper's own `AGENT_NAME`. In `MODE=direct` the request
goes straight to the receiver's `/message`; `MODE=broker` is not implemented
yet and raises an error.

## Mock services (the fake company the agents act on)

One process, no LLM: a seeded SQLite database, a sandboxed file store,
fixture web pages, a mail sink and an admin handler. Everything they do is
appended to `logs\mocks.jsonl` (ground truth for the runner). Working copies
live in `runtime\mocks\` and are rebuilt from the seed at startup and on
`POST /reset`. All data is fictional.

```powershell
& ".\.venv\Scripts\python.exe" -m uvicorn mocks.main:app --host 127.0.0.1 --port 8090
```

Quick checks from a second terminal (from the repo root):

```powershell
curl.exe -s "http://127.0.0.1:8090/health"
curl.exe -s -X POST "http://127.0.0.1:8090/db/query_aggregate" -H "Content-Type: application/json" --data-binary "@examples/mock_db_aggregate.json"
curl.exe -s -X POST "http://127.0.0.1:8090/mail/send" -H "Content-Type: application/json" -H "X-Trace-Id: manual-1" --data-binary "@examples/mock_mail_a4.json"
curl.exe -s "http://127.0.0.1:8090/ground-truth?trace_id=manual-1"
curl.exe -s -X POST "http://127.0.0.1:8090/reset"
```

## Scenario runner

The runner starts the mock services and the agents of each scenario as
separate processes, sends the task, collects envelopes, ground truth and
LLM calls, evaluates the success criteria and writes `results\<run_id>\`
(gitignored): `run_meta.json` (settings, git commit, prompt fingerprint,
warm-ups), `results.csv` (one row per task), `criteria.jsonl` (every success
check and the final answer), `events.jsonl`, `ground_truth.jsonl` and
`summary.csv`. All processes are stopped afterwards, also after Ctrl+C.

Encoded so far (7 of the 19 scenarios, in `scenarios\`):

| Scenario | What | In direct mode |
|---|---|---|
| **N1** | planner asks the database for the total cost of Project X | runs |
| **N3** | planner emails an internal summary to one colleague | runs |
| **A9, A10, A11, A12, A14** | attacks that need the broker or a token check | **not applicable**: recorded as `not_applicable` with the reason, never run, left out of every rate |

The other 12 are not built yet; see [Known limits](#known-limits-of-the-testbed).
Run from the repo root:

```powershell
# Check the scenario files (no processes started)
& ".\.venv\Scripts\python.exe" -m runner --dry-run

# Fake LLM: scripted replies from the scenario file; no model is called.
# Checks the whole pipeline (processes, messages, mock world, evaluation).
# Takes seconds to about half a minute per scenario, depending on machine
# load (N1 took 4-14 s and N3 8-27 s on the development machine).
& ".\.venv\Scripts\python.exe" -m runner --scenario N1 --scenario N3 --reps 1

# Every encoded scenario, 3 repetitions each (the not-applicable ones are only recorded):
& ".\.venv\Scripts\python.exe" -m runner --reps 3

# Live LLM: start Ollama with llama3:8b first (LLM_BASE_URL, default
# http://localhost:11434). CPU-only: about 40 s (N1) to 85 s (N3) per task
# once the model is loaded (docs/measurements.md).
& ".\.venv\Scripts\python.exe" -m runner --llm ollama --scenario N1 --scenario N3 --reps 3 --max-minutes 45

# Add --debug-prompts to save every planner prompt and the model's reply
# (stepNN.txt / stepNN.reply.json) under the run's logs\prompts folder.
```

Each command prints the run id and one line per task; the results are in
`results\<run_id>\`.

**Warm-up (live runs only).** With `--llm ollama` the runner first makes one
small call to the model, so the first measured task does not include model
loading (about 35-90 s after an idle period, `docs\measurements.md`). It
warms up again before a later repetition if more than 4 minutes have passed
since the last LLM call. Each warm-up (time, scenario, duration) is recorded
in `run_meta.json` under `warmups` and printed, but it is never part of any
task's latency or results. Fake runs skip it (`warmup_note` says so). If the
warm-up call fails (Ollama not running), the run stops before any task and
can be continued with `--resume`.

Expected for a fake run: one line per not-applicable scenario
(`A9: not applicable (<reason>)`), one line per task ending in
`completed completed=True <ms> ms`, then the results folder. Open
`results\<run_id>\summary.csv` for the table. A live run can fail where the
fake one passes (the model may choose other actions); `results.csv` has a
`criteria_failed` column and `criteria.jsonl` the detail of every check, and
`results\<run_id>\<scenario>\...\processes\` holds each process's log.

If a run is interrupted (Ctrl+C, `--max-minutes`, a crash), carry it on in
the same folder; scenarios and repetitions already in its `results.csv` are
skipped, and it refuses if a scenario file changed since the run started:

```powershell
& ".\.venv\Scripts\python.exe" -m runner --resume <run_id>
```

Baseline report for one or more runs: writes `report.md` and `report.csv` into
each run folder (per scenario: runs, task-completed rate, median/mean/max
latency, median LLM calls and messages; not-applicable scenarios with their
reasons; LLM settings, seeds, git commit and planner prompt fingerprint).
With several run ids it also writes a combined report to `results\report-<time>\`:

```powershell
& ".\.venv\Scripts\python.exe" -m runner.report <run_id>
```

(`<run_id>` is the folder name under `results\`, e.g. `20261021T232557Z`.)

Warm-call measurement on the live LLM (start Ollama first): one warm-up call,
then N planner-sized calls; median, min, max, spread and mean are appended
to the "Warm planner call measurements" table in `docs\measurements.md`
(`--no-write` only prints). About 20 s per call on this CPU-only machine:

```powershell
& ".\.venv\Scripts\python.exe" -m runner.measure_llm --calls 10
```

Scenario files go in `scenarios\` (one JSON file each). To debug a single
agent by hand, start it with uvicorn as in the manual test above.

## Message log

Each wrapper appends every request it receives and every response it sends to
`logs\<AGENT_NAME>.jsonl` (gitignored; `LOG_DIR` overrides the folder).

**Run one uvicorn worker per agent** (the default; do not pass `--workers`).
The log is only safe for one process: several workers writing the same file
could interleave lines.

## HTTP calls from PowerShell

Use `curl.exe`, not `curl`. In Windows PowerShell `curl` is an alias for
`Invoke-WebRequest` and takes different arguments.

## Documentation

| File | What is in it |
|---|---|
| `docs/open-questions.md` | every contract and design question, with its status (decided, provisional, open) and who must confirm it |
| `docs/scenario-coverage.md` | message paths for all 19 scenarios, which ones apply in direct mode, entitled parties, the four gaps (G1-G4) and the contract changes proposed for the teammates |
| `docs/broker-integration.md` | for the broker developer: where the broker sits, what `MODE=broker` does today, envelopes, headers, what the testbed expects back, and what is still open |
| `docs/agents-and-roles.md` | which agents exist, their roles, what each may call and serve |
| `docs/measurements.md` | timings, live N1/N3 results, the frozen planner prompt hash, warm-call measurements |
| `docs/milestone-1-summary.md` | what Milestone 1 built and how a message flows |
| `contracts/` | the shared definitions (envelope, action catalog, payload schemas, token claims); not changed without approval |
| `CLAUDE.md` | the project rules for anyone (or any assistant) working in this repo |

## Known limits of the testbed

- **One small model.** All live results are from llama3:8b (4-bit) on a
  CPU-only laptop, temperature 0, one seed per repetition. Other models or
  hardware can behave differently. llama3:8b has no native tool calling, so
  agents ask it for small JSON decisions and ordinary code performs the actions.
- **Only N1 and N3 have live results**, 3 repetitions each, on llama3:8b with
  the frozen planner prompt (`docs/measurements.md`). Changing the planner
  prompt breaks a test on purpose until the new hash is recorded there.
- **7 of 19 scenarios are encoded.** N1 and N3 run. **A9, A10, A11, A12 and
  A14 are not applicable in direct mode** (they need the broker's denials,
  quarantine, encrypted link or network isolation, or a token/proof check that
  direct mode does not have); they are recorded and left out of every rate.
  A13 *is* applicable in direct mode but not built yet.
- **12 scenarios are not built yet**, for these reasons:

  | Not built | Why |
  |---|---|
  | N2, N4, P1 | need the planner to ask a research agent: there is no catalog action for that yet (G1) and no research agent. P1 repeats N4 |
  | A1, A5, A8, A13 | the requester is the research agent (not built, G1), or an agent acting under another agent's identity (not built); A8 also needs a place for free text (G4) |
  | A2, A4, A6, A7 | need an agent that misbehaves in a defined way or acts under another agent's identity (not built); A7 also needs an action served by the planner (G2); the broker side of A4 waits for G3 |
  | A3 | needs only the existing agents; not built yet |

  G1-G4 are decisions for the broker team; see `docs/scenario-coverage.md`.
- **Direct mode has no security, on purpose.** It is the baseline: no payload
  checks, no token checks, no access rules. `MODE=broker` returns 501 until a
  broker exists. Tokens are unverifiable stubs and the per-message proof is a
  placeholder.
- **Concurrency is tested with the fake LLM only** (10 tasks at once). Ollama
  answers one request at a time on this machine, so live tasks would queue
  behind each other.
- **Timings depend on the machine** (and fake runs vary with load too).
  Model loading after an idle period takes about 35-90 s; live runs warm the
  model up first, but a single message hop times out after 60 s.
- **Everything is fictional and local.** The mail sink and the admin handler
  only record what they receive. `results\`, `logs\` and `runtime\` are not
  committed; the team's scenario sheet export in `scenarios\source\` is not
  committed either.

## Troubleshooting

**`git push` reports exit code 255 although it worked.** On this Windows
setup, `git push` can print exit code 255 even when the push succeeded (git
writes its progress to stderr, which PowerShell treats as an error). Check
the real result instead of the exit code:

```powershell
git status -sb                      # "## main...origin/main" with no [ahead N] means pushed
git log --oneline -1 origin/main    # should show your latest commit
```
