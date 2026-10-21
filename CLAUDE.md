# zt-broker-testbed

Testbed for a final-year project: a Zero Trust Message Broker for Agentic AI.
LLM agents (planner, research, database, tool, malicious) exchange messages.
A broker (built by teammates, NOT in this repo) will later sit between them
and decide ALLOW / SANITIZE / HITL / DENY / QUARANTINE per message.
This repo holds: the agents, a common HTTP wrapper, the scenario runner, and
the baseline runs with no broker.

## Modes
- MODE=direct: agents call each other straight. This is the baseline.
- MODE=broker: traffic goes through the broker (currently returns HTTP 501).
- MODE is set ONLY by the operator (env var / Docker Compose). It is read only
  from the environment, never from a message, and no agent can change it.

## Direct mode provides NO security (this is deliberate)
In MODE=direct the wrapper ONLY:
- parses the envelope (valid JSON, required fields present, correct types), and
- checks `receiver == AGENT_NAME`.
It does NOT validate payload schemas, does NOT verify or even require a token,
and does NOT apply the action catalog, RBAC or default-deny. Those are the
broker's job. Adding any of them to direct mode would weaken the baseline.
Agents still attach a token when sending; direct mode just never checks it.

## Fixed decisions (ask before changing)
- Python 3.12 (3.11 also allowed), FastAPI + Uvicorn, Pydantic v2, httpx,
  pytest, python-dotenv, PyYAML, PyJWT[crypto]
- Agents: LangGraph and CrewAI (mixed)
- LLM: Ollama llama3:8b at LLM_BASE_URL (default http://localhost:11434), temperature 0
- Transport: HTTP, JWT (EdDSA only) in `Authorization: Bearer`
- Dev environment: Windows, PowerShell, VS Code

## Contracts (v0.2), in contracts/
- contracts/ is the single source of truth, shared with the broker team.
- DO NOT modify anything in contracts/ without explicit approval from the user.
- The action catalog lives in contracts/action_catalog.yaml. Never hard-code
  actions, roles or served_by anywhere else; load them through contracts.
- The JWT is never inside the envelope. JWT `sub` must equal envelope `sender`.
- Trust scores and test/scenario labels must NEVER appear in an envelope, a
  token or the message log. The runner records scenario labels separately.
- The per-message proof is a STUB (format not defined by us). Keep it clearly
  marked `# PROOF STUB` and do not invent a final format.
- Several contract details are provisional. See docs/open-questions.md and do
  not present them as final anywhere.

## Message log
The wrapper appends every parsed request ("in") and every response it sends
("out") to logs/<AGENT_NAME>.jsonl (gitignored; override with LOG_DIR). One line
per envelope: {"logged_at", "logged_by", "direction", "envelope"}, where
envelope is the full envelope. Never log HTTP headers, the Authorization
token or the proof header. No scenario labels or trust scores in the log; the
runner records labels separately.

## Sending messages
Agents send through `wrapper.send.send_message()`. It builds the envelope with
new_request() (sender = this process's AGENT_NAME) and posts it to the
receiver's wrapper in direct mode; broker mode raises "not implemented" for
now. MODE and the receiver URLs (AGENT_URLS="name=url,...") are read from the
operator-set environment at call time, never from a message. The caller passes
the token (Authorization: Bearer); the X-Agent-Proof header is the PROOF STUB.
Neither is logged. Tests inject in-process transports via the `client` argument.

## Secrets
- Never write real keys or secrets into files.
- Credentials are issued by a teammate's script; keys stay in keys/ (gitignored).
- .env is gitignored; only .env.example (no secrets) is committed.

## Repo path contains a space
The repo's absolute path contains a space. Do not move it, and do not write
the absolute path (it contains the user's Windows username) into the repo:
docs say "from the repo root". Quote every path in commands, scripts and docs. In code, build
paths with pathlib relative to the file (never hard-code the absolute path).

## Virtual environment (required)
- All Python work happens in .venv (Python 3.12). Never install globally and
  never use the system Python for project work.
- Create:   py -3.12 -m venv ".venv"
- Install:  & ".\.venv\Scripts\python.exe" -m pip install -e ".[dev]"
  Re-run it after adding a new top-level package (wrapper/, agents/, runner/):
  the editable install only maps packages that existed when it ran.
- Verify before every install or test run, and stop if it is not .venv:
  & ".\.venv\Scripts\python.exe" -c "import sys; print(sys.prefix)"
- Or activate: & ".\.venv\Scripts\Activate.ps1"

## Commands (PowerShell, from the repo root)
- Tests:       & ".\.venv\Scripts\python.exe" -m pytest
- Run wrapper: $env:MODE="direct"; $env:AGENT_NAME="dummy"; & ".\.venv\Scripts\python.exe" -m uvicorn wrapper.main:app --port 8001
  (wrapper.main reads MODE/AGENT_NAME at import and fails fast if they are invalid;
  tests use wrapper.app.create_app(Settings(...)) instead)
- HTTP calls:  use `curl.exe`, NOT `curl` (in Windows PowerShell `curl` is an
  alias for Invoke-WebRequest)

## Working style
- Small steps, each with a pytest test, one commit per step.
- Plan first and wait for approval before large changes.
- When something is unclear, ask instead of guessing.
- Remote: origin = https://github.com/Affaq7/Zero-Trust-Message-Broker.git (private), branch main.
- After each step the user approves: scan the commits about to be pushed for
  secrets (.env, keys/, *.pem/*.key, logs/, tokens, credentials), then
  `git push` only if clean. Never force-push, never rewrite history, never put
  a token or password in a URL or file. If a push is rejected, the remote has
  new commits, or the scan hits: stop and tell the user. Pushing never replaces
  the user's approval for changes to contracts/.
- Throwaway files made only to try something out go in scratch/ (gitignored).
  Real tests, including tests/test_smoke.py, stay tracked.

## Milestone 1 steps
0. Bootstrap: git, .venv, pyproject, .gitignore, .env.example, docs
1. contracts/: envelope model (version.py, envelope.py)
2. contracts/: action catalog as YAML (with served_by) + loader
3. contracts/: per-action payload schemas (proposal) + generic response payload
4. contracts/: response builder (make_response)
5. contracts/: JWT claim model + per-message proof stub
6. wrapper/ + agents/dummy: POST /message (direct: parse + receiver check only; broker: 501)
7. wrapper/: JSONL message log in logs/
8. Manual curl.exe test with examples/dummy_request.json
9. send_message() helper (direct -> receiver, broker -> broker)

## Milestone 2 (in progress; decisions in docs/open-questions.md, M1-M14)
Goal: mock services, five real agents, scenario runner, baseline runs in
MODE=direct. Agents get JSON decisions from llama3:8b (no native tool
calling); code performs actions. Scenario data (scenarios/source/) is
runner-only: never commit or encode it until the user says so, and never
let agents read it. Stage files by name (not `git add -A`) while it exists.
Steps: 0 docs; 1 mock skeleton + seeded SQLite + ground truth; 2 DB
endpoints; 3 file store + web fixtures; 4 mail sink + admin handler;
5 venv check/split; 6 LLM layer + fake backend; 7 POST /task + stub tokens;
8-12 tool, database, research, planner, malicious agents; 13 scenario
schema; 14 runner; 15 results + metrics; 16 all scenarios; 17-18 live baseline.
