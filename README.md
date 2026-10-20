# zt-broker-testbed

Test environment for a Zero Trust Message Broker for Agentic AI: the agents,
a common HTTP wrapper, a scenario runner, and baseline runs without a broker
(`MODE=direct`). See `CLAUDE.md` for project rules and `docs/open-questions.md`
for contract details that are still provisional.

## Setup (Windows, PowerShell)

Requires Python 3.12 (`winget install --id Python.Python.3.12 -e`).

```powershell
# 1. Create the virtual environment (once)
py -3.12 -m venv .venv

# 2. Verify the interpreter is the .venv one. Stop if it is not.
.\.venv\Scripts\python.exe -c "import sys; print(sys.prefix)"

# 3. Install the project and dev dependencies into .venv
.\.venv\Scripts\python.exe -m pip install -e .[dev]

# 4. Run the tests
.\.venv\Scripts\python.exe -m pytest
```

Instead of the full paths you can activate the venv for the current shell
with `.\.venv\Scripts\Activate.ps1`. If PowerShell blocks the script, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

Never install packages globally; everything goes into `.venv`.

## Configuration

Copy `.env.example` to `.env`. `MODE` is set only by the operator, never by an
agent. Do not put secrets in `.env.example`.

## HTTP calls from PowerShell

Use `curl.exe`, not `curl`. In Windows PowerShell `curl` is an alias for
`Invoke-WebRequest` and takes different arguments.
