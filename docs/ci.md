# Pull request checks (CI)

Every pull request into `main` runs `.github/workflows/pr-checks.yml` on GitHub Actions
(ubuntu-latest, Python 3.12). It can also be started by hand from the Actions tab
(`workflow_dispatch`; it then compares the branch with `origin/main`).

The workflow uses the `pull_request` trigger (not `pull_request_target`), a read-only
token (`permissions: contents: read`) and no secrets. The only actions it uses are
`actions/checkout` and `actions/setup-python`, pinned to full commit SHAs. A new push to
the same PR cancels the run still in progress. Adding or removing a label re-runs the checks.

## Required check names

Set exactly these four as required status checks:

| Check | What it does | Typical time |
|---|---|---|
| `tests` | Installs `.[dev,agents]` with `constraints.txt` and runs `python -m pytest -q`. The live-Ollama test stays skipped (`RUN_OLLAMA_TESTS` is not set). | install + suite |
| `secrets-and-forbidden-files` | `scripts/ci/check_forbidden.py`: fails if the PR adds or changes a forbidden file, or adds a line that looks like a secret or contains a seeded sensitive value. | seconds |
| `protected-paths` | `scripts/ci/check_paths.py`: contracts, frozen prompts and folder ownership, driven by `.github/ownership.json` and the PR's labels. | seconds |
| `direct-mode-smoke` | After `tests` passes: runs N1 and A1 in direct mode with the fake LLM and asserts N1 `task_completed` and A1 `attack_succeeded` are `true` in `results.csv`. | about 1 minute + install |

## secrets-and-forbidden-files

Compares the PR head with its base (`git diff --diff-filter=ACMR base...head`, added lines only).

Forbidden files (added or changed): `.env*` (this includes `.env.example`, so a change to it
fails too), anything under a `keys/`, `logs/` or `results/` folder, `scenarios/source/`,
and `*.pem`, `*.key`, `*.sqlite`, `*.db`, `*.docx`.

Rules for added lines:

- `private-key-header`: a PEM/OpenSSH/PGP private key header.
- `jwt-shaped-string`: three base64url parts where the first two start like JSON objects.
- `secret-assignment`: a name containing password, passwd, secret, token or api_key assigned
  (`=`, `:` or `:=`) a quoted literal of 4+ characters. Obvious placeholders are ignored:
  values containing stub, fake, dummy, example, placeholder or marker; the scripted attacker's
  token modes (valid, invalid, expired, missing, wrong_key); and template values such as
  `${NAME}`, `<value>` or `***`.
- `seeded-sensitive-value`: any value from `mocks.seed.sensitive_values()` (SSNs, home
  addresses, salaries, bank accounts). The values are generated when the check runs, from the
  seed generator in the base commit and in the PR, and are never written down anywhere.

Output is only the rule name and `file:line`, never the matched text. If a finding is a
false positive, change the line (for example use a placeholder word) rather than the rule.

## protected-paths

Labels and the branch name are read from the GitHub event payload. Rules:

1. **contracts/**: any change fails unless the PR has the label `contracts-approved`.
2. **Frozen prompts**: the planner v1/v2 and research prompts are built inside
   `agents/planner.py` and `agents/research.py`; their hashes are the lines
   "Historical planner prompt v1 SHA-256", "Frozen planner prompt SHA-256 (v2, the default)"
   and "Frozen research prompt SHA-256" in `docs/measurements.md`. Any change to either module,
   or to one of those lines, fails unless the PR has the label `prompt-change-approved`.
   (This is file-level: an edit to non-prompt code in those two modules needs the label too.)
3. **Ownership by branch prefix** (map in `.github/ownership.json`):
   - `kissa/*`: `broker/identity/`, `broker/policy/`, `broker/intercept/`,
     `scripts/issue_credentials.py`, `wrapper/credentials.py`, `tests/test_broker/` files for
     registry, identity, policy and validate, `docs/identity-spec.md`, `docs/scenario-control-map.md`.
   - `amna/*`: `broker/trust/`, `broker/defence/`, `broker/audit/`, `broker/transport/`,
     `scripts/simulate_trust.py`, `tests/test_broker/` files for risk, trust, defence, audit and
     signing, `docs/trust-calibration.md`, `docs/detection-design.md`, `docs/audit-log-examples.md`.
   - `afaq/*`: anything (rules 1 and 2 still apply).
   - Every branch may edit `docs/open-questions.md`.
   - A file outside the owner's list fails unless the PR has the label `cross-owner-approved`.
     Files covered by rule 1 or 2 need only that rule's label.
   - A branch with any other prefix gets a warning only (rules 1 and 2 still apply).

Renamed files count under both the old and the new path.

### The three labels

| Label | Allows |
|---|---|
| `contracts-approved` | changes under `contracts/` (only after all three agreed and a line was added to `docs/open-questions.md`) |
| `prompt-change-approved` | changes to the frozen prompt modules or their hash lines |
| `cross-owner-approved` | edits outside the branch owner's folders |

Create them once under Issues > Labels. Only people with write access can add labels, so a
label is the approval.

## Running the checks locally (Windows PowerShell, from the repo root)

```powershell
& ".\.venv\Scripts\python.exe" -c "import sys; print(sys.prefix)"   # must be .venv
git fetch origin

# tests
& ".\.venv\Scripts\python.exe" -m pytest -q

# secrets-and-forbidden-files: your branch against main
& ".\.venv\Scripts\python.exe" "scripts\ci\check_forbidden.py" --base origin/main --head HEAD

# protected-paths: give the branch and the labels the PR would have
& ".\.venv\Scripts\python.exe" "scripts\ci\check_paths.py" --base origin/main --head HEAD --branch kissa/identity-policy
& ".\.venv\Scripts\python.exe" "scripts\ci\check_paths.py" --base origin/main --head HEAD --branch kissa/identity-policy --label cross-owner-approved

# direct-mode-smoke
& ".\.venv\Scripts\python.exe" -m runner --scenario N1 --llm fake --reps 1 --results-dir "scratch\smoke-n1"
& ".\.venv\Scripts\python.exe" -m runner --scenario A1 --llm fake --reps 1 --results-dir "scratch\smoke-a1"
& ".\.venv\Scripts\python.exe" "scripts\ci\check_smoke.py" "scratch\smoke-n1" N1 task_completed
& ".\.venv\Scripts\python.exe" "scripts\ci\check_smoke.py" "scratch\smoke-a1" A1 attack_succeeded

# the scripts' own unit tests
& ".\.venv\Scripts\python.exe" -m pytest -q tests\test_ci
```

Delete `scratch\smoke-n1` and `scratch\smoke-a1` before running the smoke again
(`check_smoke.py` expects exactly one run per folder). Exit codes: 0 pass, 1 findings,
2 the check could not run.

## Branch protection to turn on (Settings > Branches > rule for `main`)

- Require a pull request before merging; require 1 approval; require review from Code Owners
  (`.github/CODEOWNERS` makes @Affaq7 the owner of everything).
- Dismiss stale approvals when new commits are pushed.
- Require status checks to pass, with "Require branches to be up to date before merging",
  and add the four checks: `tests`, `secrets-and-forbidden-files`, `protected-paths`,
  `direct-mode-smoke`. (A check appears in the list only after it has run once.)
- Require conversation resolution before merging.
- Do not allow bypassing the above settings (include administrators).
- Block force pushes and branch deletion.
- Optional: Settings > Actions > General: "Require approval for all outside collaborators"
  for fork PRs, and set the default workflow permissions to read-only.
