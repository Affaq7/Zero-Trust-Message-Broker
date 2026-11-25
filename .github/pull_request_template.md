## What this PR does

<!-- One or two sentences. -->

## Review checklist

- [ ] Only my own folders are changed (see `.github/ownership.json`), or the PR has the `cross-owner-approved` label.
- [ ] No change under `contracts/`, unless all three of us agreed, a line was added to `docs/open-questions.md`, and the PR has the `contracts-approved` label.
- [ ] Function and class signatures match the plan.
- [ ] Tests are included for the change, and the whole suite is green.
- [ ] No secrets or keys (no `.env`, `keys/`, `*.pem`, `*.key`, tokens, passwords or seeded sensitive values).
- [ ] Direct mode is unchanged (`MODE=direct` still only parses the envelope and checks the receiver).
