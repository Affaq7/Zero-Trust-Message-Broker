"""CI check 'protected-paths' (standard library only), driven by .github/ownership.json.

Rules, in order:
  (a) a change under contracts/ fails unless the PR has the label contracts-approved;
  (b) a change to a frozen prompt module, or to a frozen prompt's hash line in
      docs/measurements.md, fails unless the PR has the label prompt-change-approved;
  (c) by branch prefix, a file outside the owner's list (and outside the shared list)
      fails unless the PR has the label cross-owner-approved. Files governed by (a) or (b)
      are judged by their own label only. A branch with no owner entry gets a warning.

Labels and the branch name come from the pull_request event payload (GITHUB_EVENT_PATH).
Local use (from the repo root):
  python scripts/ci/check_paths.py --base origin/main --head HEAD --branch kissa/x --label contracts-approved
Exit codes: 0 pass (warnings allowed), 1 violations, 2 the check could not run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_common import REPO_ROOT, SetupError, annotate, diff_lines, git, load_event, resolve_range  # noqa: E402

DEFAULT_CONFIG = REPO_ROOT / ".github" / "ownership.json"


def matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return path.startswith(pattern)
    return fnmatchcase(path, pattern)


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(matches(path, p) for p in patterns)


def load_config(path: Path = DEFAULT_CONFIG) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SetupError(f"cannot read {path.name}: {exc}") from exc


@dataclass
class Result:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def owner_prefix(branch: str, owners: dict) -> str | None:
    for prefix in sorted(owners, key=len, reverse=True):
        if branch.startswith(prefix):
            return prefix
    return None


def hash_record_touched(config: dict, record_lines: list[tuple[int, str]]) -> bool:
    markers = config["frozen_prompts"]["hash_records"]["markers"]
    return any(marker in text for _, text in record_lines for marker in markers)


def evaluate(config: dict, changed: list[str], branch: str, labels: set[str],
             hash_lines_changed: bool) -> Result:
    res = Result()
    lab = config["labels"]
    contracts = config["contracts"]
    frozen = config["frozen_prompts"]
    record_file = frozen["hash_records"]["file"]

    # (a) contracts
    contract_files = [p for p in changed if matches_any(p, contracts)]
    if contract_files:
        if lab["contracts"] in labels:
            res.notes.append(f"contracts/ change allowed by label {lab['contracts']}")
        else:
            for p in contract_files:
                res.errors.append(f"contracts-change: {p} needs label {lab['contracts']}")

    # (b) frozen prompts
    prompt_files = [p for p in changed if matches_any(p, frozen["files"])]
    prompt_items = prompt_files + ([f"{record_file} (frozen prompt hash line)"] if hash_lines_changed else [])
    if prompt_items:
        if lab["frozen_prompts"] in labels:
            res.notes.append(f"frozen prompt change allowed by label {lab['frozen_prompts']}")
        else:
            for item in prompt_items:
                res.errors.append(f"frozen-prompt-change: {item} needs label {lab['frozen_prompts']}")

    # (c) ownership by branch prefix
    prefix = owner_prefix(branch, config["owners"])
    if prefix is None:
        res.warnings.append(f"branch {branch!r} has no owner prefix in ownership.json; ownership not checked")
        return res
    allowed = config["owners"][prefix] + config.get("shared", [])
    governed = set(contract_files) | set(prompt_files)
    outside = [p for p in changed if p not in governed and not matches_any(p, allowed)]
    if outside:
        if lab["cross_owner"] in labels:
            res.notes.append(f"{len(outside)} file(s) outside {prefix}* allowed by label {lab['cross_owner']}")
        else:
            for p in outside:
                res.errors.append(f"cross-owner-change: {p} is outside {prefix}* ownership; "
                                  f"needs label {lab['cross_owner']}")
    return res


def pr_context(event: dict, branch: str | None, labels: list[str] | None) -> tuple[str, set[str]]:
    pr = event.get("pull_request") or {}
    if branch is None:
        branch = (pr.get("head") or {}).get("ref") or os.environ.get("GITHUB_HEAD_REF") \
            or os.environ.get("GITHUB_REF_NAME") or git("rev-parse", "--abbrev-ref", "HEAD").strip()
    if labels is None:
        labels = [lbl.get("name", "") for lbl in pr.get("labels") or []]
    return branch, set(labels)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="protected-paths check")
    ap.add_argument("--base")
    ap.add_argument("--head")
    ap.add_argument("--branch", help="branch name (default: from the event payload, else the current branch)")
    ap.add_argument("--label", action="append", help="a PR label (repeatable; default: from the event payload)")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = ap.parse_args(argv)
    try:
        config = load_config(args.config)
        event = load_event()
        base, head = resolve_range(args.base, args.head, event)
        branch, labels = pr_context(event, args.branch, args.label)
        # --no-renames: a rename shows as delete + add, so the old path is checked too.
        changed = [p for p in git("diff", "--name-only", "--no-renames", f"{base}...{head}").splitlines() if p]
        record_file = config["frozen_prompts"]["hash_records"]["file"]
        record_diff = diff_lines(base, head, [record_file], diff_filter="ACDMR").get(record_file)
        record_lines = (record_diff.added + record_diff.removed) if record_diff else []
    except SetupError as exc:
        print(annotate("error", f"check could not run: {exc}"))
        return 2
    res = evaluate(config, changed, branch, labels, hash_record_touched(config, record_lines))
    print(f"Branch {branch!r}; labels {sorted(labels) or 'none'}; {len(changed)} changed file(s) in {base}...{head}.")
    for n in res.notes:
        print(f"note: {n}")
    for w in res.warnings:
        print(annotate("warning", w))
    for e in res.errors:
        print(annotate("error", e))
    if res.errors:
        print(f"FAILED: {len(res.errors)} violation(s). See docs/ci.md.")
        return 1
    print("OK: protected paths respected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
