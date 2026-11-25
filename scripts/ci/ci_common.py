"""Shared helpers for the CI check scripts (standard library only).

The diff range is taken from, in order: --base/--head arguments, the BASE_SHA/HEAD_SHA
environment variables, the pull_request event payload (GITHUB_EVENT_PATH), and finally
origin/main...HEAD (for a local run or workflow_dispatch).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = "origin/main"
DEFAULT_HEAD = "HEAD"


class SetupError(Exception):
    """The check could not run (bad range, git failure, missing file). Exit code 2."""


def git(*args: str, cwd: Path = REPO_ROOT) -> str:
    # core.quotePath=false keeps paths with spaces or non-ASCII characters unquoted.
    cmd = ["git", "-c", "core.quotePath=false", *args]
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise SetupError(f"git {' '.join(args[:3])} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def load_event(path: str | None = None) -> dict:
    path = path or os.environ.get("GITHUB_EVENT_PATH")
    if not path or not Path(path).is_file():
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))


def resolve_range(base: str | None, head: str | None, event: dict) -> tuple[str, str]:
    pr = event.get("pull_request") or {}
    base = base or os.environ.get("BASE_SHA") or (pr.get("base") or {}).get("sha") or DEFAULT_BASE
    head = head or os.environ.get("HEAD_SHA") or (pr.get("head") or {}).get("sha") or DEFAULT_HEAD
    return base, head


@dataclass
class FileDiff:
    path: str
    added: list[tuple[int, str]] = field(default_factory=list)    # (new line number, text)
    removed: list[tuple[int, str]] = field(default_factory=list)  # (old line number, text)


_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_unified_diff(text: str) -> dict[str, FileDiff]:
    """Parse `git diff -U0` output into added/removed lines per file (new path)."""
    files: dict[str, FileDiff] = {}
    current: FileDiff | None = None
    old_path = None
    old_no = new_no = 0
    in_header = False  # between "diff --git" and the first hunk; content lines never live here
    for line in text.splitlines():
        if line.startswith("diff --git "):
            current, old_path, in_header = None, None, True
            continue
        if in_header and line.startswith("--- "):
            old_path = line[4:]
            old_path = old_path[2:] if old_path.startswith("a/") else old_path
            continue
        if in_header and line.startswith("+++ "):
            new_path = line[4:]
            new_path = new_path[2:] if new_path.startswith("b/") else new_path
            if new_path == "/dev/null":
                new_path = old_path or new_path
            current = files.setdefault(new_path, FileDiff(new_path))
            in_header = False
            continue
        if in_header:
            continue
        m = _HUNK.match(line)
        if m:
            old_no, new_no = int(m.group(1)), int(m.group(2))
            continue
        if current is None:
            continue
        if line.startswith("+"):
            current.added.append((new_no, line[1:]))
            new_no += 1
        elif line.startswith("-"):
            current.removed.append((old_no, line[1:]))
            old_no += 1
    return files


def diff_lines(base: str, head: str, paths: list[str] | None = None,
               diff_filter: str = "ACMR") -> dict[str, FileDiff]:
    args = ["diff", "--no-color", "--no-ext-diff", "-U0", f"--diff-filter={diff_filter}",
            f"{base}...{head}"]
    if paths:
        args += ["--", *paths]
    return parse_unified_diff(git(*args))


def annotate(level: str, message: str) -> str:
    """A line GitHub shows as an annotation; plain text when run locally."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return f"::{level}::{message}"
    return f"{level.upper()}: {message}"
