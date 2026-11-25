"""CI check 'secrets-and-forbidden-files' (standard library only).

Compares a PR's head with its base and fails if the PR adds or changes a forbidden
file, or if an added line looks like a secret or contains a seeded sensitive value.
Prints only the rule name and file:line, never the matched text.

Local use (from the repo root):  python scripts/ci/check_forbidden.py --base origin/main --head HEAD
Exit codes: 0 clean, 1 findings, 2 the check could not run.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import types
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_common import REPO_ROOT, SetupError, annotate, diff_lines, git, load_event, resolve_range  # noqa: E402

SEED_PATH = "mocks/seed.py"

# --- forbidden paths ------------------------------------------------------------------------

DIR_SEGMENTS = {"keys": "keys/", "logs": "logs/", "results": "results/"}
SUFFIXES = {".pem": "*.pem", ".key": "*.key", ".sqlite": "*.sqlite", ".db": "*.db", ".docx": "*.docx"}


def forbidden_path_rule(path: str) -> str | None:
    """The forbidden-path rule a repo-relative path breaks, or None."""
    p = PurePosixPath(path)
    if p.name.startswith(".env"):
        return "forbidden-file(.env*)"
    for part in p.parts[:-1]:
        if part in DIR_SEGMENTS:
            return f"forbidden-file({DIR_SEGMENTS[part]})"
    if path.startswith("scenarios/source/"):
        return "forbidden-file(scenarios/source/)"
    suffix = p.suffix.lower()
    if suffix in SUFFIXES:
        return f"forbidden-file({SUFFIXES[suffix]})"
    return None


# --- added-line content rules ---------------------------------------------------------------

CONTENT_RULES: list[tuple[str, re.Pattern]] = [
    ("private-key-header", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")),
    ("jwt-shaped-string", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
]

SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b[\w.-]*(?:password|passwd|secret|token|api[_-]?key)[\w.-]*   # the name
    ["']?\s*(?::|=|:=)\s*                                            # = or : (dict / yaml / env)
    (?:[rbuf]{0,2})(["'])(?P<value>[^"'\s]{4,})\1                    # a quoted literal, 4+ chars
    """)

# Quoted values that are obviously not secrets. The repo's tests and scenarios use stub
# tokens and the scripted attacker's token modes (valid / expired / wrong_key / missing, and in
# broker mode stolen / reissued). Only a value that is exactly one of these words is exempt.
PLACEHOLDER_WORDS = re.compile(r"(?i)stub|fake|dummy|example|placeholder|marker")
PLACEHOLDER_VALUES = {"valid", "invalid", "expired", "missing", "wrong_key", "stolen", "reissued",
                      "none", "null", "changeme", "redacted"}
TEMPLATE_SYNTAX = re.compile(r"^(?:\$\{?\w+\}?|<[^>]+>|\{\{.*\}\}|\*{3,}|x{3,}|\.{3,})$", re.I)


def is_placeholder(value: str) -> bool:
    return (value.lower() in PLACEHOLDER_VALUES or bool(PLACEHOLDER_WORDS.search(value))
            or bool(TEMPLATE_SYNTAX.match(value)))


def has_secret_assignment(text: str) -> bool:
    return any(not is_placeholder(m.group("value")) for m in SECRET_ASSIGNMENT.finditer(text))


def seeded_value_pattern(values: list[str]) -> re.Pattern | None:
    values = sorted({v for v in values if v}, key=len, reverse=True)
    if not values:
        return None
    alternation = "|".join(re.escape(v) for v in values)
    return re.compile(rf"(?<![A-Za-z0-9])(?:{alternation})(?![A-Za-z0-9])")


def scan_line(text: str, seeded: re.Pattern | None) -> list[str]:
    hits = [name for name, rx in CONTENT_RULES if rx.search(text)]
    if has_secret_assignment(text):
        hits.append("secret-assignment")
    if seeded is not None and seeded.search(text):
        hits.append("seeded-sensitive-value")
    return hits


# --- the seed generator ---------------------------------------------------------------------

def _module_from_source(source: str, name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    exec(compile(source, f"<{name}>", "exec"), module.__dict__)  # noqa: S102 - trusted repo code
    return module


def load_seeded_values(base: str) -> list[str]:
    """Every value from mocks.seed.sensitive_values(), generated now (never hardcoded).

    Uses the seed generator from the base commit (main, so a PR cannot change what is
    looked for) and from the working tree (so values a PR adds to the seed are caught too).
    """
    modules = []
    try:
        modules.append(_module_from_source(git("show", f"{base}:{SEED_PATH}"), "seed_base"))
    except SetupError:
        pass  # the base has no seed generator; fall back to the working tree
    head_file = REPO_ROOT / SEED_PATH
    if head_file.is_file():
        spec = importlib.util.spec_from_file_location("seed_head", head_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    if not modules:
        raise SetupError(f"cannot load the seed generator ({SEED_PATH})")
    values: list[str] = []
    for module in modules:
        for column_values in module.sensitive_values().values():
            values.extend(str(v) for v in column_values)
    return values


# --- the check ------------------------------------------------------------------------------

def check(changed_paths: list[str], diffs: dict, seeded: re.Pattern | None) -> list[str]:
    """Findings as 'rule: file' or 'rule: file:line' strings (never the matched text)."""
    findings = []
    for path in changed_paths:
        rule = forbidden_path_rule(path)
        if rule:
            findings.append(f"{rule}: {path}")
    for path, fd in diffs.items():
        for line_no, text in fd.added:
            for rule in scan_line(text, seeded):
                findings.append(f"{rule}: {path}:{line_no}")
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", help="base commit (default: PR base, else origin/main)")
    ap.add_argument("--head", help="head commit (default: PR head, else HEAD)")
    args = ap.parse_args(argv)
    try:
        base, head = resolve_range(args.base, args.head, load_event())
        changed = [p for p in git("diff", "--name-only", "--diff-filter=ACMR",
                                  f"{base}...{head}").splitlines() if p]
        diffs = diff_lines(base, head)
        seeded = seeded_value_pattern(load_seeded_values(base))
    except SetupError as exc:
        print(annotate("error", f"check could not run: {exc}"))
        return 2
    print(f"Checked {len(changed)} changed file(s) in {base}...{head}; "
          f"{sum(len(d.added) for d in diffs.values())} added line(s).")
    findings = check(changed, diffs, seeded)
    for f in findings:
        print(annotate("error", f))
    if findings:
        print(f"FAILED: {len(findings)} finding(s). See docs/ci.md for what each rule means.")
        return 1
    print("OK: no forbidden files and no secret-like added lines.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
