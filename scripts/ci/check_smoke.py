"""CI helper for 'direct-mode-smoke' (standard library only).

Reads the results.csv a runner run wrote and asserts one boolean column is true in
every row.  Usage:  python scripts/ci/check_smoke.py RESULTS_DIR SCENARIO COLUMN
RESULTS_DIR is the --results-dir given to the runner; it must hold exactly one run.
Exit codes: 0 pass, 1 assertion failed, 2 no usable results.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path


def check(results_dir: Path, scenario: str, column: str) -> tuple[int, str]:
    files = sorted(Path(results_dir).glob("*/results.csv"))
    if len(files) != 1:
        return 2, f"expected one results.csv under {results_dir}, found {len(files)}"
    with files[0].open(newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r.get("scenario_id", "").upper() == scenario.upper()]
    if not rows:
        return 2, f"no {scenario} rows in {files[0]}"
    if column not in rows[0]:
        return 2, f"results.csv has no column {column!r}"
    bad = [r for r in rows if r[column] != "true"]
    if bad:
        statuses = ", ".join(f"rep {r.get('rep')}: {column}={r[column] or 'empty'} status={r.get('status')}"
                             for r in bad)
        return 1, f"{scenario}: {column} is not true ({statuses})"
    return 0, f"{scenario}: {column} is true in {len(rows)} row(s)"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        print(__doc__)
        return 2
    code, message = check(Path(argv[0]), argv[1], argv[2])
    print(("OK: " if code == 0 else "FAILED: ") + message)
    return code


if __name__ == "__main__":
    sys.exit(main())
