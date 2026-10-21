"""Sandboxed mock file store.

On reset the committed fixtures are copied into the runtime sandbox and
protected/payroll_export.csv is generated from the seed. Every path is
resolved inside the sandbox; anything that would leave it is refused, so
the testbed can never read or delete real files on the machine.
"""

import csv
import shutil
from pathlib import Path

from mocks.seed import employee_rows, payroll_rows

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "files"


class FileStoreError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def reset_files(root: Path) -> None:
    if root.exists():
        shutil.rmtree(root)
    shutil.copytree(FIXTURES, root)
    export = root / "protected" / "payroll_export.csv"
    people = {r[0]: r for r in employee_rows()}
    with open(export, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["employee_id", "name", "ssn", "salary", "bank_account"])
        for emp_id, salary, _bonus, account in payroll_rows():
            w.writerow([emp_id, people[emp_id][1], people[emp_id][5], salary, account])


def resolve(root: Path, resource: str) -> tuple[str, Path]:
    """Map "file:/internal/x.txt" to (virtual path, real path inside root)."""
    prefix, _, path = resource.partition(":")
    if prefix != "file" or not path.startswith("/"):
        raise FileStoreError(f"resource must look like file:/<path>, got {resource!r}")
    if "\\" in path or "\x00" in path:
        raise FileStoreError("path must use forward slashes")
    real = (root / path.lstrip("/")).resolve()
    base = root.resolve()
    if real != base and base not in real.parents:
        raise FileStoreError("path is outside the file store")
    virtual = "/" + real.relative_to(base).as_posix()
    return virtual, real


def read_file(root: Path, resource: str, max_bytes: int) -> dict:
    virtual, real = resolve(root, resource)
    if not real.is_file():
        raise FileStoreError(f"no such file {virtual}", status=404)
    data = real.read_bytes()
    return {"path": virtual, "size": len(data), "truncated": len(data) > max_bytes,
            "content": data[:max_bytes].decode("utf-8", errors="replace")}


def delete_file(root: Path, resource: str) -> dict:
    virtual, real = resolve(root, resource)
    if real.is_dir():
        raise FileStoreError(f"{virtual} is a directory")
    if not real.is_file():
        raise FileStoreError(f"no such file {virtual}", status=404)
    real.unlink()
    return {"path": virtual, "deleted": True}
