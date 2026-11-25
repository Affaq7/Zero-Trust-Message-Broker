"""The file store rejects drive letters with 400 on every OS (not 404 on Linux)."""

from pathlib import Path

import pytest

from mocks.files import FileStoreError, resolve


@pytest.mark.parametrize("resource", [
    "file:/C:/Windows/win.ini", "file:/c:/x.txt", "file:/internal/D:/x.txt", "file:/Z:",
])
def test_drive_letters_are_rejected(tmp_path: Path, resource):
    with pytest.raises(FileStoreError) as exc:
        resolve(tmp_path, resource)
    assert getattr(exc.value, "status", 400) == 400


@pytest.mark.parametrize("resource", ["file:/internal/q3_report.txt", "file:/internal/notes:v2.txt"])
def test_normal_paths_still_resolve(tmp_path: Path, resource):
    virtual, real = resolve(tmp_path, resource)
    assert virtual == resource[len("file:"):] and tmp_path.resolve() in real.parents
