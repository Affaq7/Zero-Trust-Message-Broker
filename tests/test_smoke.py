"""Step 0 smoke test: the test run uses the project's .venv on Python 3.11/3.12."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_python_version_is_supported():
    assert sys.version_info[:2] in {(3, 11), (3, 12)}


def test_running_inside_project_venv():
    assert Path(sys.prefix).resolve() == (REPO_ROOT / ".venv").resolve()


def test_core_dependencies_importable():
    import dotenv, fastapi, httpx, jwt, pydantic, uvicorn, yaml  # noqa: F401

    assert pydantic.VERSION.startswith("2.")
