"""M2 step 5: one venv with the agent frameworks, pinned by constraints.txt."""

import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pydantic

REPO_ROOT = Path(__file__).resolve().parents[1]


def pins():
    out = {}
    for line in (REPO_ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines():
        line = line.split(";")[0].strip()
        if line and not line.startswith("#") and "==" in line:
            name, version = line.split("==", 1)
            out[name.lower().replace("_", "-")] = version.strip()
    return out


def test_installed_versions_match_constraints():
    p = pins()
    for name in ("pydantic", "crewai", "langgraph", "langchain-ollama", "fastapi", "httpx", "pyjwt"):
        assert metadata.version(name) == p[name], name


def test_pydantic_is_the_crewai_compatible_line():
    assert pydantic.VERSION.startswith("2.12.")


def test_frameworks_import_with_telemetry_off():
    code = (
        "import os\n"
        "from agents.telemetry import OFF, disable_telemetry\n"
        "disable_telemetry()\n"
        "import crewai, langgraph.graph, langchain_ollama\n"
        "assert all(os.environ[k] == v for k, v in OFF.items())\n"
        "print('ok')\n"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT,
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip().endswith("ok")
