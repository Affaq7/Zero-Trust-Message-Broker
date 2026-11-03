"""The database and tool agents import CrewAI at start-up (create_app), not inside their first task."""

import subprocess
import sys

import pytest

from wrapper.registry import PRELOADS, preload_agent

CODE = """
import sys
from pathlib import Path
from wrapper.app import create_app
from wrapper.config import Settings
before = "crewai" in sys.modules
create_app(Settings(mode="direct", agent_name="{name}", log_dir=Path(sys.argv[1])))
print(before, "crewai" in sys.modules)
"""


def test_only_the_crewai_agents_have_a_preload():
    assert set(PRELOADS) == {"database", "tool"}
    preload_agent("planner")  # no hook, no error


@pytest.mark.parametrize("name, expected", [("database", "False True"), ("tool", "False True"),
                                           ("mailer", "False False"), ("planner", "False False")])
def test_create_app_imports_crewai_only_for_database_and_tool(tmp_path, name, expected):
    out = subprocess.run([sys.executable, "-c", CODE.format(name=name), str(tmp_path)],
                         capture_output=True, text=True, timeout=120)
    assert out.stdout.split()[-2:] == expected.split(), out.stderr[-500:]
