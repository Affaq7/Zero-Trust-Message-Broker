"""Mock-services settings, read from the environment.

MOCKS_RUNTIME_DIR: working copies (SQLite file, file store); reset on /reset.
LOG_DIR:           where the ground-truth log mocks.jsonl is written.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME_DIR = REPO_ROOT / "runtime" / "mocks"
DEFAULT_LOG_DIR = REPO_ROOT / "logs"


@dataclass(frozen=True)
class MockSettings:
    runtime_dir: Path = DEFAULT_RUNTIME_DIR
    log_dir: Path = DEFAULT_LOG_DIR

    @property
    def db_path(self) -> Path:
        return self.runtime_dir / "company.sqlite"

    @property
    def ground_truth_path(self) -> Path:
        return self.log_dir / "mocks.jsonl"


def load_mock_settings(environ: Mapping[str, str] = os.environ) -> MockSettings:
    runtime = environ.get("MOCKS_RUNTIME_DIR", "").strip()
    log_dir = environ.get("LOG_DIR", "").strip()
    return MockSettings(
        runtime_dir=Path(runtime) if runtime else DEFAULT_RUNTIME_DIR,
        log_dir=Path(log_dir) if log_dir else DEFAULT_LOG_DIR,
    )
