"""Operator settings, read only from the process environment.

MODE is set by the operator (env var / Docker Compose), never by a message.
An invalid or missing setting raises ConfigError, so the wrapper fails at
startup instead of running in an unknown mode.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args

Mode = Literal["direct", "broker"]

DEFAULT_LOG_DIR = Path(__file__).resolve().parents[1] / "logs"


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    mode: Mode
    agent_name: str
    log_dir: Path = DEFAULT_LOG_DIR


def load_settings(environ: Mapping[str, str] = os.environ) -> Settings:
    mode = environ.get("MODE", "").strip()
    if mode not in get_args(Mode):
        raise ConfigError(f"MODE must be one of {get_args(Mode)}, got {mode!r}")
    agent_name = environ.get("AGENT_NAME", "").strip()
    if not agent_name:
        raise ConfigError("AGENT_NAME is not set")
    log_dir = environ.get("LOG_DIR", "").strip()
    return Settings(mode=mode, agent_name=agent_name,
                    log_dir=Path(log_dir) if log_dir else DEFAULT_LOG_DIR)
