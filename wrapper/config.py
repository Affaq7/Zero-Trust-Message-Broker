"""Operator settings, read only from the process environment.

MODE is set by the operator (env var / Docker Compose), never by a message.
An invalid or missing setting raises ConfigError, so the wrapper fails at
startup instead of running in an unknown mode.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, get_args

Mode = Literal["direct", "broker"]


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    mode: Mode
    agent_name: str


def load_settings(environ: Mapping[str, str] = os.environ) -> Settings:
    mode = environ.get("MODE", "").strip()
    if mode not in get_args(Mode):
        raise ConfigError(f"MODE must be one of {get_args(Mode)}, got {mode!r}")
    agent_name = environ.get("AGENT_NAME", "").strip()
    if not agent_name:
        raise ConfigError("AGENT_NAME is not set")
    return Settings(mode=mode, agent_name=agent_name)
