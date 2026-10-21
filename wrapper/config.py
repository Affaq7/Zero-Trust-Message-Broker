"""Operator settings, read only from the process environment.

MODE and AGENT_URLS are set by the operator (env var / Docker Compose), never
by a message. An invalid or missing setting raises ConfigError, so the
wrapper fails at startup instead of running in an unknown mode.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, get_args
from urllib.parse import urlsplit

Mode = Literal["direct", "broker"]

DEFAULT_LOG_DIR = Path(__file__).resolve().parents[1] / "logs"


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    mode: Mode
    agent_name: str
    log_dir: Path = DEFAULT_LOG_DIR
    # Base URL of every agent's wrapper, used by send_message() in direct mode.
    agent_urls: dict[str, str] = field(default_factory=dict)
    # Which agent code runs under AGENT_NAME (default: the same name). The
    # runner sets AGENT_IMPL=malicious to start an impostor under a victim's name.
    agent_impl: str | None = None
    # Role claimed in this process's stub tokens. Default: AGENT_NAME when it
    # is a catalog role; required otherwise (e.g. for "malicious", Q2).
    agent_role: str | None = None

    @property
    def impl(self) -> str:
        return self.agent_impl or self.agent_name


def parse_agent_urls(value: str) -> dict[str, str]:
    """Parse AGENT_URLS, e.g. "dummy=http://127.0.0.1:8001,tool=http://127.0.0.1:8004"."""
    urls: dict[str, str] = {}
    for entry in filter(None, (part.strip() for part in value.split(","))):
        name, sep, url = (s.strip() for s in entry.partition("="))
        if not sep or not name or not url:
            raise ConfigError(f"AGENT_URLS entry {entry!r} must look like name=http://host:port")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ConfigError(f"AGENT_URLS: {name!r} needs an http(s) URL, got {url!r}")
        if name in urls:
            raise ConfigError(f"AGENT_URLS: {name!r} is listed twice")
        urls[name] = url.rstrip("/")
    return urls


def load_settings(environ: Mapping[str, str] = os.environ) -> Settings:
    mode = environ.get("MODE", "").strip()
    if mode not in get_args(Mode):
        raise ConfigError(f"MODE must be one of {get_args(Mode)}, got {mode!r}")
    agent_name = environ.get("AGENT_NAME", "").strip()
    if not agent_name:
        raise ConfigError("AGENT_NAME is not set")
    log_dir = environ.get("LOG_DIR", "").strip()
    return Settings(mode=mode, agent_name=agent_name,
                    log_dir=Path(log_dir) if log_dir else DEFAULT_LOG_DIR,
                    agent_urls=parse_agent_urls(environ.get("AGENT_URLS", "")),
                    agent_impl=environ.get("AGENT_IMPL", "").strip() or None,
                    agent_role=environ.get("AGENT_ROLE", "").strip() or None)
