"""Maps the agent implementation name (AGENT_IMPL, default AGENT_NAME) to its code."""

from collections.abc import Callable

from agents import database, dummy, mailer, malicious, planner, research, tool
from agents.base import AgentFn, TaskFn
from wrapper.config import ConfigError

# Message handlers (POST /message).
AGENTS: dict[str, AgentFn] = {
    "dummy": dummy.handle,
    "tool": tool.handle,
    "database": database.handle,
    "planner": planner.handle,
    "mailer": mailer.handle,
    "research": research.handle,
    # Compromised-responder test double; runs under a victim's name (AGENT_NAME=database or tool).
    "malicious": malicious.handle,
}

# Task handlers (POST /task), only for agents that can start work for the user.
TASKS: dict[str, TaskFn] = {
    "dummy": dummy.run_task,
    "planner": planner.run_task,
}


# Start-up hooks: heavy imports an agent would otherwise pay for inside its first task.
PRELOADS: dict[str, Callable[[], None]] = {
    "tool": tool.preload,
    "database": database.preload,
    "malicious": malicious.preload,
}


def preload_agent(name: str) -> None:
    hook = PRELOADS.get(name)
    if hook:
        hook()


def get_agent(name: str) -> AgentFn:
    try:
        return AGENTS[name]
    except KeyError:
        raise ConfigError(f"unknown agent implementation {name!r}; known: {sorted(AGENTS)}") from None


def get_task_handler(name: str) -> TaskFn | None:
    return TASKS.get(name)
