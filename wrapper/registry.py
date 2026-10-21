"""Maps the agent implementation name (AGENT_IMPL, default AGENT_NAME) to its code."""

from agents import database, dummy, tool
from agents.base import AgentFn, TaskFn
from wrapper.config import ConfigError

# Message handlers (POST /message).
AGENTS: dict[str, AgentFn] = {
    "dummy": dummy.handle,
    "tool": tool.handle,
    "database": database.handle,
}

# Task handlers (POST /task), only for agents that can start work for the user.
TASKS: dict[str, TaskFn] = {
    "dummy": dummy.run_task,
}


def get_agent(name: str) -> AgentFn:
    try:
        return AGENTS[name]
    except KeyError:
        raise ConfigError(f"unknown agent implementation {name!r}; known: {sorted(AGENTS)}") from None


def get_task_handler(name: str) -> TaskFn | None:
    return TASKS.get(name)
