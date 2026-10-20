"""Maps AGENT_NAME to the agent function the wrapper runs."""

from agents import dummy
from agents.base import AgentFn
from wrapper.config import ConfigError

AGENTS: dict[str, AgentFn] = {
    "dummy": dummy.handle,
}


def get_agent(name: str) -> AgentFn:
    try:
        return AGENTS[name]
    except KeyError:
        raise ConfigError(f"unknown AGENT_NAME {name!r}; known: {sorted(AGENTS)}") from None
