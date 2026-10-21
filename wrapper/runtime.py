"""What agent code may know about its own process: name, role, tokens.

The wrapper sets the runtime around every agent call, so agent code can ask
current_runtime() for its identity and a token for a receiver. It holds no
MODE, no scenario labels and no trust scores.
"""

from contextvars import ContextVar
from dataclasses import dataclass, field

from wrapper.credentials import StubCredentials


class NoRoleError(RuntimeError):
    """This process has no role, so it cannot mint a token (set AGENT_ROLE)."""


@dataclass(frozen=True)
class AgentRuntime:
    agent_name: str
    role: str | None
    credentials: StubCredentials | None = field(default=None, compare=False)

    @classmethod
    def create(cls, agent_name: str, role: str | None) -> "AgentRuntime":
        return cls(agent_name, role, StubCredentials(agent_name, role) if role else None)

    def token_for(self, receiver: str) -> str:
        if self.credentials is None:
            raise NoRoleError(f"{self.agent_name!r} has no role; set AGENT_ROLE to send messages")
        return self.credentials.token_for(receiver)


_current: ContextVar[AgentRuntime | None] = ContextVar("agent_runtime", default=None)


def current_runtime() -> AgentRuntime:
    runtime = _current.get()
    if runtime is None:
        raise RuntimeError("no agent runtime: only valid inside an agent call made by the wrapper")
    return runtime


def run_with_runtime(runtime: AgentRuntime, fn, *args):
    """Call fn(*args) with ``runtime`` as the current runtime (used in worker threads)."""
    token = _current.set(runtime)
    try:
        return fn(*args)
    finally:
        _current.reset(token)
