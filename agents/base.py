"""The interfaces every agent implements.

- Message handler (AgentFn): gets a parsed request envelope, returns the
  response payload; the wrapper builds the response with make_response().
- Task handler (TaskFn, optional): gets a task from POST /task, the runner's
  stand-in for the human user, and returns the final answer.

Agents are plain (blocking) functions; the wrapper runs them in a worker
thread. Agent code gets its identity and tokens from wrapper.runtime.
"""

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from contracts import Envelope
from contracts.payloads import ResponsePayload

AgentFn = Callable[[Envelope], ResponsePayload]


class TaskContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    task: str
    trace_id: str
    chain_so_far: list[str] = Field(default_factory=lambda: ["user"])


class TaskResult(BaseModel):
    status: Literal["ok", "error"]
    answer: str | None = None
    error: str | None = None


TaskFn = Callable[[TaskContext], TaskResult]
