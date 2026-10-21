"""Dummy agent: ignores the request and returns fixed text."""

from agents.base import TaskContext, TaskResult
from contracts import Envelope
from contracts.payloads import ResponsePayload

FIXED_TEXT = "Hello from the dummy agent."


def handle(env: Envelope) -> ResponsePayload:
    return ResponsePayload(status="ok", result={"text": FIXED_TEXT})


def run_task(ctx: TaskContext) -> TaskResult:
    return TaskResult(status="ok", answer=FIXED_TEXT)
