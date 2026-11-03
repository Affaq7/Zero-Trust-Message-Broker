"""FastAPI app: POST /message, POST /task and GET /health.

MODE=direct provides NO security (it is the baseline). It only parses the
envelope and checks receiver == AGENT_NAME. It does not validate payloads,
does not look at the Authorization header, and does not apply the catalog,
RBAC, default-deny or rule_violations(). Those are the broker's job.

POST /task is the runner's stand-in for the human user (decision C1). It is
not an envelope and not part of the catalog. It accepts only the task text
and an optional trace_id; anything else (labels, expected decisions, trust
scores) is rejected.

AGENT_IMPL picks the code that runs under AGENT_NAME, so the runner can start
an impostor under a victim's name (decision M3).
"""

import json
import logging

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agents.base import TaskContext, TaskResult
from contracts import Envelope, make_response
from contracts.catalog import get_catalog
from contracts.envelope import IdStr, new_id
from contracts.payloads import ResponsePayload
from wrapper.config import Settings
from wrapper.message_log import MessageLog
from wrapper.registry import get_agent, get_task_handler, preload_agent
from wrapper.runtime import AgentRuntime, run_with_runtime

log = logging.getLogger(__name__)


class TaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task: str = Field(min_length=1, max_length=4000)
    trace_id: IdStr | None = None


def _error(status: int, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message, **extra})


def _role_for(settings: Settings) -> str | None:
    if settings.agent_role:
        return settings.agent_role
    return settings.agent_name if settings.agent_name in get_catalog().roles else None


def create_app(settings: Settings) -> FastAPI:
    agent = get_agent(settings.impl)  # unknown implementation fails at startup
    task_handler = get_task_handler(settings.impl)
    preload_agent(settings.impl)  # slow imports happen before the server accepts requests
    runtime = AgentRuntime.create(settings.agent_name, _role_for(settings))
    message_log = MessageLog(settings.log_dir, settings.agent_name)
    app = FastAPI(title=f"agent wrapper ({settings.agent_name})")
    app.state.runtime = runtime

    @app.get("/health")
    def health():
        return {"status": "ok", "agent": settings.agent_name, "mode": settings.mode}

    @app.post("/message")
    async def message(request: Request):
        if settings.mode == "broker":
            return _error(501, "MODE=broker is not implemented yet")

        try:
            env = Envelope.model_validate_json(await request.body())
        except ValidationError as exc:
            details = json.loads(exc.json(include_url=False, include_input=False))
            return _error(422, "invalid envelope", details=details)

        # Every parsed envelope is logged, including misdirected ones.
        message_log.append(env, "in")

        if env.receiver != settings.agent_name:
            return _error(400, f"receiver {env.receiver!r} is not this agent")
        if env.msg_type != "request":
            return _error(400, "POST /message accepts requests only")

        try:
            payload = await run_in_threadpool(run_with_runtime, runtime, agent, env, trace_id=env.trace_id)
        except Exception:
            log.exception("agent %s failed on msg %s", settings.agent_name, env.msg_id)
            payload = ResponsePayload(status="error", error="agent failed")

        response = make_response(env, payload)
        message_log.append(response, "out")
        return response.model_dump(mode="json")

    @app.post("/task")
    async def task(request: Request):
        try:
            req = TaskRequest.model_validate_json(await request.body())
        except ValidationError as exc:
            details = json.loads(exc.json(include_url=False, include_input=False))
            return _error(422, "invalid task", details=details)
        if task_handler is None:
            return _error(404, f"agent {settings.agent_name!r} does not accept tasks")

        ctx = TaskContext(task=req.task, trace_id=req.trace_id or new_id())
        try:
            result = await run_in_threadpool(run_with_runtime, runtime, task_handler, ctx,
                                             trace_id=ctx.trace_id)
        except Exception as exc:
            log.exception("agent %s failed on task %s", settings.agent_name, ctx.trace_id)
            result = TaskResult(status="error", error=f"agent failed: {type(exc).__name__}")
        return {"trace_id": ctx.trace_id, **result.model_dump()}

    return app
