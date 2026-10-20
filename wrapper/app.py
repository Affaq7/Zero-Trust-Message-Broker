"""FastAPI app: POST /message and GET /health.

MODE=direct provides NO security (it is the baseline). It only parses the
envelope and checks receiver == AGENT_NAME. It does not validate payloads,
does not look at the Authorization header, and does not apply the catalog,
RBAC, default-deny or rule_violations(). Those are the broker's job.
"""

import json
import logging

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from contracts import Envelope, make_response
from contracts.payloads import ResponsePayload
from wrapper.config import Settings
from wrapper.registry import get_agent

log = logging.getLogger(__name__)


def _error(status: int, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message, **extra})


def create_app(settings: Settings) -> FastAPI:
    agent = get_agent(settings.agent_name)  # unknown agent fails at startup
    app = FastAPI(title=f"agent wrapper ({settings.agent_name})")

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

        if env.receiver != settings.agent_name:
            return _error(400, f"receiver {env.receiver!r} is not this agent")
        if env.msg_type != "request":
            return _error(400, "POST /message accepts requests only")

        try:
            payload = await run_in_threadpool(agent, env)
        except Exception:
            log.exception("agent %s failed on msg %s", settings.agent_name, env.msg_id)
            payload = ResponsePayload(status="error", error="agent failed")

        return make_response(env, payload).model_dump(mode="json")

    return app
