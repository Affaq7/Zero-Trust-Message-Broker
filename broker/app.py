"""The broker's HTTP application (F1).

    POST /message        an agent's request; always HTTP 200 with a response envelope
                         (a refusal is decision DENY / QUARANTINE / HITL, never a 5xx)
    GET  /health         status, which functions are real or stubs, startup state
    GET  /api/state      counters, agents (T, state, epoch), pending approvals
    GET  /api/events     recent decisions and defence events (newest first)
    POST /admin/release  {"agent", "reviewer"}; header X-Admin-Token required
    POST /admin/approve  {"approval_id", "by"?}: forward a HITL request (steps 8 and 9)
    POST /admin/reject   {"approval_id", "by"?}: close a HITL request as HITL_REJECTED

Admin routes need the header X-Admin-Token equal to BROKER_ADMIN_TOKEN (compared in
constant time). If BROKER_ADMIN_TOKEN is not set, every admin call is refused (fail
closed). Release answers 200, 400 (unknown agent, agent not quarantined, bad body),
401 (missing or wrong token), 403 (reviewer not allowed, or admin disabled); never 500.

Start (from the repo root):  python -m uvicorn broker.app:app --port 8100
Headers, tokens and payloads are never logged. State is in memory only.
"""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import Mapping

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from broker.pipeline import Broker, UnknownAgentError, UnknownApprovalError

ADMIN_HEADER = "X-Admin-Token"
# The largest /message body the broker reads. Larger bodies get a DENY envelope with
# PAYLOAD_TOO_LARGE without being read further (step 1 also caps the payload at 64 KB).
MAX_BODY_BYTES = 256 * 1024
ADMIN_ENV_VAR = "BROKER_ADMIN_TOKEN"


class ApprovalRequest(BaseModel):
    """Body of /admin/approve and /admin/reject. ``by`` names the approver for the audit log."""

    approval_id: str = Field(min_length=1, max_length=128)
    by: str = Field(default="admin", min_length=1, max_length=128)


class ReleaseRequest(BaseModel):
    agent: str = Field(min_length=1, max_length=128)
    reviewer: str = Field(min_length=1, max_length=128)


async def _read_limited(request: Request, limit: int) -> bytes | None:
    """The request body, or None as soon as it is known to be over ``limit`` bytes."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return None
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def create_app(broker: Broker | None = None, environ: Mapping[str, str] = os.environ,
               start: bool = True) -> FastAPI:
    broker = broker or Broker(environ=environ)
    if start and not broker.startup["started"]:
        broker.start()                                   # raises BrokerStartupError with a fix
    admin_token = environ.get(ADMIN_ENV_VAR, "")
    app = FastAPI(title="Zero Trust Message Broker", version="0.1.0")
    app.state.broker = broker

    def admin_refusal(request: Request, route: str) -> JSONResponse | None:
        """None when the caller may use an admin route; otherwise the refusal (and an event)."""
        if not admin_token:
            broker.admin_event("admin_refused", route=route, outcome="403 admin disabled: "
                               f"{ADMIN_ENV_VAR} not set")
            return _error(403, f"admin routes are disabled: {ADMIN_ENV_VAR} is not set")
        given = request.headers.get(ADMIN_HEADER, "")
        if not hmac.compare_digest(given.encode("utf-8"), admin_token.encode("utf-8")):
            broker.admin_event("admin_refused", route=route,
                               outcome="401 missing admin token" if not given else "401 wrong admin token")
            return _error(401, f"missing or wrong {ADMIN_HEADER}")
        return None

    @app.post("/message")
    async def message(request: Request) -> JSONResponse:
        # The raw body is read by hand so that FastAPI never rejects it with a 422:
        # anything that is not a JSON object still gets a DENY envelope (MALFORMED_JSON).
        body = await _read_limited(request, MAX_BODY_BYTES)
        if body is None:
            env = await run_in_threadpool(broker.refuse_unread, "PAYLOAD_TOO_LARGE")
            return JSONResponse(env.model_dump(mode="json"), status_code=200)
        try:
            raw = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raw = None
        # The pipeline blocks while forwarding, so it runs in the thread pool.
        env = await run_in_threadpool(broker.handle, raw, dict(request.headers))
        return JSONResponse(env.model_dump(mode="json"), status_code=200)

    @app.get("/health")
    def health() -> dict:
        return {**broker.health(), "admin": "enabled" if admin_token else "disabled"}

    @app.get("/api/state")
    def state() -> dict:
        return broker.state()

    @app.get("/api/events")
    def events(limit: int = Query(100, ge=1, le=1000)) -> dict:
        return {"events": broker.recent_events(limit)}

    @app.post("/admin/release")
    async def release(request: Request) -> JSONResponse:
        refusal = admin_refusal(request, "/admin/release")
        if refusal is not None:
            return refusal
        try:
            req = ReleaseRequest.model_validate_json(await request.body())
        except ValidationError:
            broker.admin_event("release_refused", outcome="400 bad body")
            return _error(400, 'body must be {"agent": "...", "reviewer": "..."}')
        try:
            result = await run_in_threadpool(broker.release, req.agent, req.reviewer)
        except PermissionError:
            broker.admin_event("release_refused", agent=req.agent, by=req.reviewer,
                               outcome="403 reviewer not allowed")
            return _error(403, f"reviewer {req.reviewer!r} may not release agents")
        except UnknownAgentError:
            broker.admin_event("release_refused", agent=req.agent, by=req.reviewer,
                               outcome="400 unknown agent")
            return _error(400, f"unknown agent {req.agent!r}")
        except ValueError as exc:
            broker.admin_event("release_refused", agent=req.agent, by=req.reviewer,
                               outcome="400 not released")
            return _error(400, str(exc))
        except Exception as exc:  # noqa: BLE001 - never a 500 from an admin route
            broker.admin_event("release_refused", agent=req.agent, by=req.reviewer,
                               outcome=f"400 {type(exc).__name__}")
            return _error(400, "release failed")
        return JSONResponse(result, status_code=200)

    async def decide(request: Request, kind: str) -> JSONResponse:
        route = f"/admin/{kind}"
        refusal = admin_refusal(request, route)
        if refusal is not None:
            return refusal
        try:
            req = ApprovalRequest.model_validate_json(await request.body())
        except ValidationError:
            broker.admin_event(f"{kind}_refused", outcome="400 bad body")
            return _error(400, 'body must be {"approval_id": "..."} (optional "by")')
        act = broker.approve if kind == "approve" else broker.reject
        try:
            result = await run_in_threadpool(act, req.approval_id, req.by)
        except UnknownApprovalError:
            broker.admin_event(f"{kind}_refused", approval_id=req.approval_id, by=req.by,
                               outcome="400 no open approval with this id")
            return _error(400, f"no open approval {req.approval_id!r}")
        except Exception as exc:  # noqa: BLE001 - never a 500 from an admin route
            broker.admin_event(f"{kind}_refused", approval_id=req.approval_id, by=req.by,
                               outcome=f"400 {type(exc).__name__}")
            return _error(400, f"{kind} failed")
        return JSONResponse(result, status_code=200)

    @app.post("/admin/approve")
    async def approve(request: Request) -> JSONResponse:
        return await decide(request, "approve")

    @app.post("/admin/reject")
    async def reject(request: Request) -> JSONResponse:
        return await decide(request, "reject")

    return app


app = create_app()
