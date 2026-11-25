"""The broker's HTTP application (F1).

    POST /message        an agent's request; always HTTP 200 with a response envelope
                         (a refusal is decision DENY / QUARANTINE / HITL, never a 5xx)
    GET  /health         status and which modules are stubs, real, or ignored
    GET  /api/state      counters, agents (T, state, epoch), pending approvals
    GET  /api/events     recent decisions with reason codes (newest first)
    POST /admin/release  {"agent", "reviewer"}: authorised release (trust engine)

Start (from the repo root):  python -m uvicorn broker.app:app --port 8100
Headers, tokens and payloads are never logged. State is in memory only.
"""

from __future__ import annotations

import json

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from broker.pipeline import Broker


class ReleaseRequest(BaseModel):
    agent: str = Field(min_length=1, max_length=128)
    reviewer: str = Field(min_length=1, max_length=128)


def create_app(broker: Broker | None = None) -> FastAPI:
    broker = broker or Broker()
    app = FastAPI(title="Zero Trust Message Broker", version="0.1.0")
    app.state.broker = broker

    @app.post("/message")
    async def message(request: Request) -> JSONResponse:
        # The raw body is read by hand so that FastAPI never rejects it with a 422:
        # anything that is not a JSON object still gets a DENY envelope (MALFORMED_JSON).
        body = await request.body()
        try:
            raw = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raw = None
        # The pipeline blocks while forwarding, so it runs in the thread pool.
        env = await run_in_threadpool(broker.handle, raw, dict(request.headers))
        return JSONResponse(env.model_dump(mode="json"), status_code=200)

    @app.get("/health")
    def health() -> dict:
        return broker.health()

    @app.get("/api/state")
    def state() -> dict:
        return broker.state()

    @app.get("/api/events")
    def events(limit: int = Query(100, ge=1, le=1000)) -> dict:
        return {"events": broker.recent_events(limit)}

    @app.post("/admin/release")
    def release(req: ReleaseRequest) -> dict:
        try:
            return broker.release(req.agent, req.reviewer)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    return app


app = create_app()
