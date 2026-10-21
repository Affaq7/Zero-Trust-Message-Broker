"""Mock-services FastAPI app: GET /health, POST /reset, GET /ground-truth.

The app resets its world at startup, so every run starts from the seed.
"""

from typing import Annotated

from fastapi import FastAPI, Header, Query

from mocks.config import MockSettings
from mocks.ground_truth import GroundTruthLog
from mocks.seed import build_database

TraceHeader = Annotated[str | None, Header(alias="X-Trace-Id", max_length=128)]


class MockWorld:
    """Holds the mock state and knows how to reset it to the seed."""

    def __init__(self, settings: MockSettings):
        self.settings = settings
        self.truth = GroundTruthLog(settings.ground_truth_path)

    def reset(self, trace_id: str | None = None) -> None:
        build_database(self.settings.db_path)
        self.truth.append("reset", trace_id, {})


def create_app(settings: MockSettings) -> FastAPI:
    world = MockWorld(settings)
    world.reset()
    app = FastAPI(title="mock services")
    app.state.world = world

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "mocks"}

    @app.post("/reset")
    def reset(trace_id: TraceHeader = None):
        world.reset(trace_id)
        return {"status": "ok"}

    @app.get("/ground-truth")
    def ground_truth(
        trace_id: str | None = None,
        kind: str | None = None,
        since: Annotated[str | None, Query(description="ISO 8601 UTC")] = None,
        until: Annotated[str | None, Query(description="ISO 8601 UTC")] = None,
    ):
        return {"records": world.truth.read(trace_id=trace_id, kind=kind,
                                            since=since, until=until)}

    return app
