"""Mock-services FastAPI app.

GET /health, POST /reset, GET /ground-truth, and the services:
POST /db/query_aggregate, /db/query_rows, /db/update_records,
POST /files/read, /files/delete, POST /web/fetch, POST /mail/send,
POST /admin/policy and GET /admin/policies.

Service requests carry the envelope's ``resource`` and ``payload``; the
payload must fit contracts/payloads.py. The caller's X-Trace-Id header ties
ground-truth records to a run. The app resets its world at startup.
"""

import json
from typing import Annotated, Any

from fastapi import FastAPI, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError

from contracts.payloads import (
    ChangePolicyPayload,
    DeleteFilePayload,
    SendEmailExternalPayload,
    SendEmailInternalPayload,
    FetchPagePayload,
    MailDeliverPayload,
    QueryAggregatePayload,
    QueryRowsPayload,
    ReadInternalFilePayload,
    UpdateRecordsPayload,
)
from mocks import db, files, mail, web
from mocks.config import MockSettings
from mocks.ground_truth import GroundTruthLog
from mocks.seed import build_database

TraceHeader = Annotated[str | None, Header(alias="X-Trace-Id", max_length=128)]

MAIL_SCHEMAS = {"email:internal": SendEmailInternalPayload, "email:external": SendEmailExternalPayload,
                "mail:outbound": MailDeliverPayload}


class ServiceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource: str
    payload: dict[str, Any] = {}


def _error(status: int, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message, **extra})


def _invalid(exc: ValidationError) -> JSONResponse:
    details = json.loads(exc.json(include_url=False, include_input=False))
    return _error(422, "invalid payload", details=details)


class MockWorld:
    """Holds the mock state and knows how to reset it to the seed."""

    def __init__(self, settings: MockSettings):
        self.settings = settings
        self.truth = GroundTruthLog(settings.ground_truth_path)
        self.policies: dict[str, dict[str, Any]] = {}

    def reset(self, trace_id: str | None = None) -> None:
        build_database(self.settings.db_path)
        files.reset_files(self.settings.files_dir)
        self.policies.clear()
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

    # --- database ---------------------------------------------------------

    def _db_read(action, schema, run, req: ServiceRequest, trace_id):
        try:
            payload = schema.model_validate(req.payload)
            table = db.table_from_resource(req.resource)
            result = run(world.settings.db_path, table, payload)
        except ValidationError as exc:
            return _invalid(exc)
        except db.DbError as exc:
            return _error(exc.status, str(exc))
        columns = sorted({c for row in result["rows"] for c in row})
        world.truth.append("db.query", trace_id, {
            "action": action, "table": table, "columns": columns,
            "filters": payload.filters, "row_count": len(result["rows"]),
            "sensitive_columns": [] if action == "db.query_aggregate"
            else db.sensitive_in(table, columns),
        })
        return result

    @app.post("/db/query_aggregate")
    def query_aggregate(req: ServiceRequest, trace_id: TraceHeader = None):
        return _db_read("db.query_aggregate", QueryAggregatePayload, db.query_aggregate, req, trace_id)

    @app.post("/db/query_rows")
    def query_rows(req: ServiceRequest, trace_id: TraceHeader = None):
        return _db_read("db.query_rows", QueryRowsPayload, db.query_rows, req, trace_id)

    @app.post("/db/update_records")
    def update_records(req: ServiceRequest, trace_id: TraceHeader = None):
        try:
            payload = UpdateRecordsPayload.model_validate(req.payload)
            table = db.table_from_resource(req.resource)
            result, details = db.update_records(world.settings.db_path, table, payload)
        except ValidationError as exc:
            return _invalid(exc)
        except db.DbError as exc:
            return _error(exc.status, str(exc))
        world.truth.append("db.write", trace_id, details)
        return result

    # --- files ------------------------------------------------------------

    @app.post("/files/read")
    def read_file(req: ServiceRequest, trace_id: TraceHeader = None):
        try:
            payload = ReadInternalFilePayload.model_validate(req.payload)
            result = files.read_file(world.settings.files_dir, req.resource, payload.max_bytes)
        except ValidationError as exc:
            return _invalid(exc)
        except files.FileStoreError as exc:
            return _error(exc.status, str(exc))
        world.truth.append("file.read", trace_id, {
            "path": result["path"], "bytes_returned": len(result["content"].encode("utf-8")),
            "truncated": result["truncated"]})
        return result

    @app.post("/files/delete")
    def delete_file(req: ServiceRequest, trace_id: TraceHeader = None):
        try:
            payload = DeleteFilePayload.model_validate(req.payload)
            result = files.delete_file(world.settings.files_dir, req.resource)
        except ValidationError as exc:
            return _invalid(exc)
        except files.FileStoreError as exc:
            return _error(exc.status, str(exc))
        world.truth.append("file.delete", trace_id, {"path": result["path"], "reason": payload.reason})
        return result

    # --- web --------------------------------------------------------------

    @app.post("/web/fetch")
    def fetch_page(req: ServiceRequest, trace_id: TraceHeader = None):
        try:
            payload = FetchPagePayload.model_validate(req.payload)
            result = web.fetch(req.resource, payload.max_chars)
        except ValidationError as exc:
            return _invalid(exc)
        except web.WebError as exc:
            if exc.status == 404:
                world.truth.append("web.fetch", trace_id, {"url": req.resource, "found": False})
            return _error(exc.status, str(exc))
        world.truth.append("web.fetch", trace_id, {
            "url": result["url"], "found": True, "chars": len(result["content"])})
        return result

    # --- mail -------------------------------------------------------------

    @app.post("/mail/send")
    def send_mail(req: ServiceRequest, trace_id: TraceHeader = None):
        p = req.payload

        def failed(error: str) -> None:
            world.truth.append("mail.attempt", trace_id, mail.attempt_record(
                req.resource, p.get("to"), p.get("subject"), p.get("body"), status="failed", error=error,
                cc=p.get("cc"), bcc=p.get("bcc")))

        try:
            mail.kind_from_resource(req.resource)
            # Same schema the contract defines for the action behind this resource,
            # so e.g. an external email may carry a justification and an internal one may not.
            payload = MAIL_SCHEMAS[req.resource].model_validate(p)
        except ValidationError as exc:
            failed("invalid payload")
            return _invalid(exc)
        except mail.MailError as exc:
            failed(str(exc))
            return _error(exc.status, str(exc))
        world.truth.append("mail.attempt", trace_id, mail.attempt_record(
            req.resource, payload.to, payload.subject, payload.body, status="delivered",
            cc=payload.cc, bcc=payload.bcc))
        return {"status": "delivered", "to": payload.to}

    # --- admin ------------------------------------------------------------

    @app.post("/admin/policy")
    def change_policy(req: ServiceRequest, trace_id: TraceHeader = None):
        # The attempt is recorded first (outcome "pending"), then updated to
        # "applied" or "rejected"; a crash in between leaves "pending".
        p = req.payload
        attempt = world.truth.append("admin.policy_change", trace_id, {
            "resource": req.resource,
            "policy_id": p.get("policy_id") if isinstance(p.get("policy_id"), str) else None,
            "changes": p.get("changes") if isinstance(p.get("changes"), dict) else None,
            "outcome": "pending", "error": None})
        try:
            payload = ChangePolicyPayload.model_validate(p)
        except ValidationError as exc:
            world.truth.update(attempt["id"], {"outcome": "rejected", "error": "invalid payload"})
            return _invalid(exc)
        world.policies.setdefault(payload.policy_id, {}).update(payload.changes)
        world.truth.update(attempt["id"], {"outcome": "applied"})
        return {"status": "applied", "policy_id": payload.policy_id}

    @app.get("/admin/policies")
    def policies():
        return {"policies": world.policies}

    return app
