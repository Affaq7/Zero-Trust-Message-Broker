"""Per-action payload schemas and the generic response payload.

PROVISIONAL: every field below is a PROPOSAL (docs/open-questions.md Q5),
owner to confirm. `resource` in the envelope says WHAT is touched (db:sales,
a file path, a URL); the payload only carries the parameters.

These schemas are for the BROKER. Direct mode never validates payloads.
"""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contracts.catalog import get_catalog

Name = Annotated[str, Field(min_length=1, max_length=64)]
FilterValue = str | int | float | bool | None
Filters = dict[Name, FilterValue]
EmailAddress = Annotated[str, Field(pattern=r"^[^@\s]+@[^@\s]+$", max_length=254)]


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- db.* (resource: "db:<table>") -------------------------------------------

class QueryAggregatePayload(Payload):
    metric: Literal["count", "sum", "avg", "min", "max"]
    column: Name | None = None  # required unless metric == "count"
    group_by: list[Name] = []
    filters: Filters = {}

    @model_validator(mode="after")
    def _column_needed(self) -> "QueryAggregatePayload":
        if self.metric != "count" and self.column is None:
            raise ValueError(f"metric {self.metric!r} needs a column")
        return self


class QueryRowsPayload(Payload):
    columns: list[Name] = Field(min_length=1)
    filters: Filters = {}
    limit: int = Field(default=100, ge=1, le=1000)


class UpdateRecordsPayload(Payload):
    # An empty filter (= update every row) is allowed on purpose: whether it
    # is acceptable is a policy decision for the broker, not a schema rule.
    filters: Filters
    updates: dict[Name, FilterValue] = Field(min_length=1)


# --- file.* (resource: "file:<path>") ----------------------------------------

class ReadInternalFilePayload(Payload):
    max_bytes: int = Field(default=65536, ge=1, le=1_000_000)


class DeleteFilePayload(Payload):
    reason: str | None = Field(default=None, max_length=500)


# --- web.* (resource: the URL) -----------------------------------------------

class FetchPagePayload(Payload):
    max_chars: int = Field(default=20000, ge=1, le=200_000)


# --- tool.send_email_* (resource: proposal "email:internal"/"email:external") -

class EmailPayload(Payload):
    to: list[EmailAddress] = Field(min_length=1, max_length=20)
    subject: str = Field(max_length=200)
    body: str = Field(max_length=20000)


class SendEmailInternalPayload(EmailPayload):
    pass


class SendEmailExternalPayload(EmailPayload):
    pass


# --- admin.* (Prohibited; schema exists so attack messages are well-formed) --

class ChangePolicyPayload(Payload):
    policy_id: Name
    changes: dict[Name, Any] = Field(min_length=1)


ACTION_SCHEMAS: dict[str, type[Payload]] = {
    "db.query_aggregate": QueryAggregatePayload,
    "db.query_rows": QueryRowsPayload,
    "db.update_records": UpdateRecordsPayload,
    "file.read_internal": ReadInternalFilePayload,
    "file.delete": DeleteFilePayload,
    "web.fetch_page": FetchPagePayload,
    "tool.send_email_internal": SendEmailInternalPayload,
    "tool.send_email_external": SendEmailExternalPayload,
    "admin.change_policy": ChangePolicyPayload,
}


class UnknownActionError(ValueError):
    """The action is not in the catalog (default-deny)."""


def validate_payload(action: str, payload: dict[str, Any]) -> Payload:
    """Validate a request payload against its action's schema.

    Raises UnknownActionError for actions outside the catalog and
    pydantic.ValidationError for a payload that does not fit.
    """
    if action not in get_catalog().names() or action not in ACTION_SCHEMAS:
        raise UnknownActionError(action)
    return ACTION_SCHEMAS[action].model_validate(payload)


# --- generic response payload (all actions) ----------------------------------

class ResponsePayload(Payload):
    """{status, result, error}. Denials use the broker's own fields
    (decision, reason_code) on the envelope, not this payload."""

    status: Literal["ok", "error"]
    result: Any = None
    error: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _error_matches_status(self) -> "ResponsePayload":
        if self.status == "error" and not self.error:
            raise ValueError("status 'error' needs an error message")
        if self.status == "ok" and self.error is not None:
            raise ValueError("status 'ok' must not carry an error")
        return self
