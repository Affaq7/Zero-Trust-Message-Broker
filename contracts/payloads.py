"""Per-action payload schemas and the generic response payload.

PROVISIONAL: every field below is a PROPOSAL (docs/open-questions.md Q5),
owner to confirm. `resource` in the envelope says WHAT is touched (db:sales,
a file path, a URL); the payload only carries the parameters.

These schemas are for the BROKER. Direct mode never validates payloads.
"""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from contracts.catalog import get_catalog

Name = Annotated[str, Field(min_length=1, max_length=64)]
FilterValue = str | int | float | bool | None
Filters = dict[Name, FilterValue]


def normalize_address(address: str) -> str:
    """The one way an email address is normalised: strip, then lowercase.

    Every recipient list in this module (to, cc, bcc, in every email payload)
    goes through it, so the broker and the mailer see the same strings.
    Aliases and groups are NOT supported and are never expanded: an address
    is taken literally.
    """
    return address.strip().lower()


def _normalize_if_text(value: Any) -> Any:
    # Non-text input is left alone so the normal type error is reported.
    return normalize_address(value) if isinstance(value, str) else value


# Validation order: normalise first, then check the shape of the result.
EmailAddress = Annotated[str, Field(pattern=r"^[^@\s]+@[^@\s]+$", max_length=254),
                         BeforeValidator(_normalize_if_text)]
Justification = Annotated[str, Field(max_length=500)]


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
    justification: Justification | None = None   # S13: never changes who may call


class UpdateRecordsPayload(Payload):
    # An empty filter (= update every row) is allowed on purpose: whether it
    # is acceptable is a policy decision for the broker, not a schema rule.
    filters: Filters
    updates: dict[Name, FilterValue] = Field(min_length=1)
    justification: Justification | None = None   # S13


# --- file.* (resource: "file:<path>") ----------------------------------------

class ReadInternalFilePayload(Payload):
    max_bytes: int = Field(default=65536, ge=1, le=1_000_000)


class DeleteFilePayload(Payload):
    reason: str | None = Field(default=None, max_length=500)
    justification: Justification | None = None   # S13


# --- web.* (resource: the URL) -----------------------------------------------

class FetchPagePayload(Payload):
    max_chars: int = Field(default=20000, ge=1, le=200_000)


# --- tool.send_email_* (resource: proposal "email:internal"/"email:external") -

class EmailPayload(Payload):
    to: list[EmailAddress] = Field(min_length=1, max_length=20)
    cc: list[EmailAddress] = Field(default=[], max_length=20)     # S14
    bcc: list[EmailAddress] = Field(default=[], max_length=20)    # S14
    subject: str = Field(max_length=200)
    body: str = Field(max_length=20000)


class SendEmailInternalPayload(EmailPayload):
    pass


class SendEmailExternalPayload(EmailPayload):
    justification: Justification | None = None   # S13 (not on the internal action)


# --- research.lookup (resource: "research:query"; S10) -----------------------

Source = Annotated[str, Field(min_length=1, max_length=2048)]   # "file:/..." or a URL


class ResearchLookupPayload(Payload):
    query: str = Field(min_length=1, max_length=500)
    sources: list[Source] = Field(default=[], max_length=5)
    max_sources: int = Field(ge=1, le=3)


# --- planner.request (resource: "planner:request"; S11) ----------------------

class PlannerRequestPayload(Payload):
    request: str = Field(min_length=1, max_length=500)
    suggested_action: str | None = Field(default=None, min_length=1, max_length=100)


# --- mail.deliver (resource: "mail:outbound"; S12) ---------------------------

class MailDeliverPayload(EmailPayload):
    """What the tool agent hands the mailer: the final, normalised recipient
    lists (to, cc, bcc), subject and body. Same shape and limits as the
    email actions, as a separate class so the two can change independently."""


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
    "research.lookup": ResearchLookupPayload,
    "planner.request": PlannerRequestPayload,
    "mail.deliver": MailDeliverPayload,
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
