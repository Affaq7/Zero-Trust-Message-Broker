"""Message envelope, contract v0.2.

Two levels of checking, kept apart on purpose:

- ``Envelope`` checks STRUCTURE only: required fields, types, allowed literal
  values, no extra fields, timestamp in UTC. The direct-mode wrapper uses only
  this, because the baseline must provide no security.
- ``rule_violations()`` checks cross-field RULES (delegation chain, parent id
  vs msg_type, ...). Builders and the broker use it; direct mode does not.

The JWT and the per-message proof are never part of the envelope. Trust scores
and test labels must never appear here; ``extra="forbid"`` rejects them.
"""

from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from contracts.version import SCHEMA_VERSION

NonEmptyStr = Annotated[str, Field(min_length=1)]

MsgType = Literal["request", "response"]

# Filled in by the broker later; agents and direct mode leave them as None.
Decision = Literal["ALLOW", "SANITIZE", "HITL", "DENY", "QUARANTINE"]


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[SCHEMA_VERSION]
    msg_id: NonEmptyStr
    trace_id: NonEmptyStr
    parent_msg_id: NonEmptyStr | None  # required key; null for requests
    msg_type: MsgType
    sender: NonEmptyStr
    receiver: NonEmptyStr
    action: NonEmptyStr
    resource: NonEmptyStr
    payload: dict[str, Any]
    delegation_chain: list[NonEmptyStr]
    timestamp: datetime

    # Broker reply fields (not used yet).
    decision: Decision | None = None
    reason_code: str | None = None
    redacted_fields: list[str] | None = None
    broker_signature: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _timestamp_must_be_iso_string(cls, value: Any) -> Any:
        # Without this, Pydantic would also accept a Unix number.
        if not isinstance(value, (str, datetime)):
            raise ValueError("timestamp must be an ISO 8601 string")
        return value

    @field_validator("timestamp")
    @classmethod
    def _timestamp_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be UTC (e.g. 2026-10-21T10:00:00Z)")
        return value


def rule_violations(env: Envelope) -> list[str]:
    """Return the cross-field rules this envelope breaks (empty list = OK)."""
    problems: list[str] = []
    chain = env.delegation_chain

    if not chain or chain[0] != "user":
        problems.append("delegation_chain must start with 'user'")
    if env.sender == env.receiver:
        problems.append("sender and receiver must differ")
    if env.parent_msg_id is not None and env.parent_msg_id == env.msg_id:
        problems.append("parent_msg_id must differ from msg_id")

    if env.msg_type == "request":
        if env.parent_msg_id is not None:
            problems.append("a request must have parent_msg_id = null")
        if chain and chain[-1] != env.sender:
            problems.append("a request's delegation_chain must end with sender")
    else:
        if env.parent_msg_id is None:
            problems.append("a response must have parent_msg_id set")
        # A response copies the request's chain, which ends with the
        # request's sender = this response's receiver.
        if chain and chain[-1] != env.receiver:
            problems.append("a response's delegation_chain must end with receiver")

    return problems
