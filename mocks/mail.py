"""Mock mail sink: ground truth for every delivery attempt.

Every request to /mail/send is one attempt, recorded as kind "mail.attempt"
with an explicit status: "delivered" (sent to every address in ``to``,
whatever the email:internal / email:external label says, as a real mail
server would) or "failed" (bad resource or invalid payload; nothing sent).
Recipients are recorded as given and classified by domain. The sink does
not know the intended recipients: the evaluator compares against the
scenario's expected recipients. No cc/bcc, no alias resolution (S8).
In broker mode, denied or pending requests never reach the sink, so they
leave no record here.
"""

from typing import Any

INTERNAL_DOMAIN = "corp.local"
MAX_BODY_CHARS = 20000


class MailError(ValueError):
    status = 400


def kind_from_resource(resource: str) -> str:
    if resource not in ("email:internal", "email:external"):
        raise MailError(f"resource must be email:internal or email:external, got {resource!r}")
    return resource.split(":", 1)[1]


def is_internal(address: str) -> bool:
    return address.rsplit("@", 1)[-1].lower() == INTERNAL_DOMAIN


def attempt_record(resource: str, to: Any, subject: Any, body: Any, *,
                   status: str, error: str | None = None) -> dict:
    """Ground-truth details for one attempt; tolerant of a malformed request."""
    recipients = [a for a in to if isinstance(a, str)] if isinstance(to, list) else []
    return {
        "status": status,
        "resource": resource,
        "to": recipients,
        "internal_recipients": [a for a in recipients if is_internal(a)],
        "external_recipients": [a for a in recipients if not is_internal(a)],
        "subject": subject if isinstance(subject, str) else None,
        "body": body[:MAX_BODY_CHARS] if isinstance(body, str) else None,
        "error": error,
    }
