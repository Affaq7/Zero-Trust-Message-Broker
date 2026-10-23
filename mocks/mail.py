"""Mock mail sink: ground truth for every delivery attempt.

Only the mailer agent calls /mail/send in a scenario run (resource
"mail:outbound", payload of mail.deliver); the older email:internal /
email:external resources stay for manual checks.

Every request to /mail/send is one attempt, recorded as kind "mail.attempt"
with an explicit status: "delivered" (sent to every address in ``to``, ``cc``
and ``bcc``, whatever the email:internal / email:external label says, as a
real mail server would) or "failed" (bad resource or invalid payload;
nothing sent). Recipients are normalised with the contract's
normalize_address (strip, lowercase) and classified by domain over all three
lists together, so an outside bcc shows up as an external recipient. The
sink does not know the intended recipients: the evaluator compares against
the scenario's expected recipients. No alias or group resolution (S14): an
address is taken literally.
In broker mode, denied or pending requests never reach the sink, so they
leave no record here.
"""

from typing import Any

from contracts.payloads import normalize_address

INTERNAL_DOMAIN = "corp.local"
MAX_BODY_CHARS = 20000


class MailError(ValueError):
    status = 400


RESOURCES = ("email:internal", "email:external", "mail:outbound")


def kind_from_resource(resource: str) -> str:
    if resource not in RESOURCES:
        raise MailError(f"resource must be one of {', '.join(RESOURCES)}, got {resource!r}")
    return resource.split(":", 1)[1]


def is_internal(address: str) -> bool:
    return address.rsplit("@", 1)[-1].lower() == INTERNAL_DOMAIN


def _recipients(value: Any) -> list[str]:
    """Text items of a recipient list, normalised; anything else is ignored."""
    return [normalize_address(a) for a in value if isinstance(a, str)] if isinstance(value, list) else []


def attempt_record(resource: str, to: Any, subject: Any, body: Any, *,
                   status: str, error: str | None = None, cc: Any = None, bcc: Any = None) -> dict:
    """Ground-truth details for one attempt; tolerant of a malformed request."""
    to_list, cc_list, bcc_list = _recipients(to), _recipients(cc), _recipients(bcc)
    everyone = to_list + cc_list + bcc_list
    return {
        "status": status,
        "resource": resource,
        "to": to_list,
        "cc": cc_list,
        "bcc": bcc_list,
        "internal_recipients": [a for a in everyone if is_internal(a)],
        "external_recipients": [a for a in everyone if not is_internal(a)],
        "subject": subject if isinstance(subject, str) else None,
        "body": body[:MAX_BODY_CHARS] if isinstance(body, str) else None,
        "error": error,
    }
