"""Mock mail sink: ground truth for who actually received each email.

It "delivers" to every address in ``to``, whatever the email:internal /
email:external label says (a real mail server ignores such labels too),
and classifies each recipient by domain.
"""

INTERNAL_DOMAIN = "corp.local"


class MailError(ValueError):
    status = 400


def kind_from_resource(resource: str) -> str:
    if resource not in ("email:internal", "email:external"):
        raise MailError(f"resource must be email:internal or email:external, got {resource!r}")
    return resource.split(":", 1)[1]


def is_internal(address: str) -> bool:
    return address.rsplit("@", 1)[-1].lower() == INTERNAL_DOMAIN


def delivery_record(resource: str, to: list[str], subject: str, body: str) -> dict:
    return {
        "resource": resource,
        "to": to,
        "internal_recipients": [a for a in to if is_internal(a)],
        "external_recipients": [a for a in to if not is_internal(a)],
        "subject": subject,
        "body": body,
    }
