"""Content inspection (F3, Afaq): pipeline steps 5 (request) and 9 (reply).

Frozen interfaces (team plan section 7, S23), loaded by broker/pipeline.py as the
"content" group:

    check_request_content(env) -> (ok, code)
        (False, "RECIPIENT_NOT_APPROVED")    DENY (A4)
        (True,  "INDIVIDUAL_DATA_REQUEST")   allowed; V5 event for the trust engine
        (True,  None)                        allowed, nothing to note
    sanitize_reply(env) -> (reply, redacted_field_names, reply_injection_cue)

minimum_necessary(action, payload) says, per action, what "minimum necessary
information" means (docs/detection-design.md V5 and conflict 1).

State is in memory and bounded (like the V4 traces): the recipients each trace's
email request named, and the shape of each pending aggregate request. Removed
values never leave this module: only field NAMES are returned, never values, so
nothing sensitive reaches the message log, /api/events or the audit log.
"""

from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from contracts.envelope import Envelope
from contracts.payloads import normalize_address

# --- what is sensitive (mocks/seed.py SENSITIVE_COLUMNS) and what names a person ----------------

SENSITIVE_COLUMNS = frozenset({"ssn", "home_address", "salary", "bank_account"})
# Columns that identify one person: grouping or filtering by them singles a person out.
PERSON_COLUMNS = frozenset({"id", "employee_id", "name", "email", "phone", "manager_id"})
# The company's own mail domain (mocks/seed.py: every employee is first.last@corp.local).
INTERNAL_DOMAINS = ("corp.local",)

EMAIL_REQUEST_ACTIONS = ("tool.send_email_internal", "tool.send_email_external")
MAIL_DELIVER = "mail.deliver"
AGGREGATE = "db.query_aggregate"

# Memory limits, the same idea as the V4 traces in broker/pipeline.py.
TRACE_IDLE_SECONDS = 900          # a trace's approved recipients are kept this long
MAX_TRACKED_TRACES = 10_000       # and at most this many traces / pending aggregate requests

RECIPIENT_NOT_APPROVED = "RECIPIENT_NOT_APPROVED"
INDIVIDUAL_DATA_REQUEST = "INDIVIDUAL_DATA_REQUEST"


# --- minimum necessary, per action ----------------------------------------------------------------

def minimum_necessary(action: str, payload: dict[str, Any]) -> str | None:
    """None when the request asks for no more than its action needs; otherwise why it does.

    What "minimum necessary information" means for each action:

    - db.query_aggregate: totals and counts only. It may filter and group by ordinary
      columns (project, dept, item), but grouping or filtering by a sensitive column
      (ssn, home_address, salary, bank_account) or by a column that names one person
      (id, employee_id, name, email, phone, manager_id) singles a person out, so it is
      an individual-level request even though the action is an aggregate (V5, conflict 1).
    - db.query_rows: individual rows by design (risk rating individual_data: true), so
      every request is individual-level (V5). Who may make it is policy's job.
    - db.update_records: changing a sensitive column is individual-level (V5).
    - tool.send_email_*, mail.deliver: recipients are checked separately (A4,
      check_request_content); the subject and body are free text for the requester.
    - file.read_internal, file.delete, web.fetch_page, research.lookup, planner.request,
      admin.change_policy: nothing to narrow at this step (the catalog and policy decide
      who may call them; replies are checked at step 9).
    """
    payload = payload if isinstance(payload, dict) else {}
    if action == AGGREGATE:
        group_by = {str(c) for c in payload.get("group_by") or []}
        filters = {str(c) for c in (payload.get("filters") or {})}
        for kind, cols in (("groups by", group_by), ("filters on", filters)):
            hit = sorted(cols & (SENSITIVE_COLUMNS | PERSON_COLUMNS))
            if hit:
                return f"aggregate {kind} {', '.join(hit)}: singles out a person"
        return None
    if action == "db.query_rows":
        return "query_rows returns individual-level rows"
    if action == "db.update_records":
        changed = {str(c) for c in (payload.get("values") or {})}
        hit = sorted(changed & SENSITIVE_COLUMNS)
        return f"update changes {', '.join(hit)}" if hit else None
    return None


# --- the reply-side injection cue -----------------------------------------------------------------

try:
    # Kissa's K4 detector (broker/intercept/validate.py), once it is on main.
    from broker.intercept.validate import CUE_PATTERNS as _CUE_PATTERNS
except ImportError:
    # LOCAL STAND-IN, to be replaced by broker.intercept.validate.CUE_PATTERNS (PR #11).
    # Same phrases as K4's list, so the request and reply sides agree.
    _CUE_PATTERNS = tuple(re.compile(p) for p in (
        r"\b(?:ignore|disregard|forget)\s+(?:(?:all|the|any)\s+)*(?:previous|prior|above|earlier|your)\s+instructions\b",
        r"\bskip\s+(?:(?:all|the|any)\s+)*approvals?\b",
        r"\bbypass\s+(?:the\s+)?(?:approval|approvals|policy|security|checks?|broker)\b",
        r"\bsend\s+to\b",
        r"\b(?:send|forward|email)\s+(?:\w+\s+){0,2}to\s+\S+@",
        r"\byou\s+are\s+now\b",
        r"\bsystem\s+prompt\b",
    ))

MAX_CUE_TEXT = 200_000      # characters scanned per reply


def _strings(value: Any, limit: int = 1000):
    """Every string inside a reply payload (depth-first, bounded)."""
    stack, seen = [value], 0
    while stack and seen < limit:
        v = stack.pop()
        seen += 1
        if isinstance(v, str):
            yield v
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)


def reply_has_injection_cue(payload: dict[str, Any]) -> bool:
    text = " ".join(" ".join(s.lower().split()) for s in _strings(payload))[:MAX_CUE_TEXT]
    return any(p.search(text) for p in _CUE_PATTERNS)


# --- the inspector ----------------------------------------------------------------------------------

def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def _recipients(payload: dict[str, Any]) -> list[str]:
    out = []
    for field in ("to", "cc", "bcc"):
        for a in payload.get(field) or []:
            if isinstance(a, str):
                out.append(normalize_address(a))
    return out


class ContentInspector:
    """Steps 5 and 9 with their bounded memory. One per broker; tests make their own."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        # trace_id -> (last seen, approved recipients, internal-only send?)
        self._approved: OrderedDict[str, tuple[float, frozenset[str], bool]] = OrderedDict()
        # request msg_id -> (time, group_by columns) for aggregate requests awaiting their reply
        self._aggregates: OrderedDict[str, tuple[float, tuple[str, ...]]] = OrderedDict()

    # --- step 5 -----------------------------------------------------------------------------

    def check_request_content(self, env: Envelope) -> tuple[bool, str | None]:
        payload = env.payload if isinstance(env.payload, dict) else {}
        now = self._clock()
        with self._lock:
            self._expire(now)
            if env.action in EMAIL_REQUEST_ACTIONS:
                return self._email_request(env, payload, now)
            if env.action == MAIL_DELIVER:
                return self._mail_deliver(env, payload)
            if env.action == AGGREGATE:
                self._remember(self._aggregates, env.msg_id, (now, tuple(payload.get("group_by") or ())))
        if minimum_necessary(env.action, payload) is not None:
            return True, INDIVIDUAL_DATA_REQUEST
        return True, None

    def _email_request(self, env: Envelope, payload: dict, now: float) -> tuple[bool, str | None]:
        """The requester's own email request names the approved recipients for this trace."""
        recipients = _recipients(payload)
        internal = env.action == "tool.send_email_internal"
        if internal and any(_domain(a) not in INTERNAL_DOMAINS for a in recipients):
            return False, RECIPIENT_NOT_APPROVED          # an internal email may only go inside
        known = self._approved.get(env.trace_id)
        approved = frozenset(recipients) | (known[1] if known else frozenset())
        internal_only = internal and (known[2] if known else True)
        self._remember(self._approved, env.trace_id, (now, approved, internal_only))
        return True, None

    def _mail_deliver(self, env: Envelope, payload: dict) -> tuple[bool, str | None]:
        """A4. Every recipient in to, cc and bcc must have been named by an earlier
        tool.send_email_* request in the SAME trace; an internal send stays internal.
        No such request in the trace (a tool mailing on its own): deny (fail closed)."""
        known = self._approved.get(env.trace_id)
        if known is None:
            return False, RECIPIENT_NOT_APPROVED
        _, approved, internal_only = known
        for address in _recipients(payload):
            if address not in approved:
                return False, RECIPIENT_NOT_APPROVED
            if internal_only and _domain(address) not in INTERNAL_DOMAINS:
                return False, RECIPIENT_NOT_APPROVED
        return True, None

    # --- step 9 -----------------------------------------------------------------------------

    def sanitize_reply(self, env: Envelope) -> tuple[Envelope, list[str], bool]:
        payload = env.payload if isinstance(env.payload, dict) else {}
        cue = reply_has_injection_cue(payload)
        if env.action != AGGREGATE or payload.get("status") != "ok" or not isinstance(payload.get("result"), dict):
            return env, [], cue
        with self._lock:
            request = self._aggregates.pop(env.parent_msg_id, None) if env.parent_msg_id else None
        group_by = request[1] if request else ()
        result, redacted = _aggregate_only(payload["result"], group_by)
        if not redacted:
            return env, [], cue
        return env.model_copy(update={"payload": {**payload, "result": result}}), redacted, cue

    # --- memory -------------------------------------------------------------------------------

    def _remember(self, store: OrderedDict, key: str, value: tuple) -> None:
        store[key] = value
        store.move_to_end(key)
        while len(store) > MAX_TRACKED_TRACES:
            store.popitem(last=False)

    def _expire(self, now: float) -> None:
        for store in (self._approved, self._aggregates):
            while store:
                key, value = next(iter(store.items()))
                if now - value[0] <= TRACE_IDLE_SECONDS:
                    break
                store.popitem(last=False)


def _aggregate_only(result: dict[str, Any], group_by: tuple[str, ...]) -> tuple[dict[str, Any], list[str]]:
    """Cut an aggregate reply down to totals and counts.

    A row may hold only "value" plus the request's own group_by columns, and never a
    sensitive or person column. Without group_by exactly one row is the answer; any
    further rows are not part of it. Returns the cut result and the NAMES of what was
    removed (never the values).
    """
    allowed = ({"value"} | set(group_by)) - SENSITIVE_COLUMNS - PERSON_COLUMNS
    rows = result.get("rows") if isinstance(result.get("rows"), list) else []
    kept, removed = [], set()
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            removed.add("result.rows[]")
            continue
        extra = set(row) - allowed
        if extra or (not group_by and kept):
            removed.update(f"result.rows[].{k}" for k in (extra or set(row)))
            continue
        kept.append(row)
    removed.update(f"result.{k}" for k in result if k in SENSITIVE_COLUMNS | PERSON_COLUMNS)
    if not removed:
        return result, []
    cut = {k: v for k, v in result.items() if k not in SENSITIVE_COLUMNS | PERSON_COLUMNS}
    cut["rows"] = kept
    return cut, sorted(removed)


# --- the module-level frozen interface ------------------------------------------------------------

_default = ContentInspector()


def check_request_content(env: Envelope) -> tuple[bool, str | None]:
    return _default.check_request_content(env)


def sanitize_reply(env: Envelope) -> tuple[Envelope, list[str], bool]:
    return _default.sanitize_reply(env)
