"""Ground-truth log of what really happened in the mock world.

One JSON line per event: {"id", "recorded_at", "kind", "trace_id", "details"}.
trace_id comes from the caller's X-Trace-Id header (may be null); the
runner also matches records by time window. Records are appended; the only
change ever made to an existing record is update(), which merges new
detail fields (used for the admin handler's outcome) and stamps
"updated_at". recorded_at always stays the time of the first write.
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class GroundTruthLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, kind: str, trace_id: str | None, details: dict[str, Any]) -> dict:
        record = {"id": str(uuid4()), "recorded_at": utc_now_iso(), "kind": kind,
                  "trace_id": trace_id, "details": details}
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return record

    def update(self, record_id: str, details: dict[str, Any]) -> dict:
        """Merge ``details`` into the record with ``record_id`` (rewrites the file atomically)."""
        with self._lock:
            records = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]
            target = next((r for r in records if r.get("id") == record_id), None)
            if target is None:
                raise KeyError(record_id)
            target["details"] = {**target["details"], **details}
            target["updated_at"] = utc_now_iso()
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
                           encoding="utf-8")
            os.replace(tmp, self.path)
        return target

    def read(self, *, trace_id: str | None = None, kind: str | None = None,
             since: str | None = None, until: str | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        lo = _parse(since) if since else None
        hi = _parse(until) if until else None
        out = []
        with self._lock, open(self.path, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            rec = json.loads(line)
            at = _parse(rec["recorded_at"])
            if trace_id is not None and rec["trace_id"] != trace_id:
                continue
            if kind is not None and rec["kind"] != kind:
                continue
            if (lo and at < lo) or (hi and at > hi):
                continue
            out.append(rec)
        return out
