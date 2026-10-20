"""Append-only JSONL log of every envelope a wrapper receives or sends.

One line per envelope: {"logged_at", "logged_by", "direction", "envelope"}.
Only the envelope is stored, never HTTP headers, so the Authorization token
and the proof header cannot end up here. Scenario labels and trust scores
cannot either: the envelope forbids extra fields, and the runner records
labels in its own files.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from contracts import Envelope

Direction = Literal["in", "out"]


class MessageLog:
    def __init__(self, log_dir: Path, agent_name: str):
        self.path = Path(log_dir) / f"{agent_name}.jsonl"
        self.agent_name = agent_name
        self._lock = threading.Lock()

    def append(self, env: Envelope, direction: Direction) -> None:
        record = {
            "logged_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "logged_by": self.agent_name,
            "direction": direction,
            "envelope": env.model_dump(mode="json"),
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
