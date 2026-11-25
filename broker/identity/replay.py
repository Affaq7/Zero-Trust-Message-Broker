"""In-memory replay cache for proof jti values (docs/identity-spec.md section 4).

Each accepted jti is remembered for 60 s, longer than a proof's 30 s life
plus leeway, so a proof can never be used twice. Redis is FYP-II.
"""

import threading
import time
from collections import deque

REPLAY_WINDOW_SECONDS = 60


class ReplayCache:
    """Remembers jti values for ``window`` seconds."""

    def __init__(self, window: int = REPLAY_WINDOW_SECONDS) -> None:
        self._window = window
        self._expiry: dict[str, int] = {}
        self._order: deque[tuple[int, str]] = deque()   # (expiry, jti), oldest first
        self._lock = threading.Lock()

    def seen_or_record(self, jti: str, now: int | None = None) -> bool:
        """True if ``jti`` was recorded in the last ``window`` seconds (a replay).

        Otherwise records it and returns False. A replay does not extend the entry.
        """
        now = int(time.time()) if now is None else now
        with self._lock:
            self._purge(now)
            if jti in self._expiry:
                return True
            expiry = now + self._window
            self._expiry[jti] = expiry
            self._order.append((expiry, jti))
            return False

    def _purge(self, now: int) -> None:
        while self._order and self._order[0][0] <= now:
            expiry, jti = self._order.popleft()
            if self._expiry.get(jti) == expiry:
                del self._expiry[jti]

    def __len__(self) -> int:
        return len(self._expiry)
