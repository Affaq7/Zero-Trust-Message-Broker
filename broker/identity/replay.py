"""In-memory replay cache for proof jti values (docs/identity-spec.md section 4).

Each accepted jti is remembered for 60 s, longer than a proof's 30 s life
plus leeway, so a proof can never be used twice. Redis is FYP-II.
"""

import threading
import time
from collections import deque

REPLAY_WINDOW_SECONDS = 60


class ReplayCache:
    """Remembers jti values for ``window`` seconds.

    With ``max_entries`` set, the cache never holds more than that many values:
    when it is full, the oldest one is dropped to make room (bounded memory
    under a flood of unique values).
    """

    def __init__(self, window: int = REPLAY_WINDOW_SECONDS, max_entries: int | None = None) -> None:
        if max_entries is not None and max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._window = window
        self.max_entries = max_entries
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
            if self.max_entries is not None:
                while len(self._expiry) >= self.max_entries:
                    self._drop_oldest()
            expiry = now + self._window
            self._expiry[jti] = expiry
            self._order.append((expiry, jti))
            return False

    def _purge(self, now: int) -> None:
        while self._order and self._order[0][0] <= now:
            self._drop_oldest()

    def _drop_oldest(self) -> None:
        expiry, jti = self._order.popleft()
        if self._expiry.get(jti) == expiry:
            del self._expiry[jti]

    def __len__(self) -> int:
        return len(self._expiry)
