from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class SessionState:
    locked: bool = True
    username: str = "local"


@dataclass
class ClipboardState:
    value: Optional[str] = None
    copied_at: Optional[float] = None
    ttl_seconds: int = 0


@dataclass
class IdleState:
    last_activity_at: float = 0.0
    timeout_seconds: int = 0


class StateManager:

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.session = SessionState()
        self.clipboard = ClipboardState()
        self.idle = IdleState(last_activity_at=time.time())

    def set_locked(self, locked: bool) -> None:
        with self._lock:
            self.session.locked = bool(locked)

    def touch_activity(self) -> None:
        with self._lock:
            self.idle.last_activity_at = time.time()

    def set_clipboard(self, value: Optional[str], ttl_seconds: int = 0) -> None:
        with self._lock:
            self.clipboard.value = value
            self.clipboard.copied_at = time.time() if value is not None else None
            self.clipboard.ttl_seconds = int(ttl_seconds)
