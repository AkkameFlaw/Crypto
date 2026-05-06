from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


@dataclass(frozen=True)
class SecurityProfile:
    name: str
    auto_lock_seconds: int
    lock_on_focus_loss: bool
    clear_clipboard_on_lock: bool
    sensitivity: str
    close_on_panic: bool


def build_profile_config(name: str) -> SecurityProfile:
    normalized = (name or "standard").strip().lower()

    if normalized == "enhanced":
        return SecurityProfile(
            name="Enhanced",
            auto_lock_seconds=120,
            lock_on_focus_loss=True,
            clear_clipboard_on_lock=True,
            sensitivity="high",
            close_on_panic=False,
        )
    if normalized == "paranoid":
        return SecurityProfile(
            name="Paranoid",
            auto_lock_seconds=60,
            lock_on_focus_loss=True,
            clear_clipboard_on_lock=True,
            sensitivity="high",
            close_on_panic=True,
        )
    return SecurityProfile(
        name="Standard",
        auto_lock_seconds=300,
        lock_on_focus_loss=False,
        clear_clipboard_on_lock=True,
        sensitivity="medium",
        close_on_panic=False,
    )


class ActivityMonitor:
    def __init__(
        self,
        lock_callback: Callable[[], None],
        warning_callback: Callable[[int], None] | None = None,
        profile: SecurityProfile | None = None,
        check_interval: float = 1.0,
    ):
        self.lock_callback = lock_callback
        self.warning_callback = warning_callback
        self.profile = profile or build_profile_config("standard")
        self.check_interval = check_interval

        self._monitoring = False
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._last_activity = datetime.now(timezone.utc)
        self._focused = True
        self._already_locked = False
        self._warning_sent = False

    def set_profile(self, profile: SecurityProfile) -> None:
        with self._lock:
            self.profile = profile
            self._warning_sent = False

    def start(self) -> None:
        with self._lock:
            if self._monitoring:
                return
            self._monitoring = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._monitoring = False
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=1.5)

    def record_activity(self) -> None:
        with self._lock:
            self._last_activity = datetime.now(timezone.utc)
            self._already_locked = False
            self._warning_sent = False

    def set_focus(self, focused: bool) -> None:
        with self._lock:
            self._focused = focused
            if focused:
                self.record_activity()

    def get_idle_time(self) -> float:
        with self._lock:
            return (datetime.now(timezone.utc) - self._last_activity).total_seconds()

    def force_lock_check(self) -> None:
        self._evaluate_state()

    def _monitor_loop(self) -> None:
        while True:
            with self._lock:
                if not self._monitoring:
                    break
            self._evaluate_state()
            time.sleep(self.check_interval)

    def _evaluate_state(self) -> None:
        with self._lock:
            idle = self.get_idle_time()
            timeout = self.profile.auto_lock_seconds
            focused = self._focused
            already_locked = self._already_locked
            warning_sent = self._warning_sent
            lock_on_focus_loss = self.profile.lock_on_focus_loss

        if lock_on_focus_loss and not focused and not already_locked:
            self._trigger_lock()
            return

        if timeout <= 0:
            return

        remaining = int(timeout - idle)
        if remaining <= 10 and remaining > 0 and not warning_sent:
            if self.warning_callback:
                self.warning_callback(remaining)
            with self._lock:
                self._warning_sent = True

        if idle >= timeout and not already_locked:
            self._trigger_lock()

    def _trigger_lock(self) -> None:
        with self._lock:
            self._already_locked = True
            self._warning_sent = False
        self.lock_callback()