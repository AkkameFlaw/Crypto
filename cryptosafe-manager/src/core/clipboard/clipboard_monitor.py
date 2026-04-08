from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import ClipboardAdapter


class ClipboardMonitor:
    def __init__(
        self,
        adapter: ClipboardAdapter,
        service: ClipboardService,
        suspicious_callback: Optional[Callable[[str], None]] = None,
        interval_seconds: float = 0.75,
    ) -> None:
        self.adapter = adapter
        self.service = service
        self.suspicious_callback = suspicious_callback
        self.interval_seconds = max(0.25, float(interval_seconds))
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                status = self.service.get_clipboard_status()
                if status.get("active"):
                    matches = self.service.matches_system_clipboard()
                    if not matches:
                        self.service.accelerate_clear(seconds=2)
                        if self.suspicious_callback:
                            self.suspicious_callback("Clipboard content changed outside the application")
            except Exception:
                pass
            time.sleep(self.interval_seconds)