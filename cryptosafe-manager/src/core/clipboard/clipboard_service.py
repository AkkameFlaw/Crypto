from __future__ import annotations

import ctypes
import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from src.core.clipboard.platform_adapter import ClipboardAdapter
from src.core.crypto.authentication import AuthenticationManager
from src.core.events import ClipboardCleared, ClipboardCopied, EventBus
from src.core.utils import secure_zero_bytes


Observer = Callable[[dict], None]


@dataclass
class SecureClipboardItem:
    data_type: str
    source_entry_id: Optional[int]
    copied_at: float
    timeout_seconds: int
    mask: bytearray
    obfuscated: bytearray
    expected_hash: str

    def reveal_text(self) -> str:
        restored = bytearray(len(self.obfuscated))
        for i, b in enumerate(self.obfuscated):
            restored[i] = b ^ self.mask[i % len(self.mask)]
        try:
            return restored.decode("utf-8", errors="ignore")
        finally:
            secure_zero_bytes(restored)

    def masked_preview(self) -> str:
        text = self.reveal_text()
        if not text:
            return ""
        if len(text) <= 4:
            return "•" * len(text)
        return text[:3] + "•" * max(3, len(text) - 3)

    def secure_wipe(self) -> None:
        secure_zero_bytes(self.mask)
        secure_zero_bytes(self.obfuscated)


class ClipboardService:
    def __init__(
        self,
        platform_adapter: ClipboardAdapter,
        event_system: EventBus,
        timeout_seconds: int = 30,
        auth_manager: Optional[AuthenticationManager] = None,
    ) -> None:
        self.platform = platform_adapter
        self.events = event_system
        self.auth_manager = auth_manager

        self._lock = threading.RLock()
        self.current_content: Optional[SecureClipboardItem] = None
        self.timer: Optional[threading.Timer] = None
        self.warning_timer: Optional[threading.Timer] = None
        self.observers: list[Observer] = []
        self.timeout_seconds = self._normalize_timeout(timeout_seconds)

    @staticmethod
    def _normalize_timeout(timeout_seconds: int) -> int:
        if timeout_seconds == 0:
            return 0
        return min(300, max(5, int(timeout_seconds)))

    def set_timeout(self, timeout_seconds: int) -> None:
        with self._lock:
            self.timeout_seconds = self._normalize_timeout(timeout_seconds)
            self._notify()

    def add_observer(self, callback: Observer) -> None:
        with self._lock:
            if callback not in self.observers:
                self.observers.append(callback)

    def remove_observer(self, callback: Observer) -> None:
        with self._lock:
            if callback in self.observers:
                self.observers.remove(callback)

    def copy_to_clipboard(self, data: str, data_type: str = "text", source_entry_id: Optional[int] = None) -> bool:
        if self.auth_manager and not self.auth_manager.get_encryption_key():
            return False

        data = self._sanitize_input(data)
        if not data:
            return False

        with self._lock:
            self._clear_clipboard_locked(reason="replaced")

            data_bytes = data.encode("utf-8")
            mask = bytearray(secrets.token_bytes(32))
            obfuscated = bytearray(len(data_bytes))
            for i, b in enumerate(data_bytes):
                obfuscated[i] = b ^ mask[i % len(mask)]

            ok = self.platform.copy_to_clipboard(data)
            if not ok:
                secure_zero_bytes(mask)
                secure_zero_bytes(obfuscated)
                return False

            timeout = self.timeout_seconds
            expected_hash = hashlib.sha256(data_bytes).hexdigest()
            self.current_content = SecureClipboardItem(
                data_type=data_type,
                source_entry_id=source_entry_id,
                copied_at=time.time(),
                timeout_seconds=timeout,
                mask=mask,
                obfuscated=obfuscated,
                expected_hash=expected_hash,
            )

            if timeout > 0:
                self.timer = threading.Timer(timeout, self._on_timeout)
                self.timer.daemon = True
                self.timer.start()

                warning_delay = max(0, timeout - 5)
                self.warning_timer = threading.Timer(warning_delay, self._on_warning)
                self.warning_timer.daemon = True
                self.warning_timer.start()

            self.events.publish(
                ClipboardCopied(
                    entry_id=source_entry_id,
                    data_type=data_type,
                    timeout_seconds=timeout,
                )
            )
            self._notify()
            return True

    def clear_clipboard(self, reason: str = "manual") -> None:
        with self._lock:
            self._clear_clipboard_locked(reason=reason)

    def accelerate_clear(self, seconds: int = 2) -> None:
        with self._lock:
            if not self.current_content:
                return
            if self.timer:
                self.timer.cancel()
            self.timer = threading.Timer(max(1, seconds), self._on_timeout)
            self.timer.daemon = True
            self.timer.start()
            self._notify()

    def get_clipboard_status(self) -> dict:
        with self._lock:
            if not self.current_content:
                return {"active": False}

            remaining = self._remaining_seconds_locked()
            return {
                "active": True,
                "data_type": self.current_content.data_type,
                "remaining_seconds": remaining,
                "source_entry_id": self.current_content.source_entry_id,
                "preview": self.current_content.masked_preview(),
            }

    def get_preview(self, reveal: bool = False) -> Optional[str]:
        with self._lock:
            if not self.current_content:
                return None
            return self.current_content.reveal_text() if reveal else self.current_content.masked_preview()

    def matches_system_clipboard(self) -> bool:
        with self._lock:
            if not self.current_content:
                return False
        content = self.platform.get_clipboard_content()
        if content is None:
            return False
        return hashlib.sha256(content.encode("utf-8")).hexdigest() == self.current_content.expected_hash  # type: ignore[union-attr]

    def _on_warning(self) -> None:
        self._notify(extra={"warning": True})

    def _on_timeout(self) -> None:
        with self._lock:
            self._clear_clipboard_locked(reason="timeout")

    def _clear_clipboard_locked(self, reason: str) -> None:
        if self.timer:
            self.timer.cancel()
            self.timer = None
        if self.warning_timer:
            self.warning_timer.cancel()
            self.warning_timer = None

        if self.current_content is not None:
            self.platform.clear_clipboard()
            self.current_content.secure_wipe()
            self.current_content = None
            self.events.publish(ClipboardCleared(entry_id=None, reason=reason))

        self._notify()

    def _remaining_seconds_locked(self) -> int:
        if not self.current_content or self.current_content.timeout_seconds == 0:
            return 0
        elapsed = time.time() - self.current_content.copied_at
        return max(0, int(round(self.current_content.timeout_seconds - elapsed)))

    def _notify(self, extra: Optional[dict] = None) -> None:
        payload = self.get_clipboard_status()
        if extra:
            payload.update(extra)
        for callback in list(self.observers):
            try:
                callback(payload)
            except Exception:
                pass

    @staticmethod
    def _sanitize_input(data: str) -> str:
        if data is None:
            return ""
        data = str(data).replace("\x00", "").strip()
        if len(data) > 100_000:
            data = data[:100_000]
        return data