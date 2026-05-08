from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class PanicConfig:
    close_application: bool = False
    show_fake_error: bool = False
    clear_clipboard: bool = True
    wipe_secrets: bool = True
    lock_vault: bool = True


class PanicMode:
    def __init__(
        self,
        config: PanicConfig,
        *,
        auth_manager=None,
        clipboard_service=None,
        audit_logger=None,
        main_window=None,
        secret_wiper: Optional[Callable[[], None]] = None,
    ) -> None:
        self.config = config
        self.auth_manager = auth_manager
        self.clipboard_service = clipboard_service
        self.audit_logger = audit_logger
        self.main_window = main_window
        self.secret_wiper = secret_wiper

        self._lock = threading.RLock()
        self._activated = False
        self._last_method: Optional[str] = None

    @property
    def activated(self) -> bool:
        return self._activated

    @property
    def last_method(self) -> Optional[str]:
        return self._last_method

    def activate(self, method: str = "hotkey") -> None:
        with self._lock:
            self._activated = True
            self._last_method = method

            self._log_panic_event(method)
            self._clear_clipboard()
            self._wipe_memory()
            self._lock_vault()
            self._handle_ui()

    def reset(self) -> None:
        with self._lock:
            self._activated = False
            self._last_method = None

    def _clear_clipboard(self) -> None:
        if not self.config.clear_clipboard:
            return
        if self.clipboard_service is None:
            return
        try:
            self.clipboard_service.clear_clipboard("panic")
        except TypeError:
            try:
                self.clipboard_service.clear_clipboard()
            except Exception:
                pass
        except Exception:
            pass

    def _wipe_memory(self) -> None:
        if not self.config.wipe_secrets:
            return
        if self.secret_wiper is None:
            return
        try:
            self.secret_wiper()
        except Exception:
            pass

    def _lock_vault(self) -> None:
        if not self.config.lock_vault:
            return
        if self.auth_manager is None:
            return
        try:
            self.auth_manager.logout()
        except Exception:
            pass

    def _handle_ui(self) -> None:
        if self.main_window is None:
            return

        try:
            if hasattr(self.main_window, "handle_panic_ui"):
                self.main_window.handle_panic_ui(
                    close_app=self.config.close_application
                )
                return
        except TypeError:
            try:
                self.main_window.handle_panic_ui(self.config.close_application)
                return
            except Exception:
                pass
        except Exception:
            pass

        try:
            self.main_window.withdraw()
        except Exception:
            pass

        if self.config.close_application:
            try:
                self.main_window.after(200, self.main_window.on_exit)
            except Exception:
                pass

    def _log_panic_event(self, method: str) -> None:
        if self.audit_logger is None:
            return
        try:
            self.audit_logger.log_event(
                event_type="PANIC_MODE_ACTIVATED",
                severity="CRITICAL",
                source="panic_mode",
                details={"activation_method": method},
            )
        except TypeError:
            try:
                self.audit_logger.log_event(
                    "PANIC_MODE_ACTIVATED",
                    "CRITICAL",
                    "panic_mode",
                    {"activation_method": method},
                )
            except Exception:
                pass
        except Exception:
            pass