from __future__ import annotations

import threading
import tkinter.messagebox as mb
from dataclasses import dataclass


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
        auth_manager=None,
        clipboard_service=None,
        audit_logger=None,
        main_window=None,
        secret_wiper=None,
    ):
        self.config = config
        self.auth_manager = auth_manager
        self.clipboard_service = clipboard_service
        self.audit_logger = audit_logger
        self.main_window = main_window
        self.secret_wiper = secret_wiper
        self._lock = threading.RLock()
        self.activated = False

    def activate(self, method: str = "hotkey") -> None:
        with self._lock:
            if self.activated:
                return
            self.activated = True

        try:
            if self.config.clear_clipboard and self.clipboard_service:
                self.clipboard_service.clear_clipboard("panic")
        except Exception:
            pass

        try:
            if self.config.wipe_secrets and self.secret_wiper:
                self.secret_wiper()
        except Exception:
            pass

        try:
            if self.config.lock_vault and self.auth_manager:
                self.auth_manager.logout()
        except Exception:
            pass

        try:
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="PANIC_MODE_ACTIVATED",
                    severity="CRITICAL",
                    source="panic_mode",
                    details={"activation_method": method},
                )
        except Exception:
            pass

        try:
            if self.main_window:
                self.main_window.handle_panic_ui(close_app=self.config.close_application)
        except Exception:
            pass

        if self.config.show_fake_error:
            try:
                mb.showerror("Application Error", "The application encountered an unexpected error and must close.")
            except Exception:
                pass

        with self._lock:
            self.activated = False