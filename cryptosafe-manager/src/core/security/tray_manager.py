from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Optional

try:
    import pystray
    from pystray import MenuItem as Item
    from PIL import Image, ImageDraw
except Exception:
    pystray = None
    Item = None
    Image = None
    ImageDraw = None


@dataclass
class TrayState:
    locked: bool = True
    clipboard_active: bool = False
    clipboard_remaining: int = 0
    security_profile: str = "Standard"
    crypto_busy: bool = False


class TrayManager:
    def __init__(
        self,
        on_show_window: Callable[[], None],
        on_lock: Callable[[], None],
        on_unlock: Callable[[], None],
        on_quick_search: Callable[[], None],
        on_clear_clipboard: Callable[[], None],
        on_panic: Callable[[], None],
        on_settings: Callable[[], None],
        on_exit: Callable[[], None],
        notify_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.on_show_window = on_show_window
        self.on_lock = on_lock
        self.on_unlock = on_unlock
        self.on_quick_search = on_quick_search
        self.on_clear_clipboard = on_clear_clipboard
        self.on_panic = on_panic
        self.on_settings = on_settings
        self.on_exit = on_exit
        self.notify_callback = notify_callback

        self.state = TrayState()
        self.icon = None
        self._running = False
        self._blink = False
        self._lock = threading.RLock()

    @property
    def available(self) -> bool:
        return pystray is not None and Image is not None and ImageDraw is not None

    def start(self) -> None:
        if not self.available or self._running:
            return

        self.icon = pystray.Icon(
            "cryptosafe_manager",
            self._build_icon(),
            "CryptoSafe Manager",
            self._build_menu(),
        )
        self._running = True
        thread = threading.Thread(target=self.icon.run, daemon=True, name="TrayManager")
        thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
            if self.icon is not None:
                try:
                    self.icon.stop()
                except Exception:
                    pass
                self.icon = None

    def update_state(
        self,
        *,
        locked: Optional[bool] = None,
        clipboard_active: Optional[bool] = None,
        clipboard_remaining: Optional[int] = None,
        security_profile: Optional[str] = None,
        crypto_busy: Optional[bool] = None,
    ) -> None:
        with self._lock:
            if locked is not None:
                self.state.locked = locked
            if clipboard_active is not None:
                self.state.clipboard_active = clipboard_active
            if clipboard_remaining is not None:
                self.state.clipboard_remaining = clipboard_remaining
            if security_profile is not None:
                self.state.security_profile = security_profile
            if crypto_busy is not None:
                self.state.crypto_busy = crypto_busy

            self._refresh_icon()

    def show_notification(self, title: str, message: str) -> None:
        if self.icon is not None:
            try:
                self.icon.notify(message, title)
                return
            except Exception:
                pass
        if self.notify_callback:
            self.notify_callback(title, message)

    def _refresh_icon(self) -> None:
        if self.icon is None:
            return
        try:
            self.icon.icon = self._build_icon()
            self.icon.title = self._build_tooltip()
            self.icon.menu = self._build_menu()
            self.icon.update_menu()
        except Exception:
            pass

    def _build_tooltip(self) -> str:
        lock_text = "Locked" if self.state.locked else "Unlocked"
        clip_text = (
            f"Clipboard: active ({self.state.clipboard_remaining}s)"
            if self.state.clipboard_active
            else "Clipboard: empty"
        )
        crypto_text = "Crypto: busy" if self.state.crypto_busy else "Crypto: idle"
        return f"CryptoSafe Manager\n{lock_text}\n{clip_text}\nProfile: {self.state.security_profile}\n{crypto_text}"

    def _build_menu(self):
        if Item is None:
            return None

        lock_title = "Unlock vault" if self.state.locked else "Lock vault"
        lock_action = self.on_unlock if self.state.locked else self.on_lock

        clipboard_title = (
            f"Clear clipboard ({self.state.clipboard_remaining}s)"
            if self.state.clipboard_active
            else "Clear clipboard"
        )

        return pystray.Menu(
            Item("Show main window", lambda: self.on_show_window()),
            Item(lock_title, lambda: lock_action()),
            Item("Quick search", lambda: self.on_quick_search()),
            Item(clipboard_title, lambda: self.on_clear_clipboard()),
            Item("Panic mode", lambda: self.on_panic()),
            Item("Settings", lambda: self.on_settings()),
            Item("Exit", lambda: self.on_exit()),
        )

    def _build_icon(self):
        size = 64
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)

        if self.state.crypto_busy:
            self._blink = not self._blink
        else:
            self._blink = False

        if self.state.locked:
            color = (200, 50, 50, 255)
        else:
            color = (40, 180, 90, 255)

        if self.state.security_profile.lower() == "paranoid":
            color = (120, 40, 160, 255)
        elif self.state.security_profile.lower() == "enhanced":
            color = (50, 110, 220, 255)

        if self._blink:
            color = (255, 180, 40, 255)

        draw.ellipse((8, 8, 56, 56), fill=color)

        if self.state.locked:
            draw.rectangle((24, 28, 40, 46), fill=(255, 255, 255, 255))
            draw.arc((22, 16, 42, 34), start=0, end=180, fill=(255, 255, 255, 255), width=3)
        else:
            draw.rectangle((24, 28, 40, 46), fill=(255, 255, 255, 255))
            draw.arc((18, 16, 38, 34), start=300, end=120, fill=(255, 255, 255, 255), width=3)

        if self.state.clipboard_active:
            draw.rectangle((44, 10, 56, 22), fill=(255, 255, 255, 255))

        return image