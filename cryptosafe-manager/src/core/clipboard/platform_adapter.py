from __future__ import annotations

import platform
import subprocess
from abc import ABC, abstractmethod
from typing import Optional

import pyperclip


class ClipboardAdapter(ABC):
    @abstractmethod
    def copy_to_clipboard(self, data: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def clear_clipboard(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_clipboard_content(self) -> Optional[str]:
        raise NotImplementedError


class PyperclipClipboardAdapter(ClipboardAdapter):
    def copy_to_clipboard(self, data: str) -> bool:
        try:
            pyperclip.copy(data)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            pyperclip.copy("")
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return pyperclip.paste()
        except Exception:
            return None


class WindowsClipboardAdapter(ClipboardAdapter):
    def __init__(self) -> None:
        import win32clipboard

        self.win32clipboard = win32clipboard

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.win32clipboard.OpenClipboard()
            self.win32clipboard.EmptyClipboard()
            self.win32clipboard.SetClipboardText(data, self.win32clipboard.CF_UNICODETEXT)
            return True
        except Exception:
            return False
        finally:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass

    def clear_clipboard(self) -> bool:
        try:
            self.win32clipboard.OpenClipboard()
            self.win32clipboard.EmptyClipboard()
            return True
        except Exception:
            return False
        finally:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass

    def get_clipboard_content(self) -> Optional[str]:
        try:
            self.win32clipboard.OpenClipboard()
            data = self.win32clipboard.GetClipboardData(self.win32clipboard.CF_UNICODETEXT)
            return str(data) if data is not None else ""
        except Exception:
            return None
        finally:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass


class MacOSClipboardAdapter(ClipboardAdapter):
    def __init__(self) -> None:
        self._appkit = None
        try:
            from AppKit import NSPasteboard, NSStringPboardType  # type: ignore

            self._appkit = (NSPasteboard, NSStringPboardType)
        except Exception:
            self._appkit = None

    def copy_to_clipboard(self, data: str) -> bool:
        if self._appkit:
            try:
                NSPasteboard, NSStringPboardType = self._appkit
                pb = NSPasteboard.generalPasteboard()
                pb.clearContents()
                pb.declareTypes_owner_([NSStringPboardType], None)
                return bool(pb.setString_forType_(data, NSStringPboardType))
            except Exception:
                pass
        try:
            subprocess.run(["pbcopy"], input=data.encode("utf-8"), check=True)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        if self._appkit:
            try:
                NSPasteboard, NSStringPboardType = self._appkit
                pb = NSPasteboard.generalPasteboard()
                data = pb.stringForType_(NSStringPboardType)
                return str(data) if data is not None else ""
            except Exception:
                pass
        try:
            result = subprocess.run(["pbpaste"], capture_output=True, check=True)
            return result.stdout.decode("utf-8", errors="ignore")
        except Exception:
            return None


class LinuxClipboardAdapter(ClipboardAdapter):
    def __init__(self) -> None:
        self._fallback = PyperclipClipboardAdapter()

    def copy_to_clipboard(self, data: str) -> bool:
        return self._fallback.copy_to_clipboard(data)

    def clear_clipboard(self) -> bool:
        return self._fallback.clear_clipboard()

    def get_clipboard_content(self) -> Optional[str]:
        return self._fallback.get_clipboard_content()


def create_clipboard_adapter() -> ClipboardAdapter:
    system = platform.system().lower()

    if system == "windows":
        try:
            return WindowsClipboardAdapter()
        except Exception:
            return PyperclipClipboardAdapter()

    if system == "darwin":
        return MacOSClipboardAdapter()

    if system == "linux":
        return LinuxClipboardAdapter()

    return PyperclipClipboardAdapter()