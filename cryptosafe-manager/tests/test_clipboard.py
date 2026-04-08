import time

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.events import EventBus


class FakeClipboardAdapter:
    def __init__(self):
        self.value = ""

    def copy_to_clipboard(self, data: str) -> bool:
        self.value = data
        return True

    def clear_clipboard(self) -> bool:
        self.value = ""
        return True

    def get_clipboard_content(self):
        return self.value


class FakeAuth:
    def get_encryption_key(self):
        return b"x" * 32


def test_clipboard_copy_and_clear():
    adapter = FakeClipboardAdapter()
    service = ClipboardService(adapter, EventBus(), timeout_seconds=30, auth_manager=FakeAuth())

    ok = service.copy_to_clipboard("secret", data_type="password", source_entry_id=1)
    assert ok is True
    assert adapter.value == "secret"

    status = service.get_clipboard_status()
    assert status["active"] is True
    assert status["data_type"] == "password"

    service.clear_clipboard("manual")
    assert adapter.value == ""
    assert service.get_clipboard_status()["active"] is False


def test_clipboard_auto_clear():
    adapter = FakeClipboardAdapter()
    service = ClipboardService(adapter, EventBus(), timeout_seconds=5, auth_manager=FakeAuth())

    ok = service.copy_to_clipboard("secret")
    assert ok is True
    service.accelerate_clear(seconds=1)
    time.sleep(1.3)

    assert adapter.value == ""
    assert service.get_clipboard_status()["active"] is False