from src.core.security import PanicConfig, PanicMode


class DummyAuth:
    def __init__(self):
        self.logged_out = False

    def logout(self):
        self.logged_out = True


class DummyClipboard:
    def __init__(self):
        self.cleared = False
        self.reason = None

    def clear_clipboard(self, reason="manual"):
        self.cleared = True
        self.reason = reason


class DummyAudit:
    def __init__(self):
        self.events = []

    def log_event(self, **kwargs):
        self.events.append(kwargs)


class DummyWindow:
    def __init__(self):
        self.calls = []

    def handle_panic_ui(self, close_app=False):
        self.calls.append(close_app)


def test_panic_mode_clears_clipboard_and_logs_out():
    auth = DummyAuth()
    clipboard = DummyClipboard()

    panic = PanicMode(
        config=PanicConfig(),
        auth_manager=auth,
        clipboard_service=clipboard,
        audit_logger=None,
        main_window=None,
        secret_wiper=None,
    )

    panic.activate(method="test")

    assert auth.logged_out is True
    assert clipboard.cleared is True
    assert clipboard.reason == "panic"


def test_panic_mode_logs_event():
    auth = DummyAuth()
    clipboard = DummyClipboard()
    audit = DummyAudit()

    panic = PanicMode(
        config=PanicConfig(),
        auth_manager=auth,
        clipboard_service=clipboard,
        audit_logger=audit,
        main_window=None,
        secret_wiper=None,
    )

    panic.activate(method="hotkey")

    assert len(audit.events) == 1
    assert audit.events[0]["event_type"] == "PANIC_MODE_ACTIVATED"


def test_panic_mode_calls_secret_wiper():
    called = {"wipe": False}

    def wipe():
        called["wipe"] = True

    panic = PanicMode(
        config=PanicConfig(),
        auth_manager=DummyAuth(),
        clipboard_service=DummyClipboard(),
        audit_logger=None,
        main_window=None,
        secret_wiper=wipe,
    )

    panic.activate(method="test")
    assert called["wipe"] is True


def test_panic_mode_calls_window_handler():
    window = DummyWindow()

    panic = PanicMode(
        config=PanicConfig(close_application=True),
        auth_manager=DummyAuth(),
        clipboard_service=DummyClipboard(),
        audit_logger=None,
        main_window=window,
        secret_wiper=None,
    )

    panic.activate(method="tray")
    assert window.calls == [True]