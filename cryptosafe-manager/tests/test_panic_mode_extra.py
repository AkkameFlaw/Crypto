from src.core.security.panic_mode import PanicConfig, PanicMode


class DummyClipboard:
    def __init__(self):
        self.calls = []

    def clear_clipboard(self, reason="manual"):
        self.calls.append(reason)


class DummyClipboardNoArgs:
    def __init__(self):
        self.called = False

    def clear_clipboard(self):
        self.called = True


class DummyAuth:
    def __init__(self):
        self.logged_out = False

    def logout(self):
        self.logged_out = True


class DummyAuditKw:
    def __init__(self):
        self.calls = []

    def log_event(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class DummyAuditPos:
    def __init__(self):
        self.calls = []

    def log_event(self, *args, **kwargs):
        if kwargs:
            raise TypeError("positional only simulation")
        self.calls.append((args, kwargs))


class DummyWindowKw:
    def __init__(self):
        self.handled = False
        self.closed = None
        self.withdrawn = False

    def handle_panic_ui(self, close_app=False):
        self.handled = True
        self.closed = close_app

    def withdraw(self):
        self.withdrawn = True

    def after(self, *_args, **_kwargs):
        pass

    def on_exit(self):
        pass


class DummyWindowPos:
    def __init__(self):
        self.calls = []
        self.withdrawn = False

    def handle_panic_ui(self, close_app):
        self.calls.append(close_app)

    def withdraw(self):
        self.withdrawn = True

    def after(self, *_args, **_kwargs):
        pass

    def on_exit(self):
        pass


def test_panic_activate_full_flow():
    clipboard = DummyClipboard()
    auth = DummyAuth()
    audit = DummyAuditKw()
    win = DummyWindowKw()
    wiped = {"ok": False}

    def wipe():
        wiped["ok"] = True

    panic = PanicMode(
        PanicConfig(
            clear_clipboard=True,
            wipe_secrets=True,
            lock_vault=True,
            close_application=False,
        ),
        auth_manager=auth,
        clipboard_service=clipboard,
        audit_logger=audit,
        main_window=win,
        secret_wiper=wipe,
    )

    panic.activate("hotkey")

    assert panic.activated is True
    assert panic.last_method == "hotkey"
    assert clipboard.calls == ["panic"]
    assert auth.logged_out is True
    assert wiped["ok"] is True
    assert win.handled is True
    assert audit.calls


def test_panic_reset():
    panic = PanicMode(PanicConfig())
    panic.activate("button")
    assert panic.activated is True

    panic.reset()
    assert panic.activated is False
    assert panic.last_method is None


def test_panic_clipboard_typeerror_fallback():
    clipboard = DummyClipboardNoArgs()
    panic = PanicMode(
        PanicConfig(clear_clipboard=True),
        clipboard_service=clipboard,
    )
    panic.activate("tray")
    assert clipboard.called is True


def test_panic_log_event_typeerror_fallback():
    audit = DummyAuditPos()
    panic = PanicMode(
        PanicConfig(),
        audit_logger=audit,
    )
    panic.activate("tray")
    assert audit.calls


def test_panic_handle_ui_positional_fallback():
    win = DummyWindowPos()
    panic = PanicMode(
        PanicConfig(close_application=True),
        main_window=win,
    )
    panic.activate("hotkey")
    assert win.calls == [True]


def test_panic_handle_ui_simple_withdraw():
    class BareWindow:
        def __init__(self):
            self.withdrawn = False
            self.scheduled = False

        def withdraw(self):
            self.withdrawn = True

        def after(self, *_args, **_kwargs):
            self.scheduled = True

        def on_exit(self):
            pass

    win = BareWindow()
    panic = PanicMode(
        PanicConfig(close_application=True),
        main_window=win,
    )
    panic.activate("hotkey")
    assert win.withdrawn is True
    assert win.scheduled is True