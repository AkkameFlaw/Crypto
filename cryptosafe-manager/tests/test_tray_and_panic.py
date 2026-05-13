from src.core.security.panic_mode import PanicConfig, PanicMode


class DummyClipboard:
    def __init__(self):
        self.cleared = False
        self.reasons = []

    def clear_clipboard(self, reason="manual"):
        self.cleared = True
        self.reasons.append(reason)


class DummyAuth:
    def __init__(self):
        self.logged_out = False

    def logout(self):
        self.logged_out = True


class DummyAudit:
    def __init__(self):
        self.events = []

    def log_event(self, *args, **kwargs):
        self.events.append((args, kwargs))


class DummyMainWindow:
    def __init__(self):
        self.handled = False
        self.close_app = None

    def handle_panic_ui(self, close_app=False):
        self.handled = True
        self.close_app = close_app


class DummyTrayManager:
    def __init__(self, *args, **kwargs):
        self.state = {}
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def update_state(self, **kwargs):
        self.state.update(kwargs)

    def show_notification(self, title, message):
        self.last_notification = (title, message)


def test_panic_mode_activation():
    clipboard = DummyClipboard()
    auth = DummyAuth()
    audit = DummyAudit()
    main = DummyMainWindow()
    wiped = {"done": False}

    def wipe():
        wiped["done"] = True

    panic = PanicMode(
        PanicConfig(
            close_application=False,
            clear_clipboard=True,
            wipe_secrets=True,
            lock_vault=True,
        ),
        auth_manager=auth,
        clipboard_service=clipboard,
        audit_logger=audit,
        main_window=main,
        secret_wiper=wipe,
    )

    panic.activate(method="hotkey")

    assert panic.activated is True
    assert panic.last_method == "hotkey"
    assert clipboard.cleared is True
    assert "panic" in clipboard.reasons
    assert auth.logged_out is True
    assert wiped["done"] is True
    assert main.handled is True
    assert audit.events


def test_panic_mode_reset():
    panic = PanicMode(PanicConfig())
    panic.activate(method="button")
    assert panic.activated is True

    panic.reset()
    assert panic.activated is False
    assert panic.last_method is None