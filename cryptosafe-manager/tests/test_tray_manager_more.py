import types

import src.core.security.tray_manager as tm


class DummyMenu:
    def __init__(self, *items):
        self.items = items


class DummyItem:
    def __init__(self, text, action):
        self.text = text
        self.action = action


class DummyIcon:
    def __init__(self, name, icon, title, menu):
        self.name = name
        self.icon = icon
        self.title = title
        self.menu = menu
        self.notified = []
        self.stopped = False
        self.updated = False

    def run(self):
        return None

    def stop(self):
        self.stopped = True

    def notify(self, message, title):
        self.notified.append((title, message))

    def update_menu(self):
        self.updated = True


class DummyImageObj:
    pass


class DummyImageModule:
    @staticmethod
    def new(*_args, **_kwargs):
        return DummyImageObj()


class DummyDrawObj:
    def ellipse(self, *_args, **_kwargs):
        pass

    def rectangle(self, *_args, **_kwargs):
        pass

    def arc(self, *_args, **_kwargs):
        pass


class DummyImageDrawModule:
    @staticmethod
    def Draw(_image):
        return DummyDrawObj()


def patch_tray(monkeypatch):
    fake_pystray = types.SimpleNamespace(Icon=DummyIcon, Menu=DummyMenu)
    monkeypatch.setattr(tm, "pystray", fake_pystray)
    monkeypatch.setattr(tm, "Item", DummyItem)
    monkeypatch.setattr(tm, "Image", DummyImageModule)
    monkeypatch.setattr(tm, "ImageDraw", DummyImageDrawModule)


def test_tray_available_false_when_deps_missing(monkeypatch):
    monkeypatch.setattr(tm, "pystray", None)
    monkeypatch.setattr(tm, "Item", None)
    monkeypatch.setattr(tm, "Image", None)
    monkeypatch.setattr(tm, "ImageDraw", None)

    tray = tm.TrayManager(
        on_show_window=lambda: None,
        on_lock=lambda: None,
        on_unlock=lambda: None,
        on_quick_search=lambda: None,
        on_clear_clipboard=lambda: None,
        on_panic=lambda: None,
        on_settings=lambda: None,
        on_exit=lambda: None,
    )

    assert tray.available is False
    assert tray._build_menu() is None


def test_tray_start_does_nothing_if_unavailable(monkeypatch):
    monkeypatch.setattr(tm, "pystray", None)
    monkeypatch.setattr(tm, "Item", None)
    monkeypatch.setattr(tm, "Image", None)
    monkeypatch.setattr(tm, "ImageDraw", None)

    tray = tm.TrayManager(
        on_show_window=lambda: None,
        on_lock=lambda: None,
        on_unlock=lambda: None,
        on_quick_search=lambda: None,
        on_clear_clipboard=lambda: None,
        on_panic=lambda: None,
        on_settings=lambda: None,
        on_exit=lambda: None,
    )

    tray.start()
    assert tray.icon is None


def test_tray_refresh_icon_without_icon(monkeypatch):
    patch_tray(monkeypatch)

    tray = tm.TrayManager(
        on_show_window=lambda: None,
        on_lock=lambda: None,
        on_unlock=lambda: None,
        on_quick_search=lambda: None,
        on_clear_clipboard=lambda: None,
        on_panic=lambda: None,
        on_settings=lambda: None,
        on_exit=lambda: None,
    )

    tray._refresh_icon()
    assert tray.icon is None


def test_tray_refresh_icon_with_icon(monkeypatch):
    patch_tray(monkeypatch)

    tray = tm.TrayManager(
        on_show_window=lambda: None,
        on_lock=lambda: None,
        on_unlock=lambda: None,
        on_quick_search=lambda: None,
        on_clear_clipboard=lambda: None,
        on_panic=lambda: None,
        on_settings=lambda: None,
        on_exit=lambda: None,
    )
    tray.start()
    tray._refresh_icon()

    assert tray.icon is not None
    assert tray.icon.updated is True


def test_tray_tooltip_locked_and_empty(monkeypatch):
    patch_tray(monkeypatch)

    tray = tm.TrayManager(
        on_show_window=lambda: None,
        on_lock=lambda: None,
        on_unlock=lambda: None,
        on_quick_search=lambda: None,
        on_clear_clipboard=lambda: None,
        on_panic=lambda: None,
        on_settings=lambda: None,
        on_exit=lambda: None,
    )

    tray.update_state(
        locked=True,
        clipboard_active=False,
        clipboard_remaining=0,
        security_profile="Paranoid",
        crypto_busy=False,
    )

    tooltip = tray._build_tooltip()
    assert "Locked" in tooltip
    assert "Clipboard: empty" in tooltip
    assert "Paranoid" in tooltip
    assert "Crypto: idle" in tooltip


def test_tray_build_icon_multiple_states(monkeypatch):
    patch_tray(monkeypatch)

    tray = tm.TrayManager(
        on_show_window=lambda: None,
        on_lock=lambda: None,
        on_unlock=lambda: None,
        on_quick_search=lambda: None,
        on_clear_clipboard=lambda: None,
        on_panic=lambda: None,
        on_settings=lambda: None,
        on_exit=lambda: None,
    )

    tray.update_state(locked=True, security_profile="Standard", crypto_busy=False)
    assert tray._build_icon() is not None

    tray.update_state(locked=False, security_profile="Enhanced", crypto_busy=False)
    assert tray._build_icon() is not None

    tray.update_state(locked=False, security_profile="Paranoid", crypto_busy=True)
    assert tray._build_icon() is not None