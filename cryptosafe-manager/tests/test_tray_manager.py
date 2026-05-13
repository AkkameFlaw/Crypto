import pytest

from src.core.security import tray_manager as tm


@pytest.mark.skipif(tm.pystray is None or tm.Image is None or tm.ImageDraw is None, reason="tray deps unavailable")
def test_tray_manager_can_be_created():
    calls = []

    tray = tm.TrayManager(
        on_show_window=lambda: calls.append("show"),
        on_lock=lambda: calls.append("lock"),
        on_unlock=lambda: calls.append("unlock"),
        on_quick_search=lambda: calls.append("search"),
        on_clear_clipboard=lambda: calls.append("clear"),
        on_panic=lambda: calls.append("panic"),
        on_settings=lambda: calls.append("settings"),
        on_exit=lambda: calls.append("exit"),
    )

    assert tray is not None
    assert tray.available is True


@pytest.mark.skipif(tm.pystray is None or tm.Image is None or tm.ImageDraw is None, reason="tray deps unavailable")
def test_tray_manager_updates_state():
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
        locked=False,
        clipboard_active=True,
        clipboard_remaining=12,
        security_profile="Enhanced",
        crypto_busy=True,
    )

    assert tray.state.locked is False
    assert tray.state.clipboard_active is True
    assert tray.state.clipboard_remaining == 12
    assert tray.state.security_profile == "Enhanced"
    assert tray.state.crypto_busy is True


@pytest.mark.skipif(tm.pystray is None or tm.Image is None or tm.ImageDraw is None, reason="tray deps unavailable")
def test_tray_manager_builds_tooltip_and_icon():
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

    tooltip = tray._build_tooltip()
    icon = tray._build_icon()

    assert isinstance(tooltip, str)
    assert "CryptoSafe Manager" in tooltip
    assert icon is not None


@pytest.mark.skipif(tm.pystray is None or tm.Image is None or tm.ImageDraw is None, reason="tray deps unavailable")
def test_tray_manager_builds_menu():
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

    menu = tray._build_menu()
    assert menu is not None