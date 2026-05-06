from src.core.security import build_profile_config


def test_standard_profile_values():
    p = build_profile_config("standard")
    assert p.name == "Standard"
    assert p.auto_lock_seconds == 300
    assert p.lock_on_focus_loss is False
    assert p.clear_clipboard_on_lock is True


def test_enhanced_profile_values():
    p = build_profile_config("enhanced")
    assert p.name == "Enhanced"
    assert p.auto_lock_seconds == 120
    assert p.lock_on_focus_loss is True
    assert p.clear_clipboard_on_lock is True


def test_paranoid_profile_values():
    p = build_profile_config("paranoid")
    assert p.name == "Paranoid"
    assert p.auto_lock_seconds == 60
    assert p.lock_on_focus_loss is True
    assert p.close_on_panic is True


def test_unknown_profile_falls_back_to_standard():
    p = build_profile_config("unknown")
    assert p.name == "Standard"