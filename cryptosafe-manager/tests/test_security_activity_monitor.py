import time

from src.core.security import ActivityMonitor, build_profile_config


def test_build_profile_standard():
    profile = build_profile_config("standard")
    assert profile.name == "Standard"
    assert profile.auto_lock_seconds == 300


def test_build_profile_enhanced():
    profile = build_profile_config("enhanced")
    assert profile.name == "Enhanced"
    assert profile.lock_on_focus_loss is True


def test_build_profile_paranoid():
    profile = build_profile_config("paranoid")
    assert profile.name == "Paranoid"
    assert profile.close_on_panic is True


def test_activity_monitor_records_activity():
    events = []

    def lock_callback():
        events.append("LOCK")

    monitor = ActivityMonitor(lock_callback=lock_callback, profile=build_profile_config("standard"), check_interval=0.1)
    idle_before = monitor.get_idle_time()
    time.sleep(0.05)
    monitor.record_activity()
    idle_after = monitor.get_idle_time()

    assert idle_after <= idle_before + 0.2
    assert events == []


def test_activity_monitor_auto_lock_triggers():
    events = []

    def lock_callback():
        events.append("LOCK")

    profile = build_profile_config("standard")
    profile = profile.__class__(
        name=profile.name,
        auto_lock_seconds=1,
        lock_on_focus_loss=profile.lock_on_focus_loss,
        clear_clipboard_on_lock=profile.clear_clipboard_on_lock,
        sensitivity=profile.sensitivity,
        close_on_panic=profile.close_on_panic,
    )

    monitor = ActivityMonitor(lock_callback=lock_callback, profile=profile, check_interval=0.1)
    monitor.start()
    try:
        time.sleep(1.6)
    finally:
        monitor.stop()

    assert "LOCK" in events


def test_activity_monitor_focus_loss_triggers_when_enabled():
    events = []

    def lock_callback():
        events.append("LOCK")

    profile = build_profile_config("enhanced")
    monitor = ActivityMonitor(lock_callback=lock_callback, profile=profile, check_interval=0.1)
    monitor.set_focus(False)
    monitor.force_lock_check()

    assert "LOCK" in events