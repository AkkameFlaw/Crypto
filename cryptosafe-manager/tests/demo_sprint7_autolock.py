import time

from src.core.security import ActivityMonitor, build_profile_config


def main():
    print("\n=== SPRINT 7 / TEST 3 / AUTO-LOCK DEMO ===")

    events = []

    def lock_callback():
        events.append("LOCK")
        print("LOCK CALLBACK TRIGGERED")

    monitor = ActivityMonitor(
        lock_callback=lock_callback,
        warning_callback=lambda sec: print(f"WARNING: lock in {sec}s"),
        profile=build_profile_config("paranoid"),
        check_interval=0.5,
    )
    monitor.profile = monitor.profile.__class__(
        name=monitor.profile.name,
        auto_lock_seconds=3,
        lock_on_focus_loss=monitor.profile.lock_on_focus_loss,
        clear_clipboard_on_lock=monitor.profile.clear_clipboard_on_lock,
        sensitivity=monitor.profile.sensitivity,
        close_on_panic=monitor.profile.close_on_panic,
    )

    monitor.start()
    print("1. Waiting 5 seconds without activity...")
    time.sleep(5)
    monitor.stop()

    if "LOCK" in events:
        print("RESULT: OK — auto-lock triggered")
    else:
        print("RESULT: FAIL — auto-lock not triggered")


if __name__ == "__main__":
    main()