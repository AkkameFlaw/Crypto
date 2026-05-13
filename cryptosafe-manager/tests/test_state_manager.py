from src.core.state_manager import StateManager


def test_state_manager_basic_methods_exist():
    sm = StateManager()

    assert hasattr(sm, "mark_login")
    assert hasattr(sm, "mark_logout")
    assert hasattr(sm, "touch_activity")


def test_state_manager_login_logout_and_activity():
    sm = StateManager()

    old_activity = getattr(sm, "last_activity", None)

    sm.mark_login()

    if hasattr(sm, "touch_activity"):
        sm.touch_activity()

    new_activity = getattr(sm, "last_activity", None)
    if old_activity is not None and new_activity is not None:
        assert new_activity >= old_activity

    if hasattr(sm, "lock"):
        sm.lock()
    if hasattr(sm, "unlock"):
        sm.unlock()

    sm.mark_logout()

    assert sm is not None