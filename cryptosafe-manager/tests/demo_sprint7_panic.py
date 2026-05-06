from src.core.security import PanicConfig, PanicMode


class DummyAuth:
    def __init__(self):
        self.logged_out = False

    def logout(self):
        self.logged_out = True


class DummyClipboard:
    def __init__(self):
        self.cleared = False

    def clear_clipboard(self, reason="manual"):
        self.cleared = True


def main():
    print("\n=== SPRINT 7 / TEST 4 / PANIC MODE DEMO ===")

    auth = DummyAuth()
    clipboard = DummyClipboard()
    calls = {"wiped": False}

    def wipe():
        calls["wiped"] = True

    panic = PanicMode(
        config=PanicConfig(close_application=False, show_fake_error=False),
        auth_manager=auth,
        clipboard_service=clipboard,
        secret_wiper=wipe,
    )

    panic.activate(method="demo")
    print("auth.logged_out =", auth.logged_out)
    print("clipboard.cleared =", clipboard.cleared)
    print("memory_wiped =", calls["wiped"])

    if auth.logged_out and clipboard.cleared and calls["wiped"]:
        print("RESULT: OK — panic mode completed")
    else:
        print("RESULT: FAIL — panic mode incomplete")


if __name__ == "__main__":
    main()