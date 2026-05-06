from src.core.security import build_profile_config


def main():
    print("\n=== SPRINT 7 / TEST 5 / PROFILES DEMO ===")

    for name in ["standard", "enhanced", "paranoid"]:
        profile = build_profile_config(name)
        print(
            {
                "name": profile.name,
                "auto_lock_seconds": profile.auto_lock_seconds,
                "lock_on_focus_loss": profile.lock_on_focus_loss,
                "clear_clipboard_on_lock": profile.clear_clipboard_on_lock,
                "close_on_panic": profile.close_on_panic,
            }
        )

    print("RESULT: OK — security profiles loaded")


if __name__ == "__main__":
    main()