from src.core.security import SecretHolder


def main():
    print("\n=== SPRINT 7 / TEST 2 / MEMORY PROTECTION DEMO ===")

    secret = b"MySensitivePassword123!"
    holder = SecretHolder(secret)

    print("1. Secret loaded into protected holder")
    print("2. Extracted bytes length =", len(holder.get_data()))
    holder.wipe()
    print("3. Secret wiped")
    print("RESULT: OK — secure memory wipe demo completed")


if __name__ == "__main__":
    main()