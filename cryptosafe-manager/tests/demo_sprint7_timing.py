from src.core.security import constant_time_compare_text, measure_compare_timing


def main():
    print("\n=== SPRINT 7 / TEST 1 / TIMING DEMO ===")

    samples = [
        ("aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa"),
        ("aaaaaaaaaaaaaaaa", "aaaaaaaabaaaaaaa"),
        ("aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"),
        ("short", "longer_value"),
    ]

    result = measure_compare_timing(constant_time_compare_text, samples, iterations=5000)
    print(result)
    print("RESULT: OK — timing demo completed")


if __name__ == "__main__":
    main()