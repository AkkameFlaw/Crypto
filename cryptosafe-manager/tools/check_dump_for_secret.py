import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dump_path")
    parser.add_argument("secret")
    args = parser.parse_args()

    dump_file = Path(args.dump_path)
    if not dump_file.exists():
        print(f"[ERROR] Dump file not found: {dump_file}")
        return 2

    dump_bytes = dump_file.read_bytes()
    secret_utf8 = args.secret.encode("utf-8")
    secret_utf16 = args.secret.encode("utf-16le")

    found = False

    pos_utf8 = dump_bytes.find(secret_utf8)
    if pos_utf8 != -1:
        print(f"[FAIL] Secret found as utf-8 at byte offset {pos_utf8}")
        found = True
    else:
        print("[OK] Secret not found as utf-8")

    pos_utf16 = dump_bytes.find(secret_utf16)
    if pos_utf16 != -1:
        print(f"[FAIL] Secret found as utf-16le at byte offset {pos_utf16}")
        found = True
    else:
        print("[OK] Secret not found as utf-16le")

    if found:
        print("[RESULT] Plaintext secret was found in process memory dump.")
        return 1

    print("[RESULT] Plaintext secret was NOT found in checked encodings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())