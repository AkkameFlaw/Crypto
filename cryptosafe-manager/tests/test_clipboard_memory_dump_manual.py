import os
import subprocess
import sys
from pathlib import Path


def test_manual_memory_dump_scan():

    dump_path = os.getenv("CRYPTOSAFE_DUMP_PATH")
    secret = os.getenv("CRYPTOSAFE_TEST_SECRET")

    assert dump_path, (
        "CRYPTOSAFE_DUMP_PATH is not set. "
        "Example: use a real .dmp path from Task Manager output."
    )
    assert secret, (
        "CRYPTOSAFE_TEST_SECRET is not set. "
        "Example: TEST_SECRET_9f3c2d1a_UNIQUE"
    )

    project_root = Path(__file__).resolve().parents[1]
    checker = project_root / "tools" / "check_dump_for_secret.py"

    assert checker.exists(), f"Checker script not found: {checker}"
    assert Path(dump_path).exists(), f"Dump file not found: {dump_path}"

    result = subprocess.run(
        [sys.executable, str(checker), dump_path, secret],
        capture_output=True,
        text=True,
    )

    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    assert result.returncode == 0, (
        "Plaintext secret was found in the dump or checker failed.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
