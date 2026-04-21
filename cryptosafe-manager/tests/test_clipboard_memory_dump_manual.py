import os

import pytest


def test_manual_memory_dump_scan():
    dump_path = os.getenv("CRYPTOSAFE_DUMP_PATH")
    secret = os.getenv("CRYPTOSAFE_TEST_SECRET")

    if not dump_path or not secret:
        pytest.skip("Manual dump test skipped: CRYPTOSAFE_DUMP_PATH / CRYPTOSAFE_TEST_SECRET not set")

    assert os.path.exists(dump_path), f"Dump file not found: {dump_path}"

    with open(dump_path, "rb") as f:
        raw = f.read()

    utf8 = secret.encode("utf-8")
    utf16 = secret.encode("utf-16le")

    assert utf8 not in raw, "Secret found in dump as UTF-8"
    assert utf16 not in raw, "Secret found in dump as UTF-16LE"