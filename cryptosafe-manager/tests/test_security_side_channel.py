from src.core.security import (
    constant_time_compare_bytes,
    constant_time_compare_text,
    normalized_security_compare,
    measure_compare_timing,
)


def test_constant_time_compare_bytes_equal():
    assert constant_time_compare_bytes(b"secret123", b"secret123") is True


def test_constant_time_compare_bytes_not_equal():
    assert constant_time_compare_bytes(b"secret123", b"secret124") is False


def test_constant_time_compare_text_equal():
    assert constant_time_compare_text("master-password", "master-password") is True


def test_constant_time_compare_text_not_equal():
    assert constant_time_compare_text("master-password", "wrong-password") is False


def test_normalized_security_compare_strips_spaces():
    assert normalized_security_compare("  abc  ", "abc") is True


def test_measure_compare_timing_returns_stats():
    result = measure_compare_timing(
        constant_time_compare_text,
        [
            ("aaaaaaaa", "aaaaaaaa"),
            ("aaaaaaaa", "bbbbbbbb"),
            ("short", "longer"),
        ],
        iterations=1000,
    )
    assert "min_ns" in result
    assert "max_ns" in result
    assert "avg_ns" in result
    assert "stdev_ns" in result
    assert result["min_ns"] >= 0