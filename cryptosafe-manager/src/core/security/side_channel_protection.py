from __future__ import annotations

import secrets
import statistics
import time
from typing import Iterable


def _to_bytes(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", errors="ignore")
    raise TypeError("Unsupported value type for constant-time comparison")


def _normalize_pair(left: bytes, right: bytes) -> tuple[bytes, bytes]:
    max_len = max(len(left), len(right), 1)
    return left.ljust(max_len, b"\x00"), right.ljust(max_len, b"\x00")


def constant_time_compare_bytes(left: bytes | bytearray, right: bytes | bytearray) -> bool:
    l_bytes = _to_bytes(left)
    r_bytes = _to_bytes(right)
    nl, nr = _normalize_pair(l_bytes, r_bytes)
    result = secrets.compare_digest(nl, nr)
    return result and len(l_bytes) == len(r_bytes)


def constant_time_compare_text(left: str, right: str) -> bool:
    l_bytes = _to_bytes(left)
    r_bytes = _to_bytes(right)
    nl, nr = _normalize_pair(l_bytes, r_bytes)
    result = secrets.compare_digest(nl, nr)
    return result and len(l_bytes) == len(r_bytes)


def normalized_security_compare(left: str, right: str) -> bool:
    return constant_time_compare_text(left.strip(), right.strip())


def measure_compare_timing(
    compare_fn,
    samples: Iterable[tuple[bytes | bytearray | str, bytes | bytearray | str]],
    iterations: int = 1000,
) -> dict[str, float]:
    timings: list[float] = []

    for left, right in samples:
        started = time.perf_counter_ns()
        for _ in range(iterations):
            compare_fn(left, right)
        elapsed = time.perf_counter_ns() - started
        timings.append(elapsed / iterations)

    return {
        "min_ns": min(timings) if timings else 0.0,
        "max_ns": max(timings) if timings else 0.0,
        "avg_ns": statistics.mean(timings) if timings else 0.0,
        "stdev_ns": statistics.pstdev(timings) if len(timings) > 1 else 0.0,
    }