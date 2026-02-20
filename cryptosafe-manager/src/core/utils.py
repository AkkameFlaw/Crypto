from __future__ import annotations

import ctypes
import os
import re
from dataclasses import dataclass
from typing import Optional


def secure_zero_bytes(b: bytearray) -> None:

    if not isinstance(b, (bytearray, memoryview)):
        return
    if isinstance(b, memoryview):
        if not b.readonly and b.contiguous:
            buf = (ctypes.c_char * len(b)).from_buffer(b)
            ctypes.memset(ctypes.addressof(buf), 0, len(b))
        return
    buf = (ctypes.c_char * len(b)).from_buffer(b)
    ctypes.memset(ctypes.addressof(buf), 0, len(b))


def minimal_path_permissions(path: str) -> None:

    try:
        if os.name == "posix" and os.path.exists(path):
            os.chmod(path, 0o600)
    except Exception:
        pass


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    message: str = ""


_SAFE_TEXT_RE = re.compile(r"^[\w\s\-\.\,\:\;\@\+\(\)\[\]\{\}\/\\\?\#\&\=\%]{0,500}$", re.UNICODE)


def validate_safe_text(value: str, field: str, max_len: int = 255, allow_empty: bool = True) -> ValidationResult:
    if value is None:
        return ValidationResult(False, f"{field}: missing")
    v = value.strip()
    if not v and not allow_empty:
        return ValidationResult(False, f"{field}: required")
    if len(v) > max_len:
        return ValidationResult(False, f"{field}: too long")
    # allow empty
    if not v:
        return ValidationResult(True, "")
    if not _SAFE_TEXT_RE.match(v):
        return ValidationResult(False, f"{field}: invalid characters")
    return ValidationResult(True, "")
