from __future__ import annotations

import os
import sys
import time
import ctypes
import threading
from dataclasses import dataclass
from typing import Optional

from src.core.utils import secure_zero_bytes

try:
    import keyring
except Exception:
    keyring = None


@dataclass
class CachePolicy:
    idle_timeout_seconds: int = 3600
    clear_on_focus_loss: bool = True
    clear_on_minimize: bool = True


class SecureKeyCache:

    def __init__(self, policy: Optional[CachePolicy] = None) -> None:
        self.policy = policy or CachePolicy()
        self._lock = threading.RLock()
        self._key: Optional[bytearray] = None
        self._login_at: Optional[float] = None
        self._last_activity_at: Optional[float] = None
        self._mlock_ok = False

    def set_key(self, key: bytes) -> None:
        with self._lock:
            self.clear()
            self._key = bytearray(key)
            self._login_at = time.time()
            self._last_activity_at = time.time()
            self._mlock_ok = self._try_lock_memory(self._key)

    def get_key(self) -> Optional[bytes]:
        with self._lock:
            if self._key is None:
                return None
            if self.is_expired():
                self.clear()
                return None
            self._last_activity_at = time.time()
            return bytes(self._key)

    def touch(self) -> None:
        with self._lock:
            self._last_activity_at = time.time()

    def is_expired(self) -> bool:
        if self._key is None or self._last_activity_at is None:
            return True
        return (time.time() - self._last_activity_at) > self.policy.idle_timeout_seconds

    def clear(self) -> None:
        with self._lock:
            if self._key is not None:
                self._try_unlock_memory(self._key)
                secure_zero_bytes(self._key)
                self._key = None
            self._login_at = None
            self._last_activity_at = None
            self._mlock_ok = False

    @property
    def login_at(self) -> Optional[float]:
        return self._login_at

    @property
    def last_activity_at(self) -> Optional[float]:
        return self._last_activity_at

    def _try_lock_memory(self, buf: bytearray) -> bool:
        try:
            if os.name == "posix":
                libc = ctypes.CDLL(None)
                arr = (ctypes.c_char * len(buf)).from_buffer(buf)
                return libc.mlock(ctypes.addressof(arr), len(buf)) == 0
            if os.name == "nt":

                return False
        except Exception:
            return False
        return False

    def _try_unlock_memory(self, buf: bytearray) -> bool:
        try:
            if os.name == "posix":
                libc = ctypes.CDLL(None)
                arr = (ctypes.c_char * len(buf)).from_buffer(buf)
                return libc.munlock(ctypes.addressof(arr), len(buf)) == 0
        except Exception:
            return False
        return False


class OSKeyringStore:

    def __init__(self, service_name: str = "CryptoSafeManager") -> None:
        self.service_name = service_name

    def available(self) -> bool:
        return keyring is not None

    def store_secret(self, username: str, secret: str) -> bool:
        if keyring is None:
            return False
        try:
            keyring.set_password(self.service_name, username, secret)
            return True
        except Exception:
            return False

    def load_secret(self, username: str) -> Optional[str]:
        if keyring is None:
            return None
        try:
            return keyring.get_password(self.service_name, username)
        except Exception:
            return None

    def delete_secret(self, username: str) -> bool:
        if keyring is None:
            return False
        try:
            keyring.delete_password(self.service_name, username)
            return True
        except Exception:
            return False