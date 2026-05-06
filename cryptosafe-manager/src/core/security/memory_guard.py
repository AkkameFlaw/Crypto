from __future__ import annotations

import ctypes
import platform
import threading
from typing import Any


class SecureMemory:
    def __init__(self) -> None:
        self.system = platform.system()
        self._setup_platform_functions()

    def _setup_platform_functions(self) -> None:
        self.kernel32 = None
        self.libc = None

        try:
            if self.system == "Windows":
                self.kernel32 = ctypes.windll.kernel32
            else:
                self.libc = ctypes.CDLL(None)
        except Exception:
            self.kernel32 = None
            self.libc = None

    def allocate_secure(self, size: int):
        buf = (ctypes.c_ubyte * size)()
        self.lock_memory(buf, size)
        return buf

    def lock_memory(self, buffer: Any, size: int) -> bool:
        try:
            if self.system == "Windows" and self.kernel32:
                return bool(self.kernel32.VirtualLock(ctypes.byref(buffer), ctypes.c_size_t(size)))
            if self.libc and hasattr(self.libc, "mlock"):
                return self.libc.mlock(ctypes.byref(buffer), ctypes.c_size_t(size)) == 0
        except Exception:
            return False
        return False

    def unlock_memory(self, buffer: Any, size: int) -> bool:
        try:
            if self.system == "Windows" and self.kernel32:
                return bool(self.kernel32.VirtualUnlock(ctypes.byref(buffer), ctypes.c_size_t(size)))
            if self.libc and hasattr(self.libc, "munlock"):
                return self.libc.munlock(ctypes.byref(buffer), ctypes.c_size_t(size)) == 0
        except Exception:
            return False
        return False

    def secure_zero(self, buffer: Any, size: int) -> None:
        try:
            if isinstance(buffer, bytearray):
                for i in range(len(buffer)):
                    buffer[i] = 0
                return

            if self.system == "Windows" and self.kernel32 and hasattr(self.kernel32, "RtlSecureZeroMemory"):
                self.kernel32.RtlSecureZeroMemory(ctypes.byref(buffer), ctypes.c_size_t(size))
                return

            if self.libc and hasattr(self.libc, "memset"):
                self.libc.memset(ctypes.byref(buffer), 0, ctypes.c_size_t(size))
                return

            ctypes.memset(ctypes.byref(buffer), 0, size)
        except Exception:
            pass

    def free_secure(self, buffer: Any, size: int) -> None:
        try:
            self.secure_zero(buffer, size)
        finally:
            try:
                self.unlock_memory(buffer, size)
            except Exception:
                pass


def secure_zero_buffer(data: bytes | bytearray | memoryview | None) -> None:
    if data is None:
        return
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
        return
    if isinstance(data, memoryview):
        try:
            data[:] = b"\x00" * len(data)
        except Exception:
            pass


class SecretHolder:
    _registry_lock = threading.RLock()
    _registry: set["SecretHolder"] = set()

    def __init__(self, data: bytes):
        self._memory = SecureMemory()
        self._size = max(1, len(data))
        self._buffer = self._memory.allocate_secure(self._size)
        self._destroyed = False

        ctypes.memmove(self._buffer, data, len(data))
        with self._registry_lock:
            self._registry.add(self)

    def get_data(self) -> bytes:
        if self._destroyed:
            return b""
        return bytes(self._buffer[: self._size])

    def wipe(self) -> None:
        if self._destroyed:
            return
        self._memory.free_secure(self._buffer, self._size)
        self._destroyed = True
        with self._registry_lock:
            self._registry.discard(self)

    @classmethod
    def wipe_all(cls) -> None:
        with cls._registry_lock:
            holders = list(cls._registry)
        for holder in holders:
            try:
                holder.wipe()
            except Exception:
                pass

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass