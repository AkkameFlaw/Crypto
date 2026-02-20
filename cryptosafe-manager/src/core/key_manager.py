from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

from .utils import minimal_path_permissions, secure_zero_bytes


@dataclass
class KdfParams:
    iterations: int = 120_000
    dklen: int = 32
    hash_name: str = "sha256"


class KeyManager:

    def __init__(self, params: Optional[KdfParams] = None) -> None:
        self.params = params or KdfParams()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        if not isinstance(password, str) or not password:
            raise ValueError("password required")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
            raise ValueError("salt must be >= 8 bytes")

        pw_bytes = bytearray(password.encode("utf-8"))
        try:
            key = hashlib.pbkdf2_hmac(
                self.params.hash_name,
                bytes(pw_bytes),
                bytes(salt),
                self.params.iterations,
                dklen=self.params.dklen,
            )
            return key
        finally:
            secure_zero_bytes(pw_bytes)

    def store_key(self, *_args, **_kwargs) -> None:
        return None

    def load_key(self, *_args, **_kwargs) -> Optional[bytes]:
        return None

    def save_params_to_file(self, path: str) -> None:
        data = {
            "iterations": self.params.iterations,
            "dklen": self.params.dklen,
            "hash_name": self.params.hash_name,
        }
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        minimal_path_permissions(path)

    @staticmethod
    def load_params_from_file(path: str) -> Optional[KdfParams]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            return KdfParams(
                iterations=int(d.get("iterations", 120_000)),
                dklen=int(d.get("dklen", 32)),
                hash_name=str(d.get("hash_name", "sha256")),
            )
        except Exception:
            return None
