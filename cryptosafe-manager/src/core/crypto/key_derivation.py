from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass, asdict
from typing import Optional

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


COMMON_WEAK_PATTERNS = {
    "password",
    "password123",
    "qwerty",
    "qwerty123",
    "123456",
    "12345678",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
}


@dataclass
class Argon2Config:
    time_cost: int = 3
    memory_cost: int = 65536   # 64 MiB
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16

    def validate(self) -> None:
        if self.time_cost < 3:
            raise ValueError("Argon2 time_cost must be >= 3")
        if self.memory_cost < 8192 or self.memory_cost > 262144:
            raise ValueError("Argon2 memory_cost out of safe range")
        if self.parallelism < 1 or self.parallelism > 16:
            raise ValueError("Argon2 parallelism out of safe range")
        if self.hash_len < 16 or self.hash_len > 64:
            raise ValueError("Argon2 hash_len out of safe range")
        if self.salt_len < 16 or self.salt_len > 64:
            raise ValueError("Argon2 salt_len out of safe range")


@dataclass
class PBKDF2Config:
    iterations: int = 100_000
    salt_len: int = 16
    dklen: int = 32

    def validate(self) -> None:
        if self.iterations < 100_000 or self.iterations > 5_000_000:
            raise ValueError("PBKDF2 iterations out of safe range")
        if self.salt_len < 16 or self.salt_len > 64:
            raise ValueError("PBKDF2 salt_len out of safe range")
        if self.dklen != 32:
            raise ValueError("PBKDF2 dklen must be 32 for AES-256 compatibility")


@dataclass
class PasswordPolicy:
    min_length: int = 12
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_special: bool = True

    def validate_password(self, password: str) -> tuple[bool, str]:
        if len(password) < self.min_length:
            return False, f"Password must be at least {self.min_length} characters long"
        lowered = password.lower()
        for pattern in COMMON_WEAK_PATTERNS:
            if pattern in lowered:
                return False, "Password contains a common weak pattern"
        if self.require_upper and not re.search(r"[A-Z]", password):
            return False, "Password must contain an uppercase letter"
        if self.require_lower and not re.search(r"[a-z]", password):
            return False, "Password must contain a lowercase letter"
        if self.require_digit and not re.search(r"\d", password):
            return False, "Password must contain a digit"
        if self.require_special and not re.search(r"[^A-Za-z0-9]", password):
            return False, "Password must contain a special character"
        return True, ""


class KeyManager:

    def __init__(
        self,
        argon2_config: Optional[Argon2Config] = None,
        pbkdf2_config: Optional[PBKDF2Config] = None,
        policy: Optional[PasswordPolicy] = None,
    ) -> None:
        self.argon2_config = argon2_config or Argon2Config()
        self.pbkdf2_config = pbkdf2_config or PBKDF2Config()
        self.policy = policy or PasswordPolicy()

        self.argon2_config.validate()
        self.pbkdf2_config.validate()

        self._argon2 = PasswordHasher(
            time_cost=self.argon2_config.time_cost,
            memory_cost=self.argon2_config.memory_cost,
            parallelism=self.argon2_config.parallelism,
            hash_len=self.argon2_config.hash_len,
            salt_len=self.argon2_config.salt_len,
            type=Type.ID,
        )

    def create_auth_hash(self, password: str) -> str:
        ok, msg = self.policy.validate_password(password)
        if not ok:
            raise ValueError(msg)
        return self._argon2.hash(password)

    def verify_auth_hash(self, password: str, stored_hash: str) -> bool:
        if not stored_hash:
            return False
        try:
            return bool(self._argon2.verify(stored_hash, password))
        except (VerifyMismatchError, VerificationError, Exception):
            # dummy constant-time compare path
            secrets.compare_digest(b"dummy-constant-time-a", b"dummy-constant-time-a")
            return False

    def derive_encryption_key(self, password: str, salt: bytes, purpose: str = "vault") -> bytes:
        self.pbkdf2_config.validate()
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
            raise ValueError("salt must be >= 16 bytes")
        domain_sep = f"CryptoSafe::{purpose}".encode("utf-8")
        pwd = password.encode("utf-8") + b"::" + domain_sep
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.pbkdf2_config.dklen,
            salt=bytes(salt),
            iterations=self.pbkdf2_config.iterations,
        )
        return kdf.derive(pwd)

    def generate_salt(self, length: Optional[int] = None) -> bytes:
        return os.urandom(length or self.pbkdf2_config.salt_len)

    def export_params_json(self) -> bytes:
        return json.dumps(
            {
                "argon2": asdict(self.argon2_config),
                "pbkdf2": asdict(self.pbkdf2_config),
                "policy": asdict(self.policy),
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_params_json(cls, raw: bytes | str) -> "KeyManager":
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw)
        return cls(
            argon2_config=Argon2Config(**data.get("argon2", {})),
            pbkdf2_config=PBKDF2Config(**data.get("pbkdf2", {})),
            policy=PasswordPolicy(**data.get("policy", {})),
        )