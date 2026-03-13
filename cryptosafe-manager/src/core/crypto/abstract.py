from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.crypto.authentication import AuthenticationManager


class EncryptionService(ABC):
    @abstractmethod
    def encrypt(self, data: bytes, auth_manager: "AuthenticationManager") -> bytes:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ciphertext: bytes, auth_manager: "AuthenticationManager") -> bytes:
        raise NotImplementedError