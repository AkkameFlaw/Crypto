from __future__ import annotations

import secrets

from src.core.crypto.abstract import EncryptionService


class AES256Placeholder(EncryptionService):

    def encrypt(self, data: bytes, auth_manager) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        key = auth_manager.get_encryption_key()
        if not key:
            raise ValueError("vault is locked")
        return self._xor(data, key)

    def decrypt(self, ciphertext: bytes, auth_manager) -> bytes:
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes")
        key = auth_manager.get_encryption_key()
        if not key:
            raise ValueError("vault is locked")
        return self._xor(ciphertext, key)

    @staticmethod
    def _xor(buf: bytes, key: bytes) -> bytes:
        out = bytearray(len(buf))
        klen = len(key)
        for i, b in enumerate(buf):
            out[i] = b ^ key[i % klen]
        return bytes(out)

    @staticmethod
    def random_key(length: int = 32) -> bytes:
        return secrets.token_bytes(length)