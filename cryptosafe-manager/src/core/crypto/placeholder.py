from __future__ import annotations

import secrets
from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        if not key:
            raise ValueError("key is empty")
        return self._xor(data, key)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes")
        if not key:
            raise ValueError("key is empty")
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
