from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto.authentication import AuthenticationManager


class EntryEncryptionError(Exception):
    pass


class AESGCMEntryEncryptionService:

    VERSION = 1
    NONCE_LEN = 12

    def __init__(self, auth_manager: AuthenticationManager) -> None:
        self.auth_manager = auth_manager

    def encrypt_entry(self, data: Dict[str, Any], created_at: int | None = None) -> bytes:
        key = self.auth_manager.get_encryption_key()
        if not key:
            raise EntryEncryptionError("Vault is locked")

        nonce = os.urandom(self.NONCE_LEN)
        payload = {
            **data,
            "created_at": int(created_at if created_at is not None else time.time()),
            "version": self.VERSION,
        }

        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_entry(self, encrypted_blob: bytes) -> Dict[str, Any]:
        key = self.auth_manager.get_encryption_key()
        if not key:
            raise EntryEncryptionError("Vault is locked")

        if not encrypted_blob or len(encrypted_blob) <= self.NONCE_LEN:
            raise EntryEncryptionError("Encrypted blob is invalid")

        nonce = encrypted_blob[: self.NONCE_LEN]
        ciphertext = encrypted_blob[self.NONCE_LEN :]

        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise EntryEncryptionError("Entry integrity check failed") from e

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            raise EntryEncryptionError("Entry payload is invalid") from e

        if not isinstance(payload, dict):
            raise EntryEncryptionError("Entry payload must be an object")
        return payload