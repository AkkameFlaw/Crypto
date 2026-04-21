from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Literal, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SignerMode = Literal["ed25519", "hmac-sha256"]


@dataclass
class SignResult:
    signature_hex: str
    public_key_b64: str
    mode: SignerMode


class AuditLogSigner:

    def __init__(self, auth_manager) -> None:
        self.auth_manager = auth_manager
        self._mode: SignerMode = "ed25519"
        self._ed25519_private: Optional[ed25519.Ed25519PrivateKey] = None
        self._ed25519_public_bytes: Optional[bytes] = None
        self._hmac_key: Optional[bytes] = None

    def is_ready(self) -> bool:
        return self.auth_manager.get_encryption_key() is not None

    def _derive_material(self, length: int = 32) -> bytes:
        base_key = self.auth_manager.get_encryption_key()
        if not base_key:
            raise RuntimeError("Vault is locked; signing key unavailable")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=b"audit-signing",
        )
        return hkdf.derive(base_key)

    def _ensure_initialized(self) -> None:
        if self._ed25519_private or self._hmac_key:
            return

        try:
            seed = self._derive_material(32)
            self._ed25519_private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            self._ed25519_public_bytes = self._ed25519_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._mode = "ed25519"
        except Exception:
            self._hmac_key = self._derive_material(32)
            self._mode = "hmac-sha256"

    def sign(self, data: bytes) -> SignResult:
        self._ensure_initialized()

        if self._mode == "ed25519":
            assert self._ed25519_private is not None
            assert self._ed25519_public_bytes is not None
            sig = self._ed25519_private.sign(data)
            return SignResult(
                signature_hex=sig.hex(),
                public_key_b64=base64.b64encode(self._ed25519_public_bytes).decode("ascii"),
                mode="ed25519",
            )

        assert self._hmac_key is not None
        sig = hmac.new(self._hmac_key, data, hashlib.sha256).digest()
        return SignResult(
            signature_hex=sig.hex(),
            public_key_b64="",
            mode="hmac-sha256",
        )

    def verify(self, data: bytes, signature_hex: str, public_key_b64: str = "", mode: str = "ed25519") -> bool:
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            return False

        if mode == "ed25519":
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
                public_key.verify(signature, data)
                return True
            except (InvalidSignature, ValueError, TypeError):
                return False

        try:
            self._ensure_initialized()
            assert self._hmac_key is not None
            expected = hmac.new(self._hmac_key, data, hashlib.sha256).digest()
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False