from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class ShareOptions:
    recipient: str
    permissions: dict[str, Any]
    expires_in_days: int = 7
    method: str = "password"
    password: str | None = None
    public_key_pem: bytes | None = None


class SharingService:
    def __init__(self, db, entry_manager, audit_logger=None):
        self.db = db
        self.entry_manager = entry_manager
        self.audit_logger = audit_logger

    def share_entry(self, entry_id: int, options: ShareOptions) -> dict[str, Any]:
        entry = self.entry_manager.get_entry(entry_id)
        share_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(days=max(1, min(30, options.expires_in_days)))

        filtered = self._filter_entry_for_sharing(entry, options.permissions)
        package_body = {
            "version": "1.0",
            "cryptosafe_share": True,
            "share_id": share_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "permissions": options.permissions,
            "entry": filtered,
        }

        raw = json.dumps(package_body, ensure_ascii=False).encode("utf-8")
        if options.method == "public_key":
            if not options.public_key_pem:
                raise ValueError("Recipient public key required")
            package = self._encrypt_with_public_key(raw, options.public_key_pem)
        else:
            if not options.password:
                raise ValueError("Share password required")
            package = self._encrypt_with_password(raw, options.password)

        self.db.insert_shared_entry(
            share_id=share_id,
            original_entry_id=entry_id,
            encryption_method=options.method,
            recipient_info=options.recipient,
            permissions=json.dumps(options.permissions, ensure_ascii=False),
            shared_at=datetime.now(timezone.utc).isoformat(),
            expires_at=expires_at.isoformat(),
        )

        if self.audit_logger:
            self.audit_logger.log_event(
                event_type="ENTRY_SHARED",
                severity="INFO",
                source="sharing",
                details={
                    "share_id": share_id,
                    "recipient": options.recipient,
                    "method": options.method,
                    "expires_at": expires_at.isoformat(),
                },
                entry_id=entry_id,
            )

        return {
            "share_id": share_id,
            "expires_at": expires_at.isoformat(),
            "package": package,
        }

    def import_shared_entry(
        self,
        package: dict[str, Any],
        password: str | None = None,
        private_key_pem: bytes | None = None,
        save_to_vault: bool = True,
    ) -> dict[str, Any]:
        if "encrypted_key" in package:
            if not private_key_pem:
                raise ValueError("Private key required")
            private_key = serialization.load_pem_private_key(private_key_pem, password=None)
            symmetric_key = private_key.decrypt(
                base64.b64decode(package["encrypted_key"]),
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            nonce = base64.b64decode(package["encryption"]["nonce"])
            ciphertext = base64.b64decode(package["data"])
            raw = AESGCM(symmetric_key).decrypt(nonce, ciphertext, None)
        else:
            if not password:
                raise ValueError("Password required")
            salt = base64.b64decode(package["encryption"]["salt"])
            nonce = base64.b64decode(package["encryption"]["nonce"])
            ciphertext = base64.b64decode(package["data"])

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(password.encode("utf-8"))

            h = hmac.HMAC(key, hashes.SHA256())
            h.update(ciphertext)
            h.verify(base64.b64decode(package["auth"]["value"]))

            raw = AESGCM(key).decrypt(nonce, ciphertext, None)

        payload = json.loads(raw.decode("utf-8"))
        entry = payload["entry"]

        if not save_to_vault:
            return {"entry": entry, "saved": False}

        created = self.entry_manager.create_entry(entry)
        return {"entry": entry, "saved": True, "entry_id": int(created.id)}

    @staticmethod
    def _filter_entry_for_sharing(entry: dict[str, Any], permissions: dict[str, Any]) -> dict[str, Any]:
        result = {
            "title": entry.get("title", ""),
            "username": entry.get("username", ""),
            "password": entry.get("password", ""),
            "url": entry.get("url", ""),
            "notes": entry.get("notes", ""),
            "category": entry.get("category", ""),
            "tags": entry.get("tags", ""),
        }
        if not permissions.get("include_notes", True):
            result["notes"] = ""
        if permissions.get("read_only", False):
            result["read_only"] = True
        return result

    @staticmethod
    def _encrypt_with_password(raw: bytes, password: str) -> dict[str, Any]:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode("utf-8"))

        ciphertext = AESGCM(key).encrypt(nonce, raw, None)

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(ciphertext)
        mac = h.finalize()

        return {
            "version": "1.0",
            "cryptosafe_share": True,
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations": 100000,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "auth": {
                "mode": "hmac-sha256",
                "value": base64.b64encode(mac).decode("ascii"),
            },
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }

    @staticmethod
    def _encrypt_with_public_key(raw: bytes, public_key_pem: bytes) -> dict[str, Any]:
        symmetric_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(symmetric_key).encrypt(nonce, raw, None)

        public_key = serialization.load_pem_public_key(public_key_pem)
        encrypted_key = public_key.encrypt(
            symmetric_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return {
            "version": "1.0",
            "cryptosafe_share": True,
            "encryption": {
                "algorithm": "RSA-OAEP/AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }