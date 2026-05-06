from __future__ import annotations

import base64
import gzip
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.core.import_export.formats import BitwardenJSONFormat, CSVFormat, LastPassCSVExportFormat


@dataclass
class ExportOptions:
    export_format: str = "encrypted_json"
    include_notes: bool = True
    include_tags: bool = True
    compress: bool = False
    key_bits: int = 256
    selected_entry_ids: Optional[list[int]] = None


class VaultExporter:
    def __init__(self, entry_manager, auth_manager, audit_logger=None):
        self.entry_manager = entry_manager
        self.auth_manager = auth_manager
        self.audit_logger = audit_logger

    def export_vault(
        self,
        password: str | None = None,
        public_key_pem: bytes | None = None,
        options: ExportOptions | None = None,
    ) -> dict[str, Any]:
        options = options or ExportOptions()
        entries = self._get_entries_for_export(options.selected_entry_ids)
        entries = [self._filter_entry(e, options) for e in entries]

        if options.export_format == "csv":
            plaintext = CSVFormat.export(entries)
        elif options.export_format == "bitwarden_json":
            plaintext = BitwardenJSONFormat.export(entries)
        elif options.export_format == "lastpass_csv":
            plaintext = LastPassCSVExportFormat.export(entries)
        else:
            plaintext = json.dumps(
                {
                    "version": "1.0",
                    "cryptosafe_export": True,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_application": "CryptoSafe Manager",
                    "entry_count": len(entries),
                    "entries": entries,
                },
                ensure_ascii=False,
                indent=2,
            ).encode("utf-8")

        if options.compress:
            plaintext = gzip.compress(plaintext)

        package: dict[str, Any]
        if public_key_pem:
            package = self._encrypt_with_public_key(plaintext, public_key_pem)
        elif password:
            package = self._encrypt_with_password(plaintext, password, key_bits=options.key_bits)
        else:
            raise ValueError("Password or public key is required")

        integrity_hash = hashlib.sha256(plaintext).hexdigest()
        package["version"] = "1.0"
        package["cryptosafe_export"] = True
        package["timestamp"] = datetime.now(timezone.utc).isoformat()
        package["source_application"] = "CryptoSafe Manager"
        package["entry_count"] = len(entries)
        package["compressed"] = options.compress
        package["format"] = options.export_format
        package["integrity"] = {
            "hash": integrity_hash,
            "hash_algorithm": "SHA256",
        }

        if self.audit_logger:
            self.audit_logger.log_event(
                event_type="VAULT_EXPORT",
                severity="INFO",
                source="import_export",
                details={
                    "format": options.export_format,
                    "entry_count": len(entries),
                    "compressed": options.compress,
                    "key_bits": options.key_bits,
                    "method": "public_key" if public_key_pem else "password",
                },
            )

        return package

    def _get_entries_for_export(self, selected_ids: list[int] | None) -> list[dict[str, Any]]:
        rows = self.entry_manager.get_all_entries()
        if not selected_ids:
            return rows
        selected = set(selected_ids)
        return [r for r in rows if int(r["id"]) in selected]

    @staticmethod
    def _filter_entry(entry: dict[str, Any], options: ExportOptions) -> dict[str, Any]:
        result = {
            "id": entry.get("id"),
            "title": entry.get("title", ""),
            "username": entry.get("username", ""),
            "password": entry.get("password", ""),
            "url": entry.get("url", ""),
            "category": entry.get("category", ""),
        }
        if options.include_notes:
            result["notes"] = entry.get("notes", "")
        if options.include_tags:
            result["tags"] = entry.get("tags", "")
        return result

    def _derive_export_key(self, password: str, salt: bytes, key_bits: int = 256) -> bytes:
        length = 32 if key_bits == 256 else 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode("utf-8"))

    def _encrypt_with_password(self, plaintext: bytes, password: str, key_bits: int = 256) -> dict[str, Any]:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = self._derive_export_key(password, salt, key_bits=key_bits)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        export_hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"cryptosafe-export-hmac",
        ).derive(key)

        h = hmac.HMAC(export_hmac_key, hashes.SHA256())
        h.update(ciphertext)
        mac = h.finalize()

        return {
            "encryption": {
                "algorithm": "AES-256-GCM" if key_bits == 256 else "AES-128-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations": 100000,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "data": base64.b64encode(ciphertext).decode("ascii"),
            "auth": {
                "mode": "hmac-sha256",
                "value": base64.b64encode(mac).decode("ascii"),
            },
        }

    def _encrypt_with_public_key(self, plaintext: bytes, public_key_pem: bytes) -> dict[str, Any]:
        symmetric_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        aesgcm = AESGCM(symmetric_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

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
            "encryption": {
                "algorithm": "RSA-OAEP/AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }