from __future__ import annotations

import difflib
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.core.crypto.placeholder import AES256Placeholder
from src.core.events import EntryCreated, EntryDeleted, EntryUpdated, EventBus
from src.core.vault.encryption_service import AESGCMEntryEncryptionService
from src.database.db import Database


class EntryManagerError(Exception):
    pass


@dataclass
class EntryResult:
    id: int
    created_at: int
    updated_at: int
    tags: str


class EntryManager:
    def __init__(self, db: Database, encryption_service: AESGCMEntryEncryptionService, bus: EventBus) -> None:
        self.db = db
        self.encryption_service = encryption_service
        self.bus = bus

    def create_entry(self, data_dict: dict[str, Any]) -> EntryResult:
        clean = self._normalize_data(data_dict, creating=True)
        now = int(time.time())
        blob = self.encryption_service.encrypt_entry(clean, created_at=now)
        entry_id = self.db.insert_vault_entry_v3(
            encrypted_data=blob,
            created_at=now,
            updated_at=now,
            tags=clean.get("tags", ""),
        )
        self.bus.publish(EntryCreated(entry_id=entry_id))
        return EntryResult(id=entry_id, created_at=now, updated_at=now, tags=clean.get("tags", ""))

    def get_entry(self, entry_id: int) -> dict[str, Any]:
        row = self.db.get_vault_row(entry_id)
        if not row:
            raise EntryManagerError("Entry not found")

        payload = self._decrypt_or_migrate_legacy(row)
        payload["id"] = row["id"]
        payload["created_at_db"] = row["created_at"]
        payload["updated_at_db"] = row["updated_at"]
        payload["tags"] = row["tags"] or payload.get("tags", "")
        return payload

    def get_all_entries(self) -> list[dict[str, Any]]:
        rows = self.db.list_vault_rows_v3()
        result = []
        for row in rows:
            try:
                payload = self._decrypt_or_migrate_legacy(row)
                result.append(
                    {
                        "id": row["id"],
                        "title": payload.get("title", ""),
                        "username": payload.get("username", ""),
                        "password": payload.get("password", ""),
                        "url": payload.get("url", ""),
                        "notes": payload.get("notes", ""),
                        "category": payload.get("category", ""),
                        "version": payload.get("version", 1),
                        "totp_secret": payload.get("totp_secret", ""),
                        "share_metadata": payload.get("share_metadata", {}),
                        "created_at": row["created_at"],
                        "updated_at": row["updated_at"],
                        "tags": row["tags"] or payload.get("tags", ""),
                        "domain": self._extract_domain(payload.get("url", "")),
                    }
                )
            except Exception as e:
                print(f"FAILED TO LOAD ENTRY id={row.get('id')}: {e}")
                continue
        return result

    def update_entry(self, entry_id: int, data_dict: dict[str, Any]) -> EntryResult:
        row = self.db.get_vault_row(entry_id)
        if not row:
            raise EntryManagerError("Entry not found")

        current = self._decrypt_or_migrate_legacy(row)
        merged = {**current, **data_dict}
        clean = self._normalize_data(merged, creating=False)

        created_at = int(current.get("created_at", row["created_at"]))
        blob = self.encryption_service.encrypt_entry(clean, created_at=created_at)
        updated_at = int(time.time())
        self.db.update_vault_entry_v3(entry_id, encrypted_data=blob, updated_at=updated_at, tags=clean.get("tags", ""))
        self.bus.publish(EntryUpdated(entry_id=entry_id))
        return EntryResult(id=entry_id, created_at=row["created_at"], updated_at=updated_at, tags=clean.get("tags", ""))

    def delete_entry(self, entry_id: int, soft_delete: bool = True) -> None:
        row = self.db.get_vault_row(entry_id)
        if not row:
            raise EntryManagerError("Entry not found")

        if soft_delete:
            self.db.soft_delete_vault_entry(entry_id)
        else:
            self.db.hard_delete_vault_entry(entry_id)

        self.bus.publish(EntryDeleted(entry_id=entry_id))

    def search_entries(self, query: str) -> list[dict[str, Any]]:
        query = (query or "").strip()
        entries = self.get_all_entries()
        if not query:
            return entries

        field_query = {}
        free_text = query
        if ":" in query:
            parts = query.split()
            for p in parts:
                if ":" in p:
                    k, v = p.split(":", 1)
                    field_query[k.strip().lower()] = v.strip().strip('"')
            free_text = " ".join(p for p in parts if ":" not in p).strip()

        filtered = []
        for e in entries:
            haystack = " ".join(
                [
                    e.get("title", ""),
                    e.get("username", ""),
                    e.get("url", ""),
                    e.get("notes", ""),
                    e.get("category", ""),
                    e.get("tags", ""),
                ]
            ).lower()

            ok = True
            for key, value in field_query.items():
                target = str(e.get(key, "")).lower()
                if value.lower() not in target:
                    ok = False
                    break
            if not ok:
                continue

            if not free_text:
                filtered.append(e)
                continue

            q = free_text.lower()
            if q in haystack:
                filtered.append(e)
                continue

            ratio = difflib.SequenceMatcher(None, q, haystack).ratio()
            if ratio >= 0.28:
                filtered.append(e)

        return filtered

    def _decrypt_or_migrate_legacy(self, row: dict[str, Any]) -> dict[str, Any]:
        encrypted_data = row.get("encrypted_data")
        if encrypted_data:
            return self.encryption_service.decrypt_entry(bytes(encrypted_data))

        legacy_ct = row.get("encrypted_password")
        if not legacy_ct:
            raise EntryManagerError("Entry payload missing")

        key = self.encryption_service.auth_manager.get_encryption_key()
        if not key:
            raise EntryManagerError("Vault is locked")

        legacy_pw = AES256Placeholder._xor(bytes(legacy_ct), key).decode("utf-8", errors="ignore")
        payload = {
            "title": row.get("title", ""),
            "username": row.get("username", ""),
            "password": legacy_pw,
            "url": row.get("url", ""),
            "notes": row.get("notes", ""),
            "category": row.get("category", ""),
            "version": 1,
            "totp_secret": "",
            "share_metadata": {},
            "tags": row.get("tags", ""),
            "created_at": row.get("created_at"),
        }

        blob = self.encryption_service.encrypt_entry(payload, created_at=row.get("created_at"))
        self.db.update_vault_entry_v3(
            int(row["id"]),
            encrypted_data=blob,
            updated_at=int(time.time()),
            tags=row.get("tags", ""),
        )
        return payload

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            parsed = urlparse(url)
            return parsed.netloc or url
        except Exception:
            return url

    @staticmethod
    def _normalize_data(data: dict[str, Any], creating: bool) -> dict[str, Any]:
        title = str(data.get("title", "")).strip()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
        url = str(data.get("url", "")).strip()
        notes = str(data.get("notes", "")).strip()
        category = str(data.get("category", "")).strip()
        tags = str(data.get("tags", "")).strip()
        totp_secret = str(data.get("totp_secret", "")).strip()
        share_metadata = data.get("share_metadata", {}) or {}

        if not title:
            raise EntryManagerError("Title is required")
        if not password:
            raise EntryManagerError("Password is required")

        return {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "category": category,
            "version": 1,
            "totp_secret": totp_secret,
            "share_metadata": share_metadata,
            "tags": tags,
        }