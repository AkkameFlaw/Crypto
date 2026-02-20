from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class VaultEntry:
    id: int
    title: str
    username: str
    encrypted_password: bytes
    url: str
    notes: str
    created_at: int
    updated_at: int
    tags: str


@dataclass
class AuditLogRow:
    id: int
    action: str
    timestamp: int
    entry_id: Optional[int]
    details: str
    signature: Optional[bytes]


@dataclass
class SettingRow:
    id: int
    setting_key: str
    setting_value: bytes | str
    encrypted: int


@dataclass
class KeyStoreRow:
    id: int
    key_type: str
    salt: bytes
    hash: bytes
    params: str
