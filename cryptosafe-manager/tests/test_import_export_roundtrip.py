import json

from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus
from src.core.import_export import VaultExporter, VaultImporter
from src.core.vault import AESGCMEntryEncryptionService, EntryManager


def test_roundtrip_encrypted_json(db):
    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    vault = EntryManager(db, AESGCMEntryEncryptionService(auth), bus)
    vault.create_entry(
        {
            "title": "GitHub",
            "username": "user@example.com",
            "password": "StrongPass!456",
            "url": "https://github.com",
            "notes": "note",
            "category": "Work",
            "tags": "dev,git",
        }
    )

    exporter = VaultExporter(vault, auth)
    package = exporter.export_vault(password="ExportPass!123")

    raw = json.dumps(package, ensure_ascii=False).encode("utf-8")
    importer = VaultImporter(vault)
    preview = importer.import_data(raw, password="ExportPass!123", options=None, import_format="encrypted_json")
    assert "summary" in preview