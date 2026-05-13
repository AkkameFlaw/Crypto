from src.core.events import EventBus
from src.core.vault.entry_manager import EntryManager
from src.core.vault.encryption_service import AESGCMEntryEncryptionService
from src.database.db import Database
from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache


def _extract_entry_id(result):
    if isinstance(result, int):
        return result
    if hasattr(result, "id"):
        return result.id
    if isinstance(result, dict) and "id" in result:
        return result["id"]
    raise AssertionError(f"Cannot extract entry id from result: {result!r}")


def test_entry_manager_create_and_soft_delete(tmp_path):
    db_path = tmp_path / "entry_manager.sqlite3"
    db = Database(str(db_path))
    db.initialize()

    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    enc = AESGCMEntryEncryptionService(auth)
    manager = EntryManager(db, enc, bus)

    created = manager.create_entry(
        {
            "title": "GitHub",
            "username": "alice",
            "password": "pass123",
            "url": "https://github.com",
            "notes": "dev account",
            "category": "",
            "tags": "git,dev",
        }
    )
    entry_id = _extract_entry_id(created)

    all_entries = manager.get_all_entries()
    assert any(row["id"] == entry_id for row in all_entries)

    full_entry = manager.get_entry(entry_id)
    assert full_entry["title"] == "GitHub"
    assert full_entry["username"] == "alice"
    assert full_entry["password"] == "pass123"

    manager.delete_entry(entry_id, soft_delete=True)

    all_entries_after_delete = manager.get_all_entries()
    assert all(row["id"] != entry_id for row in all_entries_after_delete)

    db.close()


def test_entry_manager_update_entry(tmp_path):
    db_path = tmp_path / "entry_manager_update.sqlite3"
    db = Database(str(db_path))
    db.initialize()

    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    enc = AESGCMEntryEncryptionService(auth)
    manager = EntryManager(db, enc, bus)

    created = manager.create_entry(
        {
            "title": "Mail",
            "username": "user1",
            "password": "pass1",
            "url": "https://mail.example.com",
            "notes": "old",
            "category": "",
            "tags": "mail",
        }
    )
    entry_id = _extract_entry_id(created)

    manager.update_entry(
        entry_id,
        {
            "title": "Mail Updated",
            "username": "user2",
            "password": "pass2",
            "url": "https://mail.example.com",
            "notes": "new",
            "category": "",
            "tags": "mail,updated",
        },
    )

    entry = manager.get_entry(entry_id)
    assert entry["title"] == "Mail Updated"
    assert entry["username"] == "user2"
    assert entry["password"] == "pass2"

    db.close()