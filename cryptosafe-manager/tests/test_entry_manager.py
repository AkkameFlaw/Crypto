from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus
from src.core.vault import AESGCMEntryEncryptionService, EntryManager


def test_crud_integration_100_entries(db):
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), EventBus())
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    manager = EntryManager(db, AESGCMEntryEncryptionService(auth), EventBus())

    ids = []
    for i in range(100):
        result = manager.create_entry(
            {
                "title": f"Entry {i}",
                "username": f"user{i}@example.com",
                "password": f"Pass!{i}Strong",
                "url": f"https://example{i}.com",
                "notes": f"Note {i}",
                "category": "Work",
                "tags": "work,test",
            }
        )
        ids.append(result.id)

    rows = manager.get_all_entries()
    assert len(rows) == 100

    for i in range(10):
        manager.update_entry(ids[i], {"title": f"Updated {i}", "password": f"Changed!{i}Pass"})

    row = manager.get_entry(ids[0])
    assert row["title"] == "Updated 0"
    assert row["password"] == "Changed!0Pass"

    for i in range(5):
        manager.delete_entry(ids[i], soft_delete=True)

    rows_after = manager.get_all_entries()
    assert len(rows_after) == 95