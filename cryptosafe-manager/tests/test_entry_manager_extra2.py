import time

import pytest

from src.core.events import EventBus
from src.core.vault.entry_manager import EntryManager, EntryManagerError
from src.core.vault.encryption_service import AESGCMEntryEncryptionService
from src.database.db import Database
from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache


def make_manager(tmp_path):
    db_path = tmp_path / "manager.sqlite3"
    db = Database(str(db_path))
    db.initialize()

    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    enc = AESGCMEntryEncryptionService(auth)
    manager = EntryManager(db, enc, bus)
    return db, bus, auth, manager


def extract_id(result):
    return result.id if hasattr(result, "id") else result


def test_extract_domain():
    assert EntryManager._extract_domain("https://github.com/user/repo") == "github.com"
    assert EntryManager._extract_domain("not a url") == "not a url"


def test_normalize_data_requires_title():
    with pytest.raises(EntryManagerError):
        EntryManager._normalize_data(
            {
                "title": "",
                "password": "pw",
            },
            creating=True,
        )


def test_normalize_data_requires_password():
    with pytest.raises(EntryManagerError):
        EntryManager._normalize_data(
            {
                "title": "GitHub",
                "password": "",
            },
            creating=True,
        )


def test_normalize_data_success():
    data = EntryManager._normalize_data(
        {
            "title": " GitHub ",
            "username": " alice ",
            "password": " pass123 ",
            "url": " https://github.com ",
            "notes": " note ",
            "category": " dev ",
            "tags": " git,dev ",
            "totp_secret": " totp ",
            "share_metadata": {"a": 1},
        },
        creating=True,
    )

    assert data["title"] == "GitHub"
    assert data["username"] == "alice"
    assert data["password"] == "pass123"
    assert data["url"] == "https://github.com"
    assert data["notes"] == "note"
    assert data["category"] == "dev"
    assert data["tags"] == "git,dev"
    assert data["totp_secret"] == "totp"
    assert data["share_metadata"] == {"a": 1}
    assert data["version"] == 1


def test_search_entries_field_query(tmp_path):
    db, bus, auth, manager = make_manager(tmp_path)

    r1 = manager.create_entry(
        {
            "title": "GitHub Work",
            "username": "alice",
            "password": "pw1",
            "url": "https://github.com",
            "notes": "dev account",
            "category": "work",
            "tags": "git,dev",
        }
    )
    r2 = manager.create_entry(
        {
            "title": "Gmail Personal",
            "username": "bob",
            "password": "pw2",
            "url": "https://mail.google.com",
            "notes": "mail account",
            "category": "personal",
            "tags": "mail",
        }
    )

    results = manager.search_entries("category:work")
    ids = [x["id"] for x in results]
    assert extract_id(r1) in ids
    assert extract_id(r2) not in ids

    db.close()


def test_search_entries_free_text(tmp_path):
    db, bus, auth, manager = make_manager(tmp_path)

    created = manager.create_entry(
        {
            "title": "GitLab",
            "username": "alice",
            "password": "pw",
            "url": "https://gitlab.com",
            "notes": "source hosting",
            "category": "dev",
            "tags": "git",
        }
    )

    results = manager.search_entries("GitLab")
    assert any(row["id"] == extract_id(created) for row in results)

    db.close()


def test_get_entry_not_found(tmp_path):
    db, bus, auth, manager = make_manager(tmp_path)

    with pytest.raises(EntryManagerError):
        manager.get_entry(999999)

    db.close()


def test_delete_entry_not_found(tmp_path):
    db, bus, auth, manager = make_manager(tmp_path)

    with pytest.raises(EntryManagerError):
        manager.delete_entry(999999)

    db.close()


def test_update_entry_not_found(tmp_path):
    db, bus, auth, manager = make_manager(tmp_path)

    with pytest.raises(EntryManagerError):
        manager.update_entry(999999, {"title": "x", "password": "y"})

    db.close()


def test_search_entries_empty_query_returns_all(tmp_path):
    db, bus, auth, manager = make_manager(tmp_path)

    manager.create_entry(
        {
            "title": "One",
            "username": "u1",
            "password": "p1",
            "url": "",
            "notes": "",
            "category": "",
            "tags": "",
        }
    )
    manager.create_entry(
        {
            "title": "Two",
            "username": "u2",
            "password": "p2",
            "url": "",
            "notes": "",
            "category": "",
            "tags": "",
        }
    )

    results = manager.search_entries("")
    assert len(results) >= 2

    db.close()