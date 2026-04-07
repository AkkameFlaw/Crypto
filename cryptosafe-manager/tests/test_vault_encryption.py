from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus
from src.core.vault.encryption_service import AESGCMEntryEncryptionService


def test_entry_encrypt_decrypt_cycle(db):
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), EventBus())
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    service = AESGCMEntryEncryptionService(auth)
    payload = {
        "title": "Example",
        "username": "user@example.com",
        "password": "SuperPass!123",
        "url": "https://example.com",
        "notes": "secret notes",
        "category": "Work",
        "version": 1,
    }

    blob = service.encrypt_entry(payload)
    assert b"SuperPass!123" not in blob
    assert b"user@example.com" not in blob

    decrypted = service.decrypt_entry(blob)
    assert decrypted["title"] == payload["title"]
    assert decrypted["username"] == payload["username"]
    assert decrypted["password"] == payload["password"]