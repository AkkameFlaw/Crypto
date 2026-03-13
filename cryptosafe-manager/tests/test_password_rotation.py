from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.crypto.placeholder import AES256Placeholder
from src.core.events import EventBus


def test_password_rotation_integration(db):
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), EventBus())
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    crypto = AES256Placeholder()
    for i in range(10):
        ct = crypto.encrypt(f"pass-{i}".encode(), auth)
        db.insert_vault_entry(
            title=f"title-{i}",
            username=f"user-{i}",
            encrypted_password=ct,
            url="",
            notes="",
            tags="",
        )

    ok, msg = auth.rotate_password("StrongPass!123", "NewStrongPass!456")
    assert ok is True, msg

    auth.logout()
    ok, msg = auth.authenticate("NewStrongPass!456")
    assert ok is True, msg

    rows = db.list_vault_entries_with_ciphertext()
    for i, row in enumerate(rows):
        pt = crypto.decrypt(bytes(row["encrypted_password"]), auth)
        assert pt.decode() == f"pass-{i}"