import tempfile
from pathlib import Path

from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus
from src.database.db import Database


def test_auth_logout_clears_encryption_key():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "auth_lock_test.sqlite3"
        db = Database(str(db_path))
        db.initialize()

        auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), EventBus())
        auth.initialize_master_password("StrongPass!123")

        ok, _ = auth.authenticate("StrongPass!123")
        assert ok is True
        assert auth.get_encryption_key() is not None

        auth.logout()
        assert auth.get_encryption_key() is None

        db.close()