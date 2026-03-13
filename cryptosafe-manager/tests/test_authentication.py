from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus


def test_auth_initialize_and_login(db):
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), EventBus())
    auth.initialize_master_password("StrongPass!123")
    ok, msg = auth.authenticate("StrongPass!123")
    assert ok is True
    assert auth.get_encryption_key() is not None