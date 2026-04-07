from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.crypto.placeholder import AES256Placeholder
from src.core.events import EventBus


def test_xor_encrypt_decrypt_roundtrip(db):
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), EventBus())
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok is True

    crypto = AES256Placeholder()
    data = b"hello world"

    ct = crypto.encrypt(data, auth)
    pt = crypto.decrypt(ct, auth)

    assert pt == data