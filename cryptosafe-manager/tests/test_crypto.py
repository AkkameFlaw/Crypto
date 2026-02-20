from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager


def test_xor_encrypt_decrypt_roundtrip():
    crypto = AES256Placeholder()
    key = b"abcd" * 8
    data = b"hello world"
    ct = crypto.encrypt(data, key)
    pt = crypto.decrypt(ct, key)
    assert pt == data


def test_key_manager_derive_key():
    km = KeyManager()
    salt = b"12345678ABCDEFGH"
    key1 = km.derive_key("password", salt)
    key2 = km.derive_key("password", salt)
    assert key1 == key2
    assert len(key1) == 32
