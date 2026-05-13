from pathlib import Path

import pytest

from src.core.key_manager import KeyManager, KdfParams


def test_derive_key_success():
    km = KeyManager(KdfParams(iterations=1000, dklen=32, hash_name="sha256"))
    salt = b"12345678"
    key = km.derive_key("StrongPass!123", salt)

    assert isinstance(key, bytes)
    assert len(key) == 32


def test_derive_key_same_inputs_same_output():
    km = KeyManager(KdfParams(iterations=1000, dklen=32, hash_name="sha256"))
    salt = b"abcdefgh"

    k1 = km.derive_key("password", salt)
    k2 = km.derive_key("password", salt)

    assert k1 == k2


def test_derive_key_rejects_bad_password():
    km = KeyManager()

    with pytest.raises(ValueError):
        km.derive_key("", b"12345678")

    with pytest.raises(ValueError):
        km.derive_key(None, b"12345678")  # type: ignore[arg-type]


def test_derive_key_rejects_bad_salt():
    km = KeyManager()

    with pytest.raises(ValueError):
        km.derive_key("password", b"1234")

    with pytest.raises(ValueError):
        km.derive_key("password", "not-bytes")  # type: ignore[arg-type]


def test_store_and_load_key_are_noop():
    km = KeyManager()
    assert km.store_key("x", "y") is None
    assert km.load_key("x", "y") is None


def test_save_and_load_params(tmp_path):
    path = tmp_path / "params" / "kdf.json"

    params = KdfParams(iterations=222000, dklen=48, hash_name="sha512")
    km = KeyManager(params)
    km.save_params_to_file(str(path))

    assert path.exists()

    loaded = KeyManager.load_params_from_file(str(path))
    assert loaded is not None
    assert loaded.iterations == 222000
    assert loaded.dklen == 48
    assert loaded.hash_name == "sha512"


def test_load_params_from_missing_file_returns_none(tmp_path):
    path = tmp_path / "missing.json"
    loaded = KeyManager.load_params_from_file(str(path))
    assert loaded is None