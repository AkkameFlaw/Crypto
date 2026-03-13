from src.core.crypto.key_storage import CachePolicy, SecureKeyCache


def test_key_cache_zeroize_and_clear():
    cache = SecureKeyCache(CachePolicy(idle_timeout_seconds=3600))
    cache.set_key(b"A" * 32)
    assert cache.get_key() == b"A" * 32
    cache.clear()
    assert cache.get_key() is None