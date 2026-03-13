from src.core.crypto.key_derivation import Argon2Config, KeyManager, PBKDF2Config, PasswordPolicy


def test_argon2_hash_and_verify():
    km = KeyManager(
        argon2_config=Argon2Config(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16),
        pbkdf2_config=PBKDF2Config(iterations=100000, salt_len=16, dklen=32),
        policy=PasswordPolicy(min_length=12),
    )
    h = km.create_auth_hash("StrongPass!123")
    assert km.verify_auth_hash("StrongPass!123", h) is True
    assert km.verify_auth_hash("WrongPass!123", h) is False


def test_key_consistency_100_times():
    km = KeyManager()
    salt = b"1234567890ABCDEF"
    results = [km.derive_encryption_key("StrongPass!123", salt) for _ in range(100)]
    assert all(r == results[0] for r in results)


def test_password_policy():
    km = KeyManager()
    ok, _ = km.policy.validate_password("StrongPass!123")
    assert ok is True
    ok, _ = km.policy.validate_password("password123")
    assert ok is False