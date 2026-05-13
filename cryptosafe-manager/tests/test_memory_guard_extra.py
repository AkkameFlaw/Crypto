from src.core.security.memory_guard import SecureMemory, SecretHolder


def test_secure_memory_allocate_and_free():
    mem = SecureMemory()
    buf = mem.allocate_secure(32)

    assert buf is not None

    mem.secure_zero(buf, 32)
    mem.free_secure(buf, 32)


def test_secret_holder_roundtrip():
    secret = b"super-secret-value"
    holder = SecretHolder(secret)

    data = holder.get_data()
    assert isinstance(data, bytes)
    assert len(data) >= len(secret)
    assert data[: len(secret)] == secret

    holder.__del__()