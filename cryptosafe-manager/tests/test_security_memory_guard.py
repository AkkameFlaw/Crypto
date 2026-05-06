from src.core.security import SecretHolder, secure_zero_buffer


def test_secure_zero_buffer_bytearray():
    data = bytearray(b"super-secret")
    secure_zero_buffer(data)
    assert data == bytearray(b"\x00" * len(data))


def test_secret_holder_returns_original_data():
    secret = b"MySensitiveValue"
    holder = SecretHolder(secret)
    try:
        assert holder.get_data() == secret
    finally:
        holder.wipe()


def test_secret_holder_wipe_clears_data():
    secret = b"MySensitiveValue"
    holder = SecretHolder(secret)
    holder.wipe()
    assert holder.get_data() == b""


def test_secret_holder_wipe_all():
    h1 = SecretHolder(b"aaa")
    h2 = SecretHolder(b"bbb")
    SecretHolder.wipe_all()
    assert h1.get_data() == b""
    assert h2.get_data() == b""