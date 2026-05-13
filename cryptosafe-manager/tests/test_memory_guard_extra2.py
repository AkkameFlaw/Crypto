import ctypes

import src.core.security.memory_guard as mg


def test_secure_memory_setup_platform_functions():
    mem = mg.SecureMemory()
    assert mem.system is not None
    assert hasattr(mem, "kernel32")
    assert hasattr(mem, "libc")


def test_allocate_secure_returns_buffer():
    mem = mg.SecureMemory()
    buf = mem.allocate_secure(16)
    assert buf is not None
    assert len(buf) == 16


def test_lock_and_unlock_memory_do_not_crash():
    mem = mg.SecureMemory()
    buf = (ctypes.c_ubyte * 8)()
    result1 = mem.lock_memory(buf, 8)
    result2 = mem.unlock_memory(buf, 8)
    assert result1 in (True, False)
    assert result2 in (True, False)


def test_secure_zero_bytearray():
    mem = mg.SecureMemory()
    data = bytearray(b"secret")
    mem.secure_zero(data, len(data))
    assert data == bytearray(b"\x00" * 6)


def test_secure_zero_buffer_bytearray():
    data = bytearray(b"secret")
    mg.secure_zero_buffer(data)
    assert data == bytearray(b"\x00" * 6)


def test_secure_zero_buffer_memoryview():
    data = bytearray(b"abcdef")
    view = memoryview(data)
    mg.secure_zero_buffer(view)
    assert data == bytearray(b"\x00" * 6)


def test_secure_zero_buffer_none():
    mg.secure_zero_buffer(None)
    assert True


def test_secret_holder_wipe_all():
    holder1 = mg.SecretHolder(b"one")
    holder2 = mg.SecretHolder(b"two")

    assert holder1.get_data().startswith(b"one")
    assert holder2.get_data().startswith(b"two")

    mg.SecretHolder.wipe_all()

    assert holder1.get_data() == b""
    assert holder2.get_data() == b""


def test_secret_holder_manual_wipe_twice():
    holder = mg.SecretHolder(b"abc")
    assert holder.get_data().startswith(b"abc")

    holder.wipe()
    holder.wipe()

    assert holder.get_data() == b""