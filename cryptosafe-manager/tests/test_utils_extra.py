import os

from src.core.utils import ValidationResult, minimal_path_permissions, secure_zero_bytes, validate_safe_text


def test_secure_zero_bytes_bytearray():
    data = bytearray(b"secret")
    secure_zero_bytes(data)
    assert data == bytearray(b"\x00" * 6)


def test_secure_zero_bytes_memoryview():
    data = bytearray(b"abcdef")
    view = memoryview(data)
    secure_zero_bytes(view)
    assert data == bytearray(b"\x00" * 6)


def test_secure_zero_bytes_ignores_invalid_type():
    secure_zero_bytes(b"immutable")
    assert True


def test_minimal_path_permissions_existing_file(tmp_path):
    path = tmp_path / "file.txt"
    path.write_text("hello", encoding="utf-8")

    minimal_path_permissions(str(path))
    assert path.exists()


def test_minimal_path_permissions_missing_file(tmp_path):
    path = tmp_path / "missing.txt"
    minimal_path_permissions(str(path))
    assert not path.exists()


def test_validate_safe_text_missing():
    result = validate_safe_text(None, "title")  # type: ignore[arg-type]
    assert isinstance(result, ValidationResult)
    assert result.ok is False
    assert "missing" in result.message


def test_validate_safe_text_required():
    result = validate_safe_text("   ", "title", allow_empty=False)
    assert result.ok is False
    assert "required" in result.message


def test_validate_safe_text_too_long():
    result = validate_safe_text("a" * 300, "title", max_len=10)
    assert result.ok is False
    assert "too long" in result.message


def test_validate_safe_text_invalid_chars():
    result = validate_safe_text("<script>", "notes")
    assert result.ok is False
    assert "invalid characters" in result.message


def test_validate_safe_text_valid():
    result = validate_safe_text("hello-user_1@example.com", "username")
    assert result.ok is True