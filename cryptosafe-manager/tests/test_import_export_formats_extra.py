import json

from src.core.import_export.formats.csv_format import (
    CSVFormat,
    LastPassCSVExportFormat,
    LastPassCSVFormat,
)
from src.core.import_export.formats.json_format import (
    NativeJSONFormat,
    BitwardenJSONFormat,
)


def test_csv_format_export_and_import():
    entries = [
        {
            "title": "GitHub",
            "username": "alice",
            "password": "pass123",
            "url": "https://github.com",
            "notes": "dev",
            "category": "work",
            "tags": "git,dev",
        }
    ]

    raw = CSVFormat.export(entries)
    parsed = CSVFormat.import_data(raw)

    assert isinstance(raw, bytes)
    assert len(parsed) == 1
    assert parsed[0]["title"] == "GitHub"
    assert parsed[0]["username"] == "alice"
    assert parsed[0]["password"] == "pass123"
    assert parsed[0]["category"] == "work"


def test_csv_format_handles_missing_fields():
    raw = b"title,username,password,url,notes,category,tags\nOnlyTitle,,,,,,\n"
    parsed = CSVFormat.import_data(raw)

    assert len(parsed) == 1
    assert parsed[0]["title"] == "OnlyTitle"
    assert parsed[0]["username"] == ""
    assert parsed[0]["password"] == ""


def test_lastpass_csv_import():
    raw = (
        "url,username,password,extra,name,grouping,fav\n"
        "https://example.com,bob,secret,extra note,Example,Group,0\n"
    ).encode("utf-8")

    parsed = LastPassCSVFormat.import_data(raw)

    assert len(parsed) == 1
    assert parsed[0]["title"] == "Example"
    assert parsed[0]["username"] == "bob"
    assert parsed[0]["password"] == "secret"
    assert parsed[0]["notes"] == "extra note"
    assert parsed[0]["category"] == "Group"


def test_lastpass_csv_export():
    entries = [
        {
            "title": "Mail",
            "username": "user1",
            "password": "pw1",
            "url": "https://mail.example.com",
            "notes": "mail notes",
            "category": "mail",
        }
    ]

    raw = LastPassCSVExportFormat.export(entries)
    text = raw.decode("utf-8")

    assert "url,username,password,extra,name,grouping,fav" in text
    assert "Mail" in text
    assert "mail notes" in text
    assert "mail" in text


def test_native_json_format_roundtrip():
    entries = [
        {
            "title": "Gmail",
            "username": "alice@gmail.com",
            "password": "pw",
            "url": "https://mail.google.com",
            "notes": "note",
        }
    ]

    raw = NativeJSONFormat.serialize_entries(entries)
    parsed = NativeJSONFormat.deserialize_entries(raw)

    assert isinstance(raw, bytes)
    assert parsed == entries


def test_bitwarden_json_export_and_import():
    entries = [
        {
            "title": "Bitwarden Demo",
            "username": "bw_user",
            "password": "bw_pass",
            "url": "https://bitwarden.com",
            "notes": "hello",
            "category": "",
            "tags": "",
        }
    ]

    raw = BitwardenJSONFormat.export(entries)
    parsed = BitwardenJSONFormat.import_data(raw)

    assert isinstance(raw, bytes)
    assert len(parsed) == 1
    assert parsed[0]["title"] == "Bitwarden Demo"
    assert parsed[0]["username"] == "bw_user"
    assert parsed[0]["password"] == "bw_pass"
    assert parsed[0]["url"] == "https://bitwarden.com"
    assert parsed[0]["notes"] == "hello"