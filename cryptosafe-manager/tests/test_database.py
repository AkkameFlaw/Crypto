import sqlite3

from src.database.db import SCHEMA_VERSION


def test_schema_and_user_version(db):
    with db.connection() as conn:
        cur = conn.execute("PRAGMA user_version;")
        v = int(cur.fetchone()[0])
        assert v == SCHEMA_VERSION

        for t in ("vault_entries", "audit_log", "settings", "key_store"):
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (t,))
            assert cur.fetchone() is not None


def test_insert_and_list_entries(db):
    eid = db.insert_vault_entry(
        title="Test",
        username="user",
        encrypted_password=b"\x01\x02",
        url="https://example.com",
        notes="n",
        tags="a,b",
    )
    assert isinstance(eid, int) and eid > 0
    rows = db.list_vault_entries()
    assert any(r["id"] == eid for r in rows)
