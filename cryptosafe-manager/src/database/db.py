from __future__ import annotations

import os
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional, Tuple

from ..core.utils import minimal_path_permissions


SCHEMA_VERSION = 1


class DatabaseError(Exception):
    pass


class Database:

    def __init__(self, path: str, pool_size: int = 4, timeout: float = 5.0) -> None:
        self.path = path
        self.pool_size = max(1, int(pool_size))
        self.timeout = float(timeout)
        self._pool: "queue.Queue[sqlite3.Connection]" = queue.Queue(maxsize=self.pool_size)
        self._init_lock = threading.Lock()
        self._initialized = False

    def initialize(self) -> None:
        with self._init_lock:
            if self._initialized:
                return
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)

            conn = self._new_connection()
            try:
                self._apply_migrations(conn)
            finally:
                conn.close()

            for _ in range(self.pool_size):
                self._pool.put(self._new_connection())

            minimal_path_permissions(self.path)
            self._initialized = True

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path,
            timeout=self.timeout,
            check_same_thread=False,
            isolation_level=None,
        )
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _apply_migrations(self, conn: sqlite3.Connection) -> None:
        cur = conn.execute("PRAGMA user_version;")
        row = cur.fetchone()
        current = int(row[0]) if row else 0

        if current == 0:
            self._migration_0_to_1(conn)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION};")

        elif current == SCHEMA_VERSION:
            return
        else:
            raise DatabaseError("Unsupported database schema version")

    def _migration_0_to_1(self, conn: sqlite3.Connection) -> None:
        conn.execute("BEGIN;")
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password BLOB NOT NULL,
                    url TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    tags TEXT NOT NULL DEFAULT ''
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_title ON vault_entries(title);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_username ON vault_entries(username);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at ON vault_entries(updated_at);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    entry_id INTEGER NULL,
                    details TEXT NOT NULL DEFAULT '',
                    signature BLOB NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id ON audit_log(entry_id);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    setting_key TEXT NOT NULL UNIQUE,
                    setting_value BLOB NOT NULL,
                    encrypted INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS key_store (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_type TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    hash BLOB NOT NULL,
                    params TEXT NOT NULL DEFAULT '{}'
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_key_store_type ON key_store(key_type);")

            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        if not self._initialized:
            self.initialize()

        conn = None
        try:
            conn = self._pool.get(timeout=self.timeout)
            yield conn
        except queue.Empty as e:
            raise DatabaseError("DB connection pool exhausted") from e
        finally:
            if conn is not None:
                self._pool.put(conn)


    def insert_vault_entry(
        self,
        title: str,
        username: str,
        encrypted_password: bytes,
        url: str = "",
        notes: str = "",
        tags: str = "",
    ) -> int:
        now = int(time.time())
        with self.connection() as conn:
            conn.execute("BEGIN;")
            try:
                cur = conn.execute(
                    """
                    INSERT INTO vault_entries
                    (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (title, username, sqlite3.Binary(encrypted_password), url, notes, now, now, tags),
                )
                entry_id = int(cur.lastrowid)
                conn.execute("COMMIT;")
                return entry_id
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def list_vault_entries(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute(
                "SELECT id, title, username, url, notes, created_at, updated_at, tags FROM vault_entries ORDER BY updated_at DESC;"
            )
            return [dict(r) for r in cur.fetchall()]

    def insert_audit_log(
        self,
        action: str,
        timestamp: int,
        entry_id: Optional[int],
        details: str,
        signature: Optional[bytes],
    ) -> int:
        with self.connection() as conn:
            conn.execute("BEGIN;")
            try:
                cur = conn.execute(
                    """
                    INSERT INTO audit_log(action, timestamp, entry_id, details, signature)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (action, int(timestamp), entry_id, details, sqlite3.Binary(signature) if signature else None),
                )
                rid = int(cur.lastrowid)
                conn.execute("COMMIT;")
                return rid
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def upsert_setting(self, key: str, value: bytes, encrypted: bool) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO settings(setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value=excluded.setting_value,
                    encrypted=excluded.encrypted;
                """,
                (key, sqlite3.Binary(value), 1 if encrypted else 0),
            )

    def get_setting(self, key: str) -> Optional[Tuple[bytes, int]]:
        with self.connection() as conn:
            cur = conn.execute("SELECT setting_value, encrypted FROM settings WHERE setting_key=?;", (key,))
            row = cur.fetchone()
            if not row:
                return None
            return (bytes(row["setting_value"]), int(row["encrypted"]))


    def backup(self, *_args, **_kwargs) -> None:
        raise NotImplementedError("Backup will be implemented in Sprint 8")

    def restore(self, *_args, **_kwargs) -> None:
        raise NotImplementedError("Restore will be implemented in Sprint 8")
