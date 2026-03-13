from __future__ import annotations

import os
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional, Tuple

from src.core.crypto.placeholder import AES256Placeholder
from src.core.utils import minimal_path_permissions


SCHEMA_VERSION = 2


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
            conn.execute("PRAGMA user_version=1;")
            current = 1

        if current == 1:
            self._migration_1_to_2(conn)
            conn.execute("PRAGMA user_version=2;")
            current = 2

        if current != SCHEMA_VERSION:
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

    def _migration_1_to_2(self, conn: sqlite3.Connection) -> None:
        conn.execute("BEGIN;")
        try:
            conn.execute("ALTER TABLE key_store RENAME TO key_store_old;")

            conn.execute(
                """
                CREATE TABLE key_store (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_type TEXT NOT NULL UNIQUE,
                    key_data BLOB NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_key_store_type_v2 ON key_store(key_type);")
            now = int(time.time())

            old_exists = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='key_store_old';"
            ).fetchone()
            if old_exists:
                rows = conn.execute("SELECT key_type, salt, hash, params FROM key_store_old;").fetchall()
                for r in rows:
                    # best-effort migration from old shape
                    if r["hash"]:
                        conn.execute(
                            "INSERT OR REPLACE INTO key_store(key_type, key_data, version, created_at) VALUES (?, ?, ?, ?);",
                            ("auth_hash", r["hash"], 1, now),
                        )
                    if r["salt"]:
                        conn.execute(
                            "INSERT OR REPLACE INTO key_store(key_type, key_data, version, created_at) VALUES (?, ?, ?, ?);",
                            ("enc_salt", r["salt"], 1, now),
                        )
                    if r["params"]:
                        conn.execute(
                            "INSERT OR REPLACE INTO key_store(key_type, key_data, version, created_at) VALUES (?, ?, ?, ?);",
                            ("params", r["params"].encode("utf-8"), 1, now),
                        )
                conn.execute("DROP TABLE key_store_old;")

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
                rid = int(cur.lastrowid)
                conn.execute("COMMIT;")
                return rid
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def list_vault_entries(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute(
                "SELECT id, title, username, url, notes, created_at, updated_at, tags FROM vault_entries ORDER BY updated_at DESC;"
            )
            return [dict(r) for r in cur.fetchall()]

    def list_vault_entries_with_ciphertext(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute(
                """
                SELECT id, title, username, encrypted_password, url, notes, created_at, updated_at, tags
                FROM vault_entries ORDER BY id ASC;
                """
            )
            return [dict(r) for r in cur.fetchall()]

    def update_entry_ciphertext(self, entry_id: int, encrypted_password: bytes) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE vault_entries SET encrypted_password=?, updated_at=? WHERE id=?;",
                (sqlite3.Binary(encrypted_password), int(time.time()), int(entry_id)),
            )

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

    def set_keystore_value(self, key_type: str, key_data: bytes, version: int = 1) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO key_store(key_type, key_data, version, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key_type) DO UPDATE SET
                    key_data=excluded.key_data,
                    version=excluded.version,
                    created_at=excluded.created_at;
                """,
                (key_type, sqlite3.Binary(key_data), int(version), int(time.time())),
            )

    def get_keystore_value(self, key_type: str) -> Optional[bytes]:
        with self.connection() as conn:
            cur = conn.execute("SELECT key_data FROM key_store WHERE key_type=?;", (key_type,))
            row = cur.fetchone()
            if not row:
                return None
            return bytes(row["key_data"])

    def rotate_vault_keys_atomic(self, old_key: bytes, new_key: bytes, progress_callback=None) -> None:
        crypto = AES256Placeholder()
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                rows = conn.execute(
                    "SELECT id, encrypted_password FROM vault_entries ORDER BY id ASC;"
                ).fetchall()
                total = len(rows)
                for idx, row in enumerate(rows, start=1):
                    ct = bytes(row["encrypted_password"])
                    old_pt = AES256Placeholder._xor(ct, old_key)
                    new_ct = AES256Placeholder._xor(old_pt, new_key)
                    conn.execute(
                        "UPDATE vault_entries SET encrypted_password=?, updated_at=? WHERE id=?;",
                        (sqlite3.Binary(new_ct), int(time.time()), int(row["id"])),
                    )
                    if progress_callback:
                        progress_callback(idx, total)
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def backup(self, *_args, **_kwargs) -> None:
        raise NotImplementedError("Backup will be implemented in Sprint 8")

    def restore(self, *_args, **_kwargs) -> None:
        raise NotImplementedError("Restore will be implemented in Sprint 8")