from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Optional

from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus, UserLoggedIn, UserLoggedOut
from src.database.db import Database


@dataclass
class SessionInfo:
    logged_in_at: Optional[float] = None
    last_activity_at: Optional[float] = None
    failed_attempts: int = 0
    username: str = "local"
    unlocked: bool = False


class AuthenticationManager:
    def __init__(self, db: Database, key_manager: KeyManager, key_cache: SecureKeyCache, bus: EventBus) -> None:
        self.db = db
        self.key_manager = key_manager
        self.key_cache = key_cache
        self.bus = bus
        self.session = SessionInfo()

    def is_initialized(self) -> bool:
        return self.db.get_keystore_value("auth_hash") is not None and self.db.get_keystore_value("enc_salt") is not None

    def initialize_master_password(self, password: str) -> None:
        if self.is_initialized():
            raise ValueError("Vault is already initialized")

        auth_hash = self.key_manager.create_auth_hash(password)
        enc_salt = self.key_manager.generate_salt()
        params = self.key_manager.export_params_json()

        self.db.set_keystore_value("auth_hash", auth_hash.encode("utf-8"), version=1)
        self.db.set_keystore_value("enc_salt", enc_salt, version=1)
        self.db.set_keystore_value("params", params, version=1)

        self.db.upsert_setting("password_policy", params, encrypted=False)
        self.db.upsert_setting("auto_lock_seconds", b"3600", encrypted=False)

    def authenticate(self, password: str) -> tuple[bool, str]:
        stored_hash_raw = self.db.get_keystore_value("auth_hash")
        enc_salt = self.db.get_keystore_value("enc_salt")

        if stored_hash_raw is None or enc_salt is None:
            return False, "Vault is not initialized"

        stored_hash = stored_hash_raw.decode("utf-8", errors="ignore")

        if not self.key_manager.verify_auth_hash(password, stored_hash):
            self.session.failed_attempts += 1
            self._apply_failure_delay()
            return False, "Invalid password"

        key = self.key_manager.derive_encryption_key(password, enc_salt, purpose="vault")
        self.key_cache.set_key(key)
        self.session.unlocked = True
        self.session.logged_in_at = time.time()
        self.session.last_activity_at = time.time()
        self.session.failed_attempts = 0
        self.bus.publish(UserLoggedIn(username=self.session.username))
        return True, ""

    def logout(self) -> None:
        self.key_cache.clear()
        self.session.unlocked = False
        self.session.logged_in_at = None
        self.session.last_activity_at = None
        self.bus.publish(UserLoggedOut(username=self.session.username))

    def touch_activity(self) -> None:
        self.session.last_activity_at = time.time()
        self.key_cache.touch()

    def get_encryption_key(self) -> Optional[bytes]:
        return self.key_cache.get_key()

    def rotate_password(self, current_password: str, new_password: str, progress_callback=None) -> tuple[bool, str]:
        stored_hash_raw = self.db.get_keystore_value("auth_hash")
        old_salt = self.db.get_keystore_value("enc_salt")
        if stored_hash_raw is None or old_salt is None:
            return False, "Vault is not initialized"

        stored_hash = stored_hash_raw.decode("utf-8", errors="ignore")
        if not self.key_manager.verify_auth_hash(current_password, stored_hash):
            self._apply_failure_delay()
            return False, "Current password is invalid"

        ok, msg = self.key_manager.policy.validate_password(new_password)
        if not ok:
            return False, msg

        old_key = self.key_manager.derive_encryption_key(current_password, old_salt, purpose="vault")
        new_salt = self.key_manager.generate_salt()
        new_key = self.key_manager.derive_encryption_key(new_password, new_salt, purpose="vault")
        new_auth_hash = self.key_manager.create_auth_hash(new_password)

        try:
            self.db.rotate_vault_keys_atomic(
                old_key=old_key,
                new_key=new_key,
                progress_callback=progress_callback,
            )
            self.db.set_keystore_value("auth_hash", new_auth_hash.encode("utf-8"), version=1)
            self.db.set_keystore_value("enc_salt", new_salt, version=1)
            self.db.set_keystore_value("params", self.key_manager.export_params_json(), version=1)
            self.key_cache.set_key(new_key)
            self.session.unlocked = True
            self.session.last_activity_at = time.time()
            return True, ""
        except Exception:
            secrets.compare_digest(b"rollback", b"rollback")
            return False, "Password rotation failed"

    def _apply_failure_delay(self) -> None:
        n = self.session.failed_attempts
        if n <= 2:
            delay = 1
        elif n <= 4:
            delay = 5
        else:
            delay = 30
        time.sleep(delay)