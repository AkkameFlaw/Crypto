from __future__ import annotations

import copy
import json
from pathlib import Path

from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus
from src.core.import_export import SharingService
from src.core.import_export.sharing_service import ShareOptions
from src.core.vault import AESGCMEntryEncryptionService, EntryManager
from src.database.db import Database


def main():
    print("\n=== SPRINT 6 / TEST 3 / SHARING SECURITY DEMO ===")

    db_path = Path("demo_sprint6_sharing.sqlite3")
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass

    db = Database(str(db_path))
    db.initialize()

    try:
        bus = EventBus()
        auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
        auth.initialize_master_password("StrongPass!123")
        ok, msg = auth.authenticate("StrongPass!123")
        print("1. authenticate =", ok, msg)
        if not ok:
            print("FAIL")
            return

        vault = EntryManager(db, AESGCMEntryEncryptionService(auth), bus)
        created = vault.create_entry(
            {
                "title": "Shared Entry",
                "username": "alice",
                "password": "StrongPass!999",
                "url": "https://example.com",
                "notes": "share me",
                "category": "Demo",
                "tags": "shared",
            }
        )
        print(f"2. Создана запись для шаринга: id={created.id}")

        sharing = SharingService(db, vault)

        print("3. Создание share package...")
        result = sharing.share_entry(
            int(created.id),
            ShareOptions(
                recipient="bob@example.com",
                permissions={"read_only": True, "include_notes": True},
                expires_in_days=7,
                method="password",
                password="SharePass!123",
                public_key_pem=None,
            ),
        )
        print(json.dumps(
            {
                "share_id": result["share_id"],
                "expires_at": result["expires_at"],
                "package_keys": list(result["package"].keys()),
            },
            ensure_ascii=False,
            indent=2,
        ))

        print("4. Нормальная расшифровка share package...")
        restored = sharing.import_shared_entry(
            result["package"],
            password="SharePass!123",
            save_to_vault=False,
        )
        print(json.dumps(restored, ensure_ascii=False, indent=2))

        print("5. Tampering attempt: подменяем ciphertext...")
        tampered = copy.deepcopy(result["package"])
        tampered["data"] = tampered["data"][:-4] + "AAAA"

        tamper_detected = False
        try:
            sharing.import_shared_entry(tampered, password="SharePass!123", save_to_vault=False)
        except Exception as e:
            tamper_detected = True
            print("   tampering detected:", type(e).__name__, str(e))

        if tamper_detected:
            print("RESULT: OK — подмена share package обнаружена")
        else:
            print("RESULT: FAIL — tampering не был обнаружен")

    finally:
        try:
            db.close()
        except Exception:
            pass

        try:
            if db_path.exists():
                db_path.unlink()
        except Exception:
            print(f"NOTE: demo db file left on disk: {db_path}")


if __name__ == "__main__":
    main()