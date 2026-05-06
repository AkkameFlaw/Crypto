from __future__ import annotations

import json
from pathlib import Path

from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus
from src.core.import_export import VaultExporter, VaultImporter
from src.core.import_export.importer import ImportOptions
from src.core.vault import AESGCMEntryEncryptionService, EntryManager
from src.database.db import Database


def main():
    print("\n=== SPRINT 6 / TEST 1 / ROUND-TRIP DEMO ===")

    db_path = Path("demo_sprint6_roundtrip.sqlite3")
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

        print("1. Инициализация мастер-пароля...")
        auth.initialize_master_password("StrongPass!123")
        ok, msg = auth.authenticate("StrongPass!123")
        print("   authenticate =", ok, msg)
        if not ok:
            print("FAIL: не удалось открыть vault")
            return

        vault = EntryManager(db, AESGCMEntryEncryptionService(auth), bus)

        print("2. Создание тестовых записей...")
        demo_entries = [
            {
                "title": "GitHub",
                "username": "alice@example.com",
                "password": "StrongPass!111",
                "url": "https://github.com",
                "notes": "Dev account",
                "category": "Work",
                "tags": "git,dev",
            },
            {
                "title": "Gmail",
                "username": "alice@gmail.com",
                "password": "StrongPass!222",
                "url": "https://mail.google.com",
                "notes": "Personal mail",
                "category": "Personal",
                "tags": "mail,google",
            },
        ]
        for item in demo_entries:
            created = vault.create_entry(item)
            print(f"   created entry id={created.id} title={item['title']}")

        before = vault.get_all_entries()
        print(f"   всего записей до экспорта: {len(before)}")

        print("3. Экспорт в encrypted_json...")
        exporter = VaultExporter(vault, auth)
        package = exporter.export_vault(password="ExportPass!123")
        raw = json.dumps(package, ensure_ascii=False).encode("utf-8")
        print(f"   размер экспортного пакета: {len(raw)} байт")

        print("4. Dry-run импорт того же файла...")
        importer = VaultImporter(vault)
        preview = importer.import_data(
            raw,
            import_format="encrypted_json",
            password="ExportPass!123",
            options=ImportOptions(dry_run=True),
        )
        print(json.dumps(preview, ensure_ascii=False, indent=2))

        print("5. Replace-import для проверки полного round-trip...")
        result = importer.import_data(
            raw,
            import_format="encrypted_json",
            password="ExportPass!123",
            options=ImportOptions(mode="replace", dry_run=False),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))

        after = vault.get_all_entries()
        print(f"6. Всего записей после импорта: {len(after)}")
        for row in after:
            print(f"   - {row['title']} | {row['username']} | {row['url']}")

        ok_titles = {row["title"] for row in after}
        if len(after) == 2 and {"GitHub", "Gmail"} <= ok_titles:
            print("RESULT: OK — round-trip успешно прошёл")
        else:
            print("RESULT: FAIL — данные после импорта не совпали")

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