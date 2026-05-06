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


BITWARDEN_SAMPLE = {
    "encrypted": False,
    "folders": [],
    "items": [
        {
            "type": 1,
            "name": "Bitwarden Demo",
            "notes": "Imported from Bitwarden",
            "login": {
                "username": "bw_user",
                "password": "BWpass!123",
                "uris": [{"uri": "https://bitwarden.com"}],
            },
            "folderId": None,
            "favorite": False,
            "collectionIds": [],
            "fields": [],
        }
    ],
}

LASTPASS_CSV_SAMPLE = """url,username,password,extra,name,grouping
https://example.com,last_user,LPpass!123,"secure note",LastPass Demo,Imported
"""


def main():
    print("\n=== SPRINT 6 / TEST 2 / INTEROPERABILITY DEMO ===")

    db_path = Path("demo_sprint6_interop.sqlite3")
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
        importer = VaultImporter(vault)

        print("\n2. Импорт Bitwarden JSON...")
        result_bw = importer.import_data(
            json.dumps(BITWARDEN_SAMPLE).encode("utf-8"),
            import_format="bitwarden_json",
            options=ImportOptions(mode="merge", dry_run=False),
        )
        print(json.dumps(result_bw, ensure_ascii=False, indent=2))

        print("\n3. Импорт LastPass CSV...")
        result_lp = importer.import_data(
            LASTPASS_CSV_SAMPLE.encode("utf-8"),
            import_format="lastpass_csv",
            options=ImportOptions(mode="merge", dry_run=False),
        )
        print(json.dumps(result_lp, ensure_ascii=False, indent=2))

        print("\n4. Проверка записей в vault...")
        entries = vault.get_all_entries()
        for row in entries:
            print(f"   - {row['title']} | {row['username']} | {row['url']}")

        print("\n5. Экспорт обратно в native encrypted JSON...")
        exporter = VaultExporter(vault, auth)
        package = exporter.export_vault(password="InteropPass!123")
        print(json.dumps(
            {
                "cryptosafe_export": package.get("cryptosafe_export"),
                "entry_count": package.get("entry_count"),
                "format": package.get("format"),
                "algorithm": package.get("encryption", {}).get("algorithm"),
            },
            ensure_ascii=False,
            indent=2,
        ))

        titles = {e["title"] for e in entries}
        if "Bitwarden Demo" in titles and "LastPass Demo" in titles:
            print("RESULT: OK — interop импорт/экспорт работает")
        else:
            print("RESULT: FAIL — interop сценарий не пройден")

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