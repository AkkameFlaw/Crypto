from __future__ import annotations

import json
import time
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
    print("\n=== SPRINT 6 / TEST 5 / PERFORMANCE DEMO ===")

    db_path = Path("demo_sprint6_performance.sqlite3")
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

        print("2. Создание 1000 записей...")
        t_create_0 = time.perf_counter()
        for i in range(1000):
            vault.create_entry(
                {
                    "title": f"Site {i}",
                    "username": f"user{i}@example.com",
                    "password": f"Pass!{i:04d}Strong",
                    "url": f"https://example{i}.com",
                    "notes": f"note {i}",
                    "category": "Perf",
                    "tags": "perf,test",
                }
            )
        t_create = time.perf_counter() - t_create_0
        print(f"   create time = {t_create:.3f} sec")

        exporter = VaultExporter(vault, auth)

        print("3. Export 1000 entries...")
        t0 = time.perf_counter()
        package = exporter.export_vault(password="PerfExport!123")
        export_time = time.perf_counter() - t0
        raw = json.dumps(package, ensure_ascii=False).encode("utf-8")
        print(f"   export time = {export_time:.3f} sec")
        print(f"   export size = {len(raw)} bytes")

        print("4. Import preview 1000 entries...")
        importer = VaultImporter(vault)
        t1 = time.perf_counter()
        preview = importer.import_data(
            raw,
            import_format="encrypted_json",
            password="PerfExport!123",
            options=ImportOptions(dry_run=True),
        )
        import_time = time.perf_counter() - t1
        print(f"   import preview time = {import_time:.3f} sec")
        print(json.dumps(preview["summary"], ensure_ascii=False, indent=2))

        print("5. Performance thresholds:")
        print("   expected export < 5 sec")
        print("   expected import < 10 sec")

        export_ok = export_time < 5.0
        import_ok = import_time < 10.0

        print(f"   export_ok = {export_ok}")
        print(f"   import_ok = {import_ok}")

        if export_ok and import_ok and preview["summary"]["detected_entries"] == 1000:
            print("RESULT: OK — performance test passed")
        else:
            print("RESULT: FAIL — performance thresholds not met")

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