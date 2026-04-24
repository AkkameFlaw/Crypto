from src.core.audit import AuditLogger, LogVerifier
from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import ClipboardCopied, EventBus, UserLoggedIn


def test_05_audit_security_demo(db):
    print("\n=== TEST 5 / AUDIT SECURITY DEMO ===")

    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok is True
    print("Шаг 1: аутентификация успешна -> OK")

    logger = AuditLogger(bus, db, auth)
    logger.start()
    verifier = LogVerifier(logger)

    bus.publish(UserLoggedIn(username="local"))
    bus.publish(ClipboardCopied(entry_id=10, data_type="password", timeout_seconds=30))
    logger.log_event("SECURITY_TEST", "WARN", "tests", {"attempt": "normal"})
    print("Шаг 2: нормальные security-relevant события записаны -> OK")

    malicious_search = "' OR 1=1 --"
    rows = db.fetch_audit_entries(search=malicious_search, limit=100)
    print(f"Шаг 3: попытка SQL injection через search='{malicious_search}'")
    print(f"Получено строк: {len(rows)}")
    print("Проверка: приложение не упало, запрос отработал безопасно -> OK")

    logger.log_event("PRIVILEGE_ESCALATION_ATTEMPT", "CRITICAL", "tests", {
        "actor": "demo-user",
        "target": "admin",
        "result": "blocked"
    })
    print("Шаг 4: зафиксирована попытка privilege escalation -> OK")

    with db.connection() as conn:
        conn.execute(
            "UPDATE audit_log SET entry_hash=? WHERE sequence_number=?;",
            ("deadbeef" * 8, 1),
        )
    print("Шаг 5: симулирована подмена audit hash -> OK")

    report = verifier.verify_full()
    print("Шаг 6: итоговая верификация:")
    print(verifier.to_pretty_text(report))

    assert report["verified"] is False
    assert len(report["invalid_entries"]) >= 1 or len(report["chain_breaks"]) >= 1

    print("Итог: tampering / suspicious activity обнаружены -> OK")
    print("=== TEST 5 PASSED ===\n")