from src.core.audit import AuditLogger, LogVerifier
from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus, UserLoggedIn


def test_04_audit_failure_recovery_demo(db):
    print("\n=== TEST 4 / AUDIT FAILURE RECOVERY DEMO ===")

    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok is True
    print("Шаг 1: vault разблокирован -> OK")

    logger = AuditLogger(bus, db, auth)
    logger.start()
    verifier = LogVerifier(logger)

    bus.publish(UserLoggedIn(username="local"))
    logger.log_event("TEST4_EVENT_A", "INFO", "tests", {"step": "A"})
    logger.log_event("TEST4_EVENT_B", "WARN", "tests", {"step": "B"})
    logger.log_event("TEST4_EVENT_C", "ERROR", "tests", {"step": "C"})
    print("Шаг 2: создано несколько audit entries -> OK")

    report_before = verifier.verify_full()
    print("Шаг 3: верификация до повреждения:")
    print(verifier.to_pretty_text(report_before))
    assert report_before["verified"] is True

    with db.connection() as conn:
        conn.execute(
            "UPDATE audit_log SET entry_data=? WHERE sequence_number=?;",
            (b'{"corrupted":true}', 2),
        )
    print("Шаг 4: симулировано повреждение БД (tampering) -> OK")

    report_after = verifier.verify_full()
    print("Шаг 5: верификация после повреждения:")
    print(verifier.to_pretty_text(report_after))

    assert report_after["verified"] is False
    assert len(report_after["invalid_entries"]) >= 1

    print("Итог: повреждение корректно обнаружено -> OK")
    print("=== TEST 4 PASSED ===\n")