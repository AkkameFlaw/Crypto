import json

from src.core.audit import AuditLogger
from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus, UserLoggedIn


def test_audit_integrity_detects_tampering(db):
    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    logger = AuditLogger(bus, db, auth)
    logger.start()

    bus.publish(UserLoggedIn(username="local"))
    logger.log_event("TEST_EVENT", "INFO", "tests", {"value": 123})
    logger.log_event("TEST_EVENT", "INFO", "tests", {"value": 456})

    report_ok = logger.verify_integrity()
    assert report_ok["verified"] is True

    with db.connection() as conn:
        conn.execute(
            "UPDATE audit_log SET entry_data=? WHERE sequence_number=?;",
            (b'{"tampered":true}', 1),
        )

    report_bad = logger.verify_integrity()
    assert report_bad["verified"] is False
    assert len(report_bad["invalid_entries"]) >= 1