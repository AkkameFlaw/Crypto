from pathlib import Path

from src.core.audit import AuditExportFormatter, AuditLogger
from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import KeyManager
from src.core.crypto.key_storage import SecureKeyCache
from src.core.events import EventBus, UserLoggedIn


def test_signed_json_export(db, tmp_path):
    bus = EventBus()
    auth = AuthenticationManager(db, KeyManager(), SecureKeyCache(), bus)
    auth.initialize_master_password("StrongPass!123")
    ok, _ = auth.authenticate("StrongPass!123")
    assert ok

    logger = AuditLogger(bus, db, auth)
    logger.start()
    bus.publish(UserLoggedIn(username="local"))
    logger.log_event("EXPORT_TEST", "INFO", "tests", {"ok": True})

    rows = db.fetch_audit_entries(limit=1000)
    out = tmp_path / "audit.json"
    AuditExportFormatter.export_signed_json(rows, str(out))
    assert out.exists()
    assert out.read_text(encoding="utf-8")