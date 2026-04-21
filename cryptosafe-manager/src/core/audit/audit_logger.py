from __future__ import annotations

import hashlib
import json
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.core.audit.log_signer import AuditLogSigner
from src.core.events import (
    ClipboardCleared,
    ClipboardCopied,
    EntryAdded,
    EntryCreated,
    EntryDeleted,
    EntryUpdated,
    EventBus,
    UserLoggedIn,
    UserLoggedOut,
)


class AuditLogger:
    REDACT_KEYS = {
        "password",
        "master_password",
        "encryption_key",
        "key",
        "secret",
        "totp_secret",
        "clipboard_value",
        "data",
    }

    def __init__(self, bus: EventBus, db, auth_manager, user_id: str = "local-user") -> None:
        self.bus = bus
        self.db = db
        self.auth_manager = auth_manager
        self.user_id = user_id
        self.signer = AuditLogSigner(auth_manager)
        self._buffer: deque[tuple[str, str, str, dict, Optional[int]]] = deque(maxlen=500)
        self._genesis_in_progress = False

    def start(self) -> None:
        for evt in (
            EntryAdded,
            EntryCreated,
            EntryUpdated,
            EntryDeleted,
            UserLoggedIn,
            UserLoggedOut,
            ClipboardCopied,
            ClipboardCleared,
        ):
            self.bus.subscribe(evt, self._on_event)

    def _ensure_initialized(self) -> bool:
        if not self.signer.is_ready():
            return False

        if self.db.count_audit_entries() == 0 and not self._genesis_in_progress:
            self._genesis_in_progress = True
            try:
                self._write_genesis_entry()
            finally:
                self._genesis_in_progress = False

        return True

    def _write_genesis_entry(self) -> None:
        timestamp_utc = datetime.now(timezone.utc).isoformat()
        sequence_number = 0
        previous_hash = "0" * 64

        entry = {
            "timestamp": timestamp_utc,
            "event_type": "SYSTEM_GENESIS",
            "severity": "INFO",
            "user_id": "system",
            "source": "audit_logger",
            "details": {"message": "Audit log initialized"},
            "entry_id": None,
            "sequence_number": sequence_number,
            "previous_hash": previous_hash,
        }

        entry_json = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(entry_json.encode("utf-8")).hexdigest()
        sign_result = self.signer.sign(entry_json.encode("utf-8"))

        self.db.insert_audit_entry(
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            timestamp_utc=timestamp_utc,
            event_type="SYSTEM_GENESIS",
            severity="INFO",
            user_id="system",
            source="audit_logger",
            entry_id=None,
            entry_data=entry_json.encode("utf-8"),
            entry_hash=entry_hash,
            signature=sign_result.signature_hex,
            public_key=sign_result.public_key_b64,
            signing_mode=sign_result.mode,
        )

    def flush_buffer(self) -> None:
        if not self._ensure_initialized():
            return

        while self._buffer:
            event_type, severity, source, details, entry_id = self._buffer.popleft()
            self.log_event(
                event_type=event_type,
                severity=severity,
                source=source,
                details=details,
                entry_id=entry_id,
                internal=True,
            )

    def log_event(
        self,
        event_type: str,
        severity: str,
        source: str,
        details: Dict[str, Any],
        entry_id: Optional[int] = None,
        internal: bool = False,
    ) -> None:
        if not self._ensure_initialized():
            if not internal:
                self._buffer.append((event_type, severity, source, details, entry_id))
            return

        timestamp_utc = datetime.now(timezone.utc).isoformat()
        sequence_number = self.db.get_next_audit_sequence()
        previous_hash = self.db.get_last_audit_hash() or ("0" * 64)

        entry = {
            "timestamp": timestamp_utc,
            "event_type": event_type,
            "severity": severity,
            "user_id": self.user_id,
            "source": source,
            "details": self._sanitize_details(details),
            "entry_id": entry_id,
            "sequence_number": sequence_number,
            "previous_hash": previous_hash,
        }

        entry_json = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(entry_json.encode("utf-8")).hexdigest()
        sign_result = self.signer.sign(entry_json.encode("utf-8"))

        self.db.insert_audit_entry(
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            timestamp_utc=timestamp_utc,
            event_type=event_type,
            severity=severity,
            user_id=self.user_id,
            source=source,
            entry_id=entry_id,
            entry_data=entry_json.encode("utf-8"),
            entry_hash=entry_hash,
            signature=sign_result.signature_hex,
            public_key=sign_result.public_key_b64,
            signing_mode=sign_result.mode,
        )

    def verify_integrity(self, start_seq: int = 0, end_seq: Optional[int] = None) -> dict[str, Any]:
        rows = self.db.fetch_audit_entries(start_seq=start_seq, end_seq=end_seq)
        rows = sorted(rows, key=lambda r: int(r["sequence_number"]))

        results = {
            "total_entries": len(rows),
            "valid_entries": 0,
            "invalid_entries": [],
            "chain_breaks": [],
            "verified": True,
        }

        previous_hash = None

        for index, row in enumerate(rows):
            seq = int(row["sequence_number"])
            entry_data = bytes(row["entry_data"]).decode("utf-8", errors="ignore")
            entry_hash = row["entry_hash"] or ""
            previous_row_hash = row["previous_hash"] or ""
            signature = row["signature"] or ""
            public_key = row["public_key"] or ""
            signing_mode = row["signing_mode"] or "ed25519"

            if not self.signer.verify(entry_data.encode("utf-8"), signature, public_key, signing_mode):
                results["invalid_entries"].append({"sequence": seq, "reason": "Invalid signature"})
                results["verified"] = False
                continue

            computed_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()
            if computed_hash != entry_hash:
                results["invalid_entries"].append({"sequence": seq, "reason": "Hash mismatch"})
                results["verified"] = False
                continue

            if index == 0:
                if seq == 0:
                    if previous_row_hash != ("0" * 64):
                        results["chain_breaks"].append(
                            {"sequence": seq, "expected": "0" * 64, "actual": previous_row_hash}
                        )
                        results["verified"] = False
                else:
                    if previous_hash is not None and previous_row_hash != previous_hash:
                        results["chain_breaks"].append(
                            {"sequence": seq, "expected": previous_hash, "actual": previous_row_hash}
                        )
                        results["verified"] = False
            else:
                if previous_row_hash != previous_hash:
                    results["chain_breaks"].append(
                        {"sequence": seq, "expected": previous_hash, "actual": previous_row_hash}
                    )
                    results["verified"] = False

            results["valid_entries"] += 1
            previous_hash = entry_hash

        return results

    def _on_event(self, event) -> None:
        event_type = type(event).__name__
        severity = "INFO"
        source = event.__class__.__module__.split(".")[-1]
        entry_id = getattr(event, "entry_id", None)

        details = {
            k: v
            for k, v in vars(event).items()
            if not k.startswith("_")
        }

        if event_type in {"ClipboardCopied", "ClipboardCleared"}:
            source = "clipboard"
        elif event_type in {"UserLoggedIn", "UserLoggedOut"}:
            source = "authentication"
        elif event_type in {"EntryCreated", "EntryUpdated", "EntryDeleted", "EntryAdded"}:
            source = "vault"

        self.log_event(
            event_type=event_type,
            severity=severity,
            source=source,
            details=details,
            entry_id=entry_id,
        )

        if event_type == "UserLoggedIn":
            self.flush_buffer()

    def _sanitize_details(self, details: dict[str, Any]) -> dict[str, Any]:
        def scrub(value: Any, key: str = "") -> Any:
            if key.lower() in self.REDACT_KEYS:
                return "[REDACTED]"
            if isinstance(value, dict):
                return {k: scrub(v, k) for k, v in value.items()}
            if isinstance(value, list):
                return [scrub(v) for v in value]
            if isinstance(value, (bytes, bytearray)):
                return "[BINARY]"
            return value

        return scrub(details)