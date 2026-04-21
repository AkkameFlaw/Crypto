from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


class LogVerifier:
    def __init__(self, audit_logger) -> None:
        self.audit_logger = audit_logger

    def verify_full(self) -> dict[str, Any]:
        result = self.audit_logger.verify_integrity()
        return {
            "verified_at": datetime.now(timezone.utc).isoformat(),
            **result,
        }

    def verify_recent(self, last_n: int = 1000) -> dict[str, Any]:
        last_seq = self.audit_logger.db.get_last_audit_sequence()
        start = max(0, last_seq - max(1, last_n) + 1)
        result = self.audit_logger.verify_integrity(start_seq=start)
        return {
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "range_start": start,
            "range_end": last_seq,
            **result,
        }

    @staticmethod
    def to_pretty_text(report: dict[str, Any]) -> str:
        return json.dumps(report, ensure_ascii=False, indent=2)