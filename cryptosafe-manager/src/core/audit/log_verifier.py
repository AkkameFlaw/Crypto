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
            "user_id": self.audit_logger.user_id,
            **result,
        }

    def verify_recent(self, last_n: int = 1000) -> dict[str, Any]:
        last_seq = self.audit_logger.db.get_last_audit_sequence()
        start = max(0, last_seq - max(1, last_n) + 1)
        result = self.audit_logger.verify_integrity(start_seq=start)
        return {
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "user_id": self.audit_logger.user_id,
            "range_start": start,
            "range_end": last_seq,
            **result,
        }

    @staticmethod
    def to_pretty_text(report: dict[str, Any]) -> str:
        lines = [
            "=== AUDIT LOG VERIFICATION REPORT ===",
            f"Verified at: {report.get('verified_at', '-')}",
            f"User: {report.get('user_id', '-')}",
            f"Verified: {report.get('verified', False)}",
            f"Total entries: {report.get('total_entries', 0)}",
            f"Valid entries: {report.get('valid_entries', 0)}",
            f"Invalid entries: {len(report.get('invalid_entries', []))}",
            f"Chain breaks: {len(report.get('chain_breaks', []))}",
        ]

        if "range_start" in report and "range_end" in report:
            lines.append(f"Range: {report['range_start']} .. {report['range_end']}")

        invalid_entries = report.get("invalid_entries", [])
        if invalid_entries:
            lines.append("")
            lines.append("Invalid entries:")
            for item in invalid_entries[:10]:
                lines.append(f"  - seq={item.get('sequence')} reason={item.get('reason')}")

        chain_breaks = report.get("chain_breaks", [])
        if chain_breaks:
            lines.append("")
            lines.append("Chain breaks:")
            for item in chain_breaks[:10]:
                lines.append(
                    f"  - seq={item.get('sequence')} expected={item.get('expected')} actual={item.get('actual')}"
                )

        lines.append("")
        lines.append("Raw JSON:")
        lines.append(json.dumps(report, ensure_ascii=False, indent=2))

        return "\n".join(lines)