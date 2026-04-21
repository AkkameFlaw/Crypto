from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


class AuditExportFormatter:
    @staticmethod
    def _normalize_row(row: dict) -> dict:
        normalized = dict(row)
        entry_data = normalized.get("entry_data")
        if isinstance(entry_data, (bytes, bytearray)):
            normalized["entry_data"] = entry_data.decode("utf-8", errors="ignore")
        return normalized

    @staticmethod
    def export_signed_json(rows: list[dict], output_path: str, public_key: str = "") -> str:
        normalized_rows = [AuditExportFormatter._normalize_row(r) for r in rows]
        payload = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "format": "signed-json",
            "public_key": public_key,
            "entries": normalized_rows,
        }
        path = Path(output_path)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)

    @staticmethod
    def export_csv(rows: list[dict], output_path: str) -> str:
        normalized_rows = [AuditExportFormatter._normalize_row(r) for r in rows]
        path = Path(output_path)
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "sequence_number",
                    "timestamp_utc",
                    "event_type",
                    "severity",
                    "user_id",
                    "source",
                    "entry_id",
                    "entry_hash",
                    "previous_hash",
                    "signature",
                    "signing_mode",
                    "entry_data",
                ],
            )
            writer.writeheader()
            for row in normalized_rows:
                writer.writerow(
                    {
                        "sequence_number": row.get("sequence_number"),
                        "timestamp_utc": row.get("timestamp_utc"),
                        "event_type": row.get("event_type"),
                        "severity": row.get("severity"),
                        "user_id": row.get("user_id"),
                        "source": row.get("source"),
                        "entry_id": row.get("entry_id"),
                        "entry_hash": row.get("entry_hash"),
                        "previous_hash": row.get("previous_hash"),
                        "signature": row.get("signature"),
                        "signing_mode": row.get("signing_mode"),
                        "entry_data": row.get("entry_data"),
                    }
                )
        return str(path)

    @staticmethod
    def export_pdf(rows: list[dict], output_path: str, title: str = "CryptoSafe Audit Report") -> str:
        normalized_rows = [AuditExportFormatter._normalize_row(r) for r in rows]
        path = Path(output_path)
        c = canvas.Canvas(str(path), pagesize=A4)
        width, height = A4
        y = height - 40

        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, title)
        y -= 25

        c.setFont("Helvetica", 9)
        c.drawString(40, y, f"Generated: {datetime.now(timezone.utc).isoformat()}")
        y -= 20

        for row in normalized_rows:
            line = (
                f"#{row.get('sequence_number')} | {row.get('timestamp_utc')} | "
                f"{row.get('severity')} | {row.get('event_type')} | {row.get('source')}"
            )
            c.drawString(40, y, line[:110])
            y -= 14
            if y < 50:
                c.showPage()
                c.setFont("Helvetica", 9)
                y = height - 40

        c.save()
        return str(path)