from __future__ import annotations

import csv
import io
from typing import Any


class CSVFormat:
    name = "csv"

    HEADERS = ["title", "username", "password", "url", "notes", "category", "tags"]

    @staticmethod
    def export(entries: list[dict[str, Any]]) -> bytes:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=CSVFormat.HEADERS)
        writer.writeheader()
        for e in entries:
            writer.writerow(
                {
                    "title": e.get("title", ""),
                    "username": e.get("username", ""),
                    "password": e.get("password", ""),
                    "url": e.get("url", ""),
                    "notes": e.get("notes", ""),
                    "category": e.get("category", ""),
                    "tags": e.get("tags", ""),
                }
            )
        return buf.getvalue().encode("utf-8")

    @staticmethod
    def import_data(raw: bytes) -> list[dict[str, Any]]:
        text = raw.decode("utf-8-sig", errors="ignore")
        buf = io.StringIO(text)
        reader = csv.DictReader(buf)
        result = []
        for row in reader:
            result.append(
                {
                    "title": (row.get("title") or "").strip(),
                    "username": (row.get("username") or "").strip(),
                    "password": row.get("password") or "",
                    "url": (row.get("url") or "").strip(),
                    "notes": row.get("notes") or "",
                    "category": (row.get("category") or "").strip(),
                    "tags": (row.get("tags") or "").strip(),
                }
            )
        return result


class LastPassCSVFormat:
    name = "lastpass_csv"

    @staticmethod
    def import_data(raw: bytes) -> list[dict[str, Any]]:
        text = raw.decode("utf-8-sig", errors="ignore")
        buf = io.StringIO(text)
        reader = csv.DictReader(buf)
        result = []
        for row in reader:
            result.append(
                {
                    "title": (row.get("name") or row.get("url") or "").strip(),
                    "username": (row.get("username") or "").strip(),
                    "password": row.get("password") or "",
                    "url": (row.get("url") or "").strip(),
                    "notes": row.get("extra") or "",
                    "category": (row.get("grouping") or "").strip(),
                    "tags": "",
                }
            )
        return result


class LastPassCSVExportFormat:
    name = "lastpass_csv"

    HEADERS = ["url", "username", "password", "extra", "name", "grouping", "fav"]

    @staticmethod
    def export(entries: list[dict[str, Any]]) -> bytes:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=LastPassCSVExportFormat.HEADERS)
        writer.writeheader()
        for e in entries:
            writer.writerow(
                {
                    "url": e.get("url", ""),
                    "username": e.get("username", ""),
                    "password": e.get("password", ""),
                    "extra": e.get("notes", ""),
                    "name": e.get("title", ""),
                    "grouping": e.get("category", ""),
                    "fav": "0",
                }
            )
        return buf.getvalue().encode("utf-8")