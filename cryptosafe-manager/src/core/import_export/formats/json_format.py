from __future__ import annotations

import json
from typing import Any


class NativeJSONFormat:
    name = "encrypted_json"

    @staticmethod
    def serialize_entries(entries: list[dict[str, Any]]) -> bytes:
        payload = {"entries": entries}
        return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    @staticmethod
    def deserialize_entries(raw: bytes) -> list[dict[str, Any]]:
        data = json.loads(raw.decode("utf-8"))
        return list(data.get("entries", []))


class BitwardenJSONFormat:
    name = "bitwarden_json"

    @staticmethod
    def export(entries: list[dict[str, Any]]) -> bytes:
        items = []
        for e in entries:
            items.append(
                {
                    "type": 1,
                    "name": e.get("title", ""),
                    "notes": e.get("notes", ""),
                    "login": {
                        "username": e.get("username", ""),
                        "password": e.get("password", ""),
                        "uris": [{"uri": e.get("url", "")}] if e.get("url") else [],
                    },
                    "folderId": None,
                    "favorite": False,
                    "collectionIds": [],
                    "fields": [],
                }
            )
        payload = {
            "encrypted": False,
            "folders": [],
            "items": items,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    @staticmethod
    def import_data(raw: bytes) -> list[dict[str, Any]]:
        data = json.loads(raw.decode("utf-8"))
        result = []
        for item in data.get("items", []):
            login = item.get("login", {}) or {}
            uris = login.get("uris", []) or []
            url = ""
            if uris and isinstance(uris, list):
                first = uris[0] or {}
                url = first.get("uri", "") if isinstance(first, dict) else ""
            result.append(
                {
                    "title": item.get("name", "") or "",
                    "username": login.get("username", "") or "",
                    "password": login.get("password", "") or "",
                    "url": url,
                    "notes": item.get("notes", "") or "",
                    "category": "",
                    "tags": "",
                }
            )
        return result