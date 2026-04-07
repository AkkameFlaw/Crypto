from __future__ import annotations

import json
import time
from dataclasses import asdict

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
from src.database.db import Database


class AuditLogger:
    def __init__(self, bus: EventBus, db: Database) -> None:
        self.bus = bus
        self.db = db

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

    def _on_event(self, event) -> None:
        try:
            action = type(event).__name__
            details = json.dumps(asdict(event), ensure_ascii=False)
            entry_id = getattr(event, "entry_id", None)
            self.db.insert_audit_log(
                action=action,
                timestamp=int(time.time()),
                entry_id=int(entry_id) if entry_id is not None else None,
                details=details,
                signature=None,
            )
        except Exception:
            pass