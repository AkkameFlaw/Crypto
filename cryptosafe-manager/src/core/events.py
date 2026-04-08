from __future__ import annotations

import asyncio
import inspect
import threading
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Optional, Type


@dataclass(frozen=True)
class Event:
    pass


@dataclass(frozen=True)
class EntryAdded(Event):
    entry_id: int


@dataclass(frozen=True)
class EntryUpdated(Event):
    entry_id: int


@dataclass(frozen=True)
class EntryDeleted(Event):
    entry_id: int


@dataclass(frozen=True)
class EntryCreated(Event):
    entry_id: int


@dataclass(frozen=True)
class UserLoggedIn(Event):
    username: str = "local"


@dataclass(frozen=True)
class UserLoggedOut(Event):
    username: str = "local"


@dataclass(frozen=True)
class ClipboardCopied(Event):
    entry_id: Optional[int] = None
    data_type: str = "text"
    timeout_seconds: int = 30


@dataclass(frozen=True)
class ClipboardCleared(Event):
    entry_id: Optional[int] = None
    reason: str = "manual"


SyncHandler = Callable[[Event], None]
AsyncHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sync: Dict[Type[Event], List[SyncHandler]] = {}
        self._async: Dict[Type[Event], List[AsyncHandler]] = {}

    def subscribe(self, event_type: Type[Event], handler: SyncHandler | AsyncHandler) -> None:
        with self._lock:
            if inspect.iscoroutinefunction(handler):
                self._async.setdefault(event_type, []).append(handler)  # type: ignore[arg-type]
            else:
                self._sync.setdefault(event_type, []).append(handler)  # type: ignore[arg-type]

    def unsubscribe(self, event_type: Type[Event], handler: SyncHandler | AsyncHandler) -> None:
        with self._lock:
            handlers = self._async.get(event_type, []) if inspect.iscoroutinefunction(handler) else self._sync.get(event_type, [])
            if handler in handlers:
                handlers.remove(handler)

    def publish(self, event: Event) -> None:
        with self._lock:
            sync_handlers = list(self._sync.get(type(event), []))
            async_handlers = list(self._async.get(type(event), []))

        for handler in sync_handlers:
            try:
                handler(event)
            except Exception:
                pass

        if async_handlers:
            try:
                loop = asyncio.get_running_loop()
                for handler in async_handlers:
                    loop.create_task(self._safe_call_async(handler, event))
            except RuntimeError:
                pass

    async def publish_async(self, event: Event) -> None:
        with self._lock:
            sync_handlers = list(self._sync.get(type(event), []))
            async_handlers = list(self._async.get(type(event), []))

        for handler in sync_handlers:
            try:
                handler(event)
            except Exception:
                pass

        for handler in async_handlers:
            await self._safe_call_async(handler, event)

    @staticmethod
    async def _safe_call_async(handler: AsyncHandler, event: Event) -> None:
        try:
            await handler(event)
        except Exception:
            pass