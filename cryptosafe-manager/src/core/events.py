from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, DefaultDict, Dict, List, Type


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
class UserLoggedIn(Event):
    username: str = "local"


@dataclass(frozen=True)
class UserLoggedOut(Event):
    username: str = "local"


@dataclass(frozen=True)
class ClipboardCopied(Event):
    entry_id: int


@dataclass(frozen=True)
class ClipboardCleared(Event):
    entry_id: int


SyncHandler = Callable[[Event], None]
AsyncHandler = Callable[[Event], Awaitable[None]]


class EventBus:

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sync: Dict[Type[Event], List[SyncHandler]] = {}
        self._async: Dict[Type[Event], List[AsyncHandler]] = {}

    def subscribe(self, event_type: Type[Event], handler: SyncHandler | AsyncHandler) -> None:
        with self._lock:
            if asyncio.iscoroutinefunction(handler):
                self._async.setdefault(event_type, []).append(handler)
            else:
                self._sync.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: Type[Event], handler: SyncHandler | AsyncHandler) -> None:
        with self._lock:
            if asyncio.iscoroutinefunction(handler):
                handlers = self._async.get(event_type, [])
            else:
                handlers = self._sync.get(event_type, [])
            if handler in handlers:
                handlers.remove(handler)

    def publish(self, event: Event) -> None:

        sync_handlers: List[SyncHandler] = []
        async_handlers: List[AsyncHandler] = []
        with self._lock:
            sync_handlers = list(self._sync.get(type(event), []))
            async_handlers = list(self._async.get(type(event), []))

        for h in sync_handlers:
            try:
                h(event)
            except Exception:
                # Do not leak details.
                pass

        if async_handlers:
            try:
                loop = asyncio.get_running_loop()
                for ah in async_handlers:
                    loop.create_task(self._safe_call_async(ah, event))
            except RuntimeError:
                pass

    async def publish_async(self, event: Event) -> None:

        sync_handlers: List[SyncHandler] = []
        async_handlers: List[AsyncHandler] = []
        with self._lock:
            sync_handlers = list(self._sync.get(type(event), []))
            async_handlers = list(self._async.get(type(event), []))

        for h in sync_handlers:
            try:
                h(event)
            except Exception:
                pass

        for ah in async_handlers:
            await self._safe_call_async(ah, event)

    @staticmethod
    async def _safe_call_async(handler: AsyncHandler, event: Event) -> None:
        try:
            await handler(event)
        except Exception:
            pass