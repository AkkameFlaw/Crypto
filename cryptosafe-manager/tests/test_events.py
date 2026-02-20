import asyncio

from src.core.events import EventBus, EntryAdded


def test_event_bus_sync_handler():
    bus = EventBus()
    seen = []

    def handler(evt):
        seen.append(evt.entry_id)

    bus.subscribe(EntryAdded, handler)
    bus.publish(EntryAdded(entry_id=123))
    assert seen == [123]


def test_event_bus_async_handler():
    bus = EventBus()
    seen = []

    async def handler(evt):
        await asyncio.sleep(0)
        seen.append(evt.entry_id)

    bus.subscribe(EntryAdded, handler)

    async def run():
        await bus.publish_async(EntryAdded(entry_id=7))

    asyncio.run(run())
    assert seen == [7]
