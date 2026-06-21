from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator

from sentinel.api.worker import ScanQueue


async def event_generator(
    scan_id: str, queue: ScanQueue
) -> AsyncGenerator[str, None]:
    sent_events = 0
    while True:
        events = queue.get_events(scan_id)
        while sent_events < len(events):
            event = events[sent_events]
            sent_events += 1
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") in ("scan_completed", "error"):
                return
        await asyncio.sleep(0.5)
