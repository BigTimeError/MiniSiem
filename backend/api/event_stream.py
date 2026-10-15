import asyncio
import json
import threading


class EventBroker:
    def __init__(self):
        self.clients: set[asyncio.Queue[str]] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.lock = threading.Lock()

    def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue()

        with self.lock:
            self.clients.add(queue)

            if self.loop is None:
                self.loop = asyncio.get_running_loop()

        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        with self.lock:
            self.clients.discard(queue)

    def publish(self, event_type: str, data: dict) -> None:
        message = (
            f"event: {event_type}\n"
            f"data: {json.dumps(data)}\n\n"
        )

        with self.lock:
            loop = self.loop
            clients = list(self.clients)

        if loop is None:
            return

        for queue in clients:
            asyncio.run_coroutine_threadsafe(
                queue.put(message),
                loop,
            )


event_broker = EventBroker()
