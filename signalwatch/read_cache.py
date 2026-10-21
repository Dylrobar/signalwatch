"""Small read snapshots with bounded concurrent graph work and no cached errors."""
import json
import threading
import time
from collections import OrderedDict

from fastapi import HTTPException
from starlette.responses import Response


class ReadSnapshots:
    def __init__(self, ttl=3, max_entries=16, max_bytes=4 * 1024 * 1024):
        self.ttl, self.max_entries, self.max_bytes = ttl, max_entries, max_bytes
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(2)
        self.entries, self.pending = OrderedDict(), {}
        self.generation = 0
        self.size = 0

    def clear(self):
        with self.lock:
            self.entries.clear()
            self.size = 0
            self.generation += 1

    def read(self, fn, *args):
        key = (fn.__name__, args)
        while True:
            with self.lock:
                current = self.entries.get(key)
                if current and current[0] > time.monotonic():
                    self.entries.move_to_end(key)
                    return Response(current[1], media_type='application/json', headers={'Cache-Control': 'no-store'})
                if current:
                    self.size -= len(self.entries.pop(key)[1])
                event = self.pending.get(key)
                if event is None:
                    if not self.slots.acquire(blocking=False):
                        raise HTTPException(503, 'Intelligence queries are busy; retry shortly', headers={'Retry-After': '3'})
                    event = self.pending[key] = threading.Event()
                    generation = self.generation
                    break
            if not event.wait(3):
                raise HTTPException(503, 'Intelligence query is still running; retry shortly', headers={'Retry-After': '3'})
        try:
            payload = json.dumps(fn(*args), ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
            with self.lock:
                if generation == self.generation and len(payload) <= self.max_bytes:
                    while self.entries and (len(self.entries) >= self.max_entries or self.size + len(payload) > self.max_bytes):
                        self.size -= len(self.entries.popitem(last=False)[1][1])
                    self.entries[key] = (time.monotonic() + self.ttl, payload)
                    self.size += len(payload)
            return Response(payload, media_type='application/json', headers={'Cache-Control': 'no-store'})
        finally:
            with self.lock:
                self.pending.pop(key).set()
            self.slots.release()
