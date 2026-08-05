"""In-process pub/sub bus with a replayable ring buffer."""

import collections
import itertools
import queue
import threading
import time


class Bus:
    def __init__(self, ring_size=4000):
        self._lock = threading.Lock()
        self._subs = set()
        self._ring = collections.deque(maxlen=ring_size)
        self._seq = itertools.count(1)

    def publish(self, kind, data):
        with self._lock:
            ev = {"seq": next(self._seq), "ts": time.time(), "kind": kind, "data": data}
            self._ring.append(ev)
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass  # slow client; it will resync from the ring on reconnect
        return ev

    def subscribe(self):
        q = queue.Queue(maxsize=2000)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            self._subs.discard(q)

    def backlog(self, after=0, limit=500):
        with self._lock:
            evs = [e for e in self._ring if e["seq"] > after]
        return evs[-limit:]
