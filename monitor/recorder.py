"""Persists non-transcript events to disk so history survives a restart.

Transcript activity is deliberately NOT recorded — the .jsonl transcripts are
already durable and authoritative, and re-reading them keeps this log small.
Process and network events exist only in memory otherwise, so they are what
needs persisting.
"""

import json
import os
import queue
import threading
import time

RECORDED_KINDS = ("proc", "net", "hook", "session", "agent", "error")


class Recorder(threading.Thread):
    daemon = True

    def __init__(self, bus, data_dir, kinds=RECORDED_KINDS, max_bytes=64 * 1024 * 1024):
        super().__init__(name="recorder")
        self.bus = bus
        self.data_dir = data_dir
        self.kinds = set(kinds)
        self.max_bytes = max_bytes
        self.sub = bus.subscribe()
        self.stop_flag = threading.Event()
        os.makedirs(data_dir, exist_ok=True)

    def path_for(self, ts):
        return os.path.join(self.data_dir,
                            "events-%s.jsonl" % time.strftime("%Y%m%d", time.localtime(ts)))

    def run(self):
        fh, cur = None, None
        try:
            while not self.stop_flag.is_set():
                try:
                    ev = self.sub.get(timeout=1.0)
                except queue.Empty:
                    if fh:
                        fh.flush()
                    continue
                if ev["kind"] not in self.kinds:
                    continue
                path = self.path_for(ev["ts"])
                if path != cur:
                    if fh:
                        fh.close()
                    fh, cur = open(path, "a"), path
                if os.path.getsize(cur) < self.max_bytes:
                    fh.write(json.dumps(ev, default=str) + "\n")
        finally:
            if fh:
                fh.close()


def read_events(data_dir, since=None, until=None, days=2, kinds=None, limit=200_000):
    """Recorded events across the last `days` files, optionally time-filtered."""
    out = []
    try:
        files = sorted(f for f in os.listdir(data_dir)
                       if f.startswith("events-") and f.endswith(".jsonl"))
    except OSError:
        return out
    for name in files[-days:]:
        try:
            with open(os.path.join(data_dir, name)) as fh:
                for line in fh:
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    if kinds and ev.get("kind") not in kinds:
                        continue
                    ts = ev.get("ts") or 0
                    if since is not None and ts < since:
                        continue
                    if until is not None and ts > until:
                        continue
                    out.append(ev)
                    if len(out) >= limit:
                        return out
        except OSError:
            continue
    return out
