"""Tails Claude Code debug logs (~/.claude/debug/*.txt, written when run with --debug)."""

import glob
import os
import threading

DEBUG_GLOB = os.path.expanduser("~/.claude/debug/*.txt")


class _FileTail:
    def __init__(self, path):
        self.path = path
        self.buf = b""
        try:
            self.offset = os.path.getsize(path)
        except OSError:
            self.offset = 0

    def read_new(self):
        lines = []
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return lines
        if size < self.offset:
            self.offset, self.buf = 0, b""
        if size == self.offset:
            return lines
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.offset)
                self.buf += fh.read()
                self.offset = fh.tell()
        except OSError:
            return lines
        *complete, self.buf = self.buf.split(b"\n")
        for line in complete:
            line = line.decode("utf-8", "replace").rstrip()
            if line:
                lines.append(line)
        return lines


class DebugLogWatcher(threading.Thread):
    daemon = True

    def __init__(self, bus, interval=0.5, extra_globs=()):
        super().__init__(name="debuglog-watcher")
        self.bus = bus
        self.interval = interval
        self.globs = [DEBUG_GLOB, *extra_globs]
        self.tails = {}
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            try:
                self.tick()
            except Exception as exc:
                self.bus.publish("error", {"where": "debuglog", "error": repr(exc)})
            self.stop_flag.wait(self.interval)

    def tick(self):
        for pattern in self.globs:
            for path in glob.glob(os.path.expanduser(pattern)):
                if os.path.islink(path):
                    path = os.path.realpath(path)
                if path not in self.tails:
                    self.tails[path] = _FileTail(path)
                for line in self.tails[path].read_new():
                    self.bus.publish("debug", {"file": os.path.basename(path), "line": line[:2000]})
