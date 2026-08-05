"""Tails session .jsonl transcripts and normalises them into activity events.

This is where reasoning (thinking blocks), tool calls, tool results and token
usage come from. Claude Code appends one JSON record per content block, so
tailing gives near-real-time visibility as the turn is produced.
"""

import collections
import json
import os
import threading
import time

MAX_TEXT = 4000
MAX_INPUT = 2000

# Field of a tool's input that best summarises what it is about to do.
TOOL_SUMMARY_FIELDS = {
    "Bash": ("command",),
    "Read": ("file_path",),
    "Write": ("file_path",),
    "Edit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
    "Glob": ("pattern",),
    "Grep": ("pattern",),
    "WebFetch": ("url",),
    "WebSearch": ("query",),
    "Agent": ("description", "subagent_type"),
    "Task": ("description",),
    "Skill": ("skill", "args"),
    "Workflow": ("name",),
}


def _clip(s, n):
    if not isinstance(s, str):
        s = json.dumps(s, default=str)
    return s if len(s) <= n else s[:n] + f"… [+{len(s) - n} chars]"


def summarise_tool(name, tool_input):
    if not isinstance(tool_input, dict):
        return _clip(tool_input, 200)
    for field in TOOL_SUMMARY_FIELDS.get(name, ()):
        if tool_input.get(field):
            return _clip(tool_input[field], 200)
    for field in ("command", "file_path", "path", "url", "query", "pattern", "description"):
        if tool_input.get(field):
            return _clip(tool_input[field], 200)
    return _clip(tool_input, 200)


def _content_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
            elif isinstance(c, str):
                parts.append(c)
        return "\n".join(parts)
    return ""


def dedupe_usage(events, seen_reqs):
    """Claude Code repeats the same `usage` on every content-block record of one
    request. Keep the first per requestId so token counters do not over-count.

    `seen_reqs` is a caller-owned deque used as a bounded recent-set.
    """
    out = []
    for ev in events:
        if ev.get("event") == "usage":
            rid = ev.get("requestId")
            if rid:
                if rid in seen_reqs:
                    continue
                seen_reqs.append(rid)
        out.append(ev)
    return out


def normalise(rec, session_id):
    """Turn one transcript record into zero or more activity events."""
    out = []
    rtype = rec.get("type")
    ts = rec.get("timestamp")
    base = {
        "sessionId": rec.get("sessionId") or session_id,
        "ts": ts,
        "uuid": rec.get("uuid"),
        "cwd": rec.get("cwd"),
        "sidechain": bool(rec.get("isSidechain")),
        "agentId": rec.get("agentId"),
    }

    if rtype == "assistant":
        msg = rec.get("message") or {}
        model = msg.get("model")
        for c in msg.get("content") or []:
            ctype = c.get("type")
            if ctype == "thinking":
                out.append({**base, "event": "thinking", "model": model,
                            "text": _clip(c.get("thinking", ""), MAX_TEXT)})
            elif ctype == "text":
                out.append({**base, "event": "text", "model": model,
                            "text": _clip(c.get("text", ""), MAX_TEXT)})
            elif ctype == "tool_use":
                name = c.get("name", "?")
                out.append({**base, "event": "tool_use", "model": model,
                            "tool": name, "toolUseId": c.get("id"),
                            "summary": summarise_tool(name, c.get("input")),
                            "input": _clip(c.get("input", {}), MAX_INPUT)})
        usage = msg.get("usage")
        if usage:
            out.append({**base, "event": "usage", "model": model,
                        "effort": rec.get("effort"),
                        "requestId": rec.get("requestId"),
                        "stopReason": msg.get("stop_reason"),
                        "usage": usage})

    elif rtype == "user":
        content = (rec.get("message") or {}).get("content")
        blocks = content if isinstance(content, list) else []
        results = [c for c in blocks
                   if isinstance(c, dict) and c.get("type") == "tool_result"]
        res = rec.get("toolUseResult")

        # Main-session records carry a top-level `toolUseResult`; subagent
        # records do NOT — they only have tool_result blocks inside the message
        # content. Keying off the top-level field alone silently drops every
        # subagent tool result, so drive off the blocks and treat the top-level
        # field as a fallback.
        if results:
            top_err = isinstance(res, dict) and (res.get("is_error") or res.get("isError"))
            for c in results:
                out.append({**base, "event": "tool_result",
                            "toolUseId": c.get("tool_use_id"),
                            "isError": bool(c.get("is_error") or top_err),
                            "text": _clip(_content_text(c.get("content")) or c.get("content"),
                                          MAX_TEXT)})
        elif res is not None:
            out.append({**base, "event": "tool_result", "toolUseId": None,
                        "isError": bool(isinstance(res, dict)
                                        and (res.get("is_error") or res.get("isError"))),
                        "text": _clip(res, MAX_TEXT)})
        else:
            text = _content_text(content)
            if text.strip():
                out.append({**base, "event": "prompt", "text": _clip(text, MAX_TEXT),
                            "source": rec.get("promptSource")})

    elif rtype == "attachment":
        att = rec.get("attachment") or {}
        out.append({**base, "event": "attachment", "attachType": att.get("type"),
                    "text": _clip(att, 400)})

    elif rtype in ("ai-title", "custom-title"):
        out.append({**base, "event": "title",
                    "text": rec.get("aiTitle") or rec.get("customTitle")})

    elif rtype == "queue-operation":
        out.append({**base, "event": "queue", "op": rec.get("operation"),
                    "text": _clip(rec.get("content", ""), 300)})

    elif rtype == "system":
        out.append({**base, "event": "system", "text": _clip(rec.get("content", rec), 800)})

    return out


class Tailer:
    """Byte-offset tail of a single transcript file."""

    def __init__(self, path, session_id, from_end=True, extra=None):
        self.path = path
        self.session_id = session_id
        self.extra = extra or {}
        self.offset = 0
        self.buf = b""
        self.inode = None
        self.seen_reqs = collections.deque(maxlen=64)
        if from_end:
            try:
                st = os.stat(path)
                self.offset = st.st_size
                self.inode = st.st_ino
            except OSError:
                pass

    def read_new(self):
        events = []
        try:
            st = os.stat(self.path)
        except OSError:
            return events
        if self.inode is not None and st.st_ino != self.inode:
            self.offset, self.buf, self.inode = 0, b"", st.st_ino  # rotated
        elif self.inode is None:
            self.inode = st.st_ino
        if st.st_size < self.offset:
            self.offset, self.buf = 0, b""  # truncated
        if st.st_size == self.offset:
            return events
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.offset)
                chunk = fh.read()
                self.offset = fh.tell()
        except OSError:
            return events
        self.buf += chunk
        *lines, self.buf = self.buf.split(b"\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                continue
            evs = dedupe_usage(normalise(rec, self.session_id), self.seen_reqs)
            if self.extra:
                for ev in evs:
                    ev.update(self.extra)
            events.extend(evs)
        return events


def read_tail(path, session_id, limit=200):
    """Normalised events from the end of a transcript (for initial page load)."""
    try:
        with open(path, "rb") as fh:
            try:
                fh.seek(-2_000_000, os.SEEK_END)
                fh.readline()
            except OSError:
                fh.seek(0)
            raw = fh.read()
    except OSError:
        return []
    events = []
    seen_reqs = collections.deque(maxlen=4096)
    for line in raw.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            continue
        events.extend(dedupe_usage(normalise(rec, session_id), seen_reqs))
    return events[-limit:]


class TranscriptWatcher(threading.Thread):
    """Keeps a Tailer per live transcript and publishes normalised events."""

    daemon = True

    def __init__(self, bus, sessions_fn, agents_fn=None, interval=0.25):
        super().__init__(name="transcript-watcher")
        self.bus = bus
        self.sessions_fn = sessions_fn
        self.agents_fn = agents_fn or (lambda: [])
        self.interval = interval
        self.tailers = {}
        self.primed = False
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            try:
                self.tick()
            except Exception as exc:  # a collector must never kill the monitor
                self.bus.publish("error", {"where": "transcript", "error": repr(exc)})
            self.stop_flag.wait(self.interval)

    def _targets(self):
        """(path, session_id, extra) for every transcript worth tailing."""
        for s in self.sessions_fn():
            if s.get("transcript"):
                yield s["transcript"], s["sessionId"], {}
        for a in self.agents_fn():
            yield a["transcript"], a["parentSessionId"], {
                "agentId": a["agentId"],
                "agentType": a.get("agentType"),
                "agentLabel": a.get("description"),
                "spawnDepth": a.get("spawnDepth"),
            }

    def tick(self):
        for path, sid, extra in self._targets():
            t = self.tailers.get(path)
            if t is None:
                # Transcripts already present when the monitor started are
                # seeded at EOF (no history replay). Files that appear later —
                # notably subagent transcripts, which are created mid-run — are
                # read from byte 0 so their opening records are not lost.
                t = Tailer(path, sid, from_end=not self.primed, extra=extra)
                self.tailers[path] = t
            for ev in t.read_new():
                ev["_recv"] = time.time()
                self.bus.publish("activity", ev)
        self.primed = True
