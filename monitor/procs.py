"""Process-tree watcher: every process under a Claude session, plus spawn/exit events."""

import subprocess
import threading
import time

PS_CMD = ["ps", "-Ao", "pid=,ppid=,pcpu=,pmem=,rss=,etime=,stat=,command="]
# The claude-code agent process itself (this is what runs your tools).
CLAUDE_MARKERS = ("claude-code/", "/bin/claude", "/claude.js")
# The Electron desktop shell that may host it — noisy, opt-in via --include-desktop.
DESKTOP_MARKERS = ("/Claude.app/Contents/MacOS/Claude",)


COMM_CMD = ["ps", "-Ao", "pid=,comm="]


def _comm_map():
    """pid -> executable path. Separate call because both `comm` and `command`
    can contain spaces, so they cannot be split apart in one ps line."""
    out = {}
    try:
        raw = subprocess.run(COMM_CMD, capture_output=True, text=True, timeout=8).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    for line in raw.splitlines():
        pid, _, comm = line.strip().partition(" ")
        try:
            out[int(pid)] = comm.strip()
        except ValueError:
            continue
    return out


def snapshot_all():
    """All processes on the box, keyed by pid."""
    try:
        out = subprocess.run(PS_CMD, capture_output=True, text=True, timeout=8).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    comms = _comm_map()
    procs = {}
    for line in out.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8:
            continue
        pid, ppid, pcpu, pmem, rss, etime, stat, cmd = parts
        try:
            pid, ppid = int(pid), int(ppid)
        except ValueError:
            continue
        procs[pid] = {
            "pid": pid,
            "ppid": ppid,
            "cpu": float(pcpu or 0),
            "mem": float(pmem or 0),
            "rssKb": int(rss or 0),
            "etime": etime,
            "state": stat,
            "cmd": cmd[:400],
            "exe": comms.get(pid, ""),
            "name": (comms.get(pid) or cmd).rsplit("/", 1)[-1][:40] or "?",
        }
    return procs


def find_claude_roots(procs, include_desktop=False):
    markers = CLAUDE_MARKERS + (DESKTOP_MARKERS if include_desktop else ())
    return [p["pid"] for p in procs.values()
            if any(m in p["cmd"] for m in markers)]


def descendants(procs, roots):
    """roots + everything beneath them, with depth and owning root recorded."""
    children = {}
    for p in procs.values():
        children.setdefault(p["ppid"], []).append(p["pid"])
    seen = {}
    for root in roots:
        stack = [(root, 0)]
        while stack:
            pid, depth = stack.pop()
            if pid in seen or pid not in procs:
                continue
            entry = dict(procs[pid])
            entry["depth"] = depth
            entry["root"] = root
            seen[pid] = entry
            for kid in children.get(pid, []):
                stack.append((kid, depth + 1))
    return seen


def _owning_session(pid, procs, sess_by_pid, max_hops=24):
    """Nearest ancestor (including self) that is a known session pid."""
    hops = 0
    while pid and pid > 1 and hops < max_hops:
        if pid in sess_by_pid:
            return sess_by_pid[pid]
        parent = procs.get(pid)
        if not parent:
            return None
        pid = parent["ppid"]
        hops += 1
    return None


class ProcWatcher(threading.Thread):
    daemon = True

    def __init__(self, bus, sessions_fn, interval=1.0, include_desktop=False):
        super().__init__(name="proc-watcher")
        self.bus = bus
        self.sessions_fn = sessions_fn
        self.interval = interval
        self.include_desktop = include_desktop
        self.prev = {}
        self.state = {}
        self.pids = []
        self.primed = False
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            try:
                self.tick()
            except Exception as exc:
                self.bus.publish("error", {"where": "procs", "error": repr(exc)})
            self.stop_flag.wait(self.interval)

    def tick(self):
        allprocs = snapshot_all()
        if not allprocs:
            return
        sess = self.sessions_fn()
        roots = set(find_claude_roots(allprocs, self.include_desktop))
        for s in sess:
            if s.get("pid") and s.get("alive"):
                roots.add(int(s["pid"]))
        sess_by_pid = {int(s["pid"]): s["sessionId"] for s in sess if s.get("pid")}
        tree = descendants(allprocs, sorted(roots))
        for pid, p in tree.items():
            p["sessionId"] = _owning_session(pid, allprocs, sess_by_pid)

        now = time.time()
        if self.primed:  # the first tick is the baseline, not a burst of spawns
            for pid, p in tree.items():
                if pid not in self.prev:
                    self.bus.publish("proc", {"change": "spawn", "ts": now, **p})
            for pid, p in self.prev.items():
                if pid not in tree:
                    self.bus.publish("proc", {"change": "exit", "ts": now, **p})
        self.primed = True
        self.prev = tree
        self.state = tree
        self.pids = sorted(tree)
