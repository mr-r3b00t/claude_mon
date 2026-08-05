"""Network watcher: sockets held by the Claude process tree, via lsof."""

import socket
import subprocess
import threading
import time


def parse_name(name):
    """'192.168.1.2:50589->1.2.3.4:443 (ESTABLISHED)' -> (local, remote, state).

    Done by partitioning rather than a regex: host parts contain ':' (IPv6) and
    '-' (the '->' separator), which makes a greedy pattern swallow the arrow.
    """
    name = name.strip()
    state = None
    if name.endswith(")"):
        i = name.rfind("(")
        if i != -1:
            state = name[i + 1:-1]
            name = name[:i].strip()
    local, sep, remote = name.partition("->")
    return local.strip(), (remote.strip() if sep else None), state


def _split_hostport(s):
    if not s:
        return None, None
    s = s.strip()
    if s.startswith("["):  # IPv6 literal
        host, _, port = s[1:].partition("]:")
        return host, port
    host, _, port = s.rpartition(":")
    return host, port


class DNSCache:
    """Best-effort reverse DNS, resolved off the polling thread."""

    def __init__(self):
        self.map = {}
        self.pending = set()
        self.lock = threading.Lock()

    def get(self, ip):
        with self.lock:
            if ip in self.map:
                return self.map[ip]
            if ip in self.pending or not ip:
                return None
            self.pending.add(ip)
        threading.Thread(target=self._resolve, args=(ip,), daemon=True).start()
        return None

    def _resolve(self, ip):
        name = None
        try:
            name = socket.gethostbyaddr(ip)[0]
        except OSError:
            name = None
        with self.lock:
            self.map[ip] = name
            self.pending.discard(ip)


def lsof_for(pids, timeout=8):
    if not pids:
        return []
    cmd = ["lsof", "-nP", "-w", "-i", "-a", "-p", ",".join(str(p) for p in pids)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return []
    conns = []
    for line in res.stdout.splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        command, pid, _user, fd, ftype, _dev, _size, proto, name = parts
        local, remote, state = parse_name(name)
        if ":" not in local:
            continue
        lhost, lport = _split_hostport(local)
        rhost, rport = _split_hostport(remote)
        try:
            pid = int(pid)
        except ValueError:
            continue
        conns.append({
            "pid": pid,
            "command": command,
            "fd": fd,
            "family": ftype,
            "proto": proto,
            "localHost": lhost, "localPort": lport,
            "remoteHost": rhost, "remotePort": rport,
            "state": state or ("LISTEN" if not rhost else ""),
            "key": f"{pid}/{fd}/{lhost}:{lport}->{rhost}:{rport}",
        })
    return conns


class NetWatcher(threading.Thread):
    daemon = True

    def __init__(self, bus, pids_fn, procs_fn, interval=2.0):
        super().__init__(name="net-watcher")
        self.bus = bus
        self.pids_fn = pids_fn
        self.procs_fn = procs_fn
        self.interval = interval
        self.dns = DNSCache()
        self.prev = {}
        self.state = []
        self.primed = False
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            try:
                self.tick()
            except Exception as exc:
                self.bus.publish("error", {"where": "net", "error": repr(exc)})
            self.stop_flag.wait(self.interval)

    def tick(self):
        procs = self.procs_fn()
        conns = lsof_for(self.pids_fn())
        for c in conns:
            p = procs.get(c["pid"]) or {}
            c["sessionId"] = p.get("sessionId")
            c["procCmd"] = p.get("cmd", "")
            if c["remoteHost"]:
                c["remoteName"] = self.dns.get(c["remoteHost"])
        cur = {c["key"]: c for c in conns}
        now = time.time()
        if self.primed:  # the first tick is the baseline, not a burst of opens
            for key, c in cur.items():
                if key not in self.prev and c.get("remoteHost"):
                    self.bus.publish("net", {"change": "open", "ts": now, **c})
            for key, c in self.prev.items():
                if key not in cur and c.get("remoteHost"):
                    self.bus.publish("net", {"change": "close", "ts": now, **c})
        self.primed = True
        self.prev = cur
        self.state = conns
