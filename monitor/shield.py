"""Shield: countermeasures against agent activity.

Three actions, in increasing severity:

  freeze    SIGSTOP the process. Reversible, loses nothing, and is almost always
            the right first move — it holds the process still so a human can
            look at it. `resume` sends SIGCONT.
  kill      SIGTERM, grace period, then SIGKILL.
  sinkhole  Add a host to a blocklist. Process-level enforcement only: when a
            blocked host is contacted again, the owning process is frozen or
            killed per config. Packet-level blocking needs root, so pfctl and
            /etc/hosts snippets are GENERATED for review — claudemon never runs
            sudo, and never applies them itself.

Safety model, in order of application:

  1. mode gate      off / monitor (dry run) / armed
  2. capability     allowKill, allowFreeze, allowSinkhole
  3. target guards  pid > 1, inside the tracked agent tree, not the session
                    process, not matching a protect pattern, not the monitor
  4. rate limit     a circuit breaker that disarms rather than keeps firing

Every decision, including every refusal, is written to the audit log.
"""

import json
import os
import re
import signal
import subprocess
import threading
import time

ACTIONS = ("alert", "freeze", "resume", "kill", "sinkhole", "unsinkhole", "none")
DESTRUCTIVE = ("freeze", "kill")

DEFAULT_CONFIG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "shield.json")


def load_config(path=None):
    with open(path or DEFAULT_CONFIG) as fh:
        return json.load(fh)


class Refused(Exception):
    """A countermeasure was not performed. The reason is user-facing."""


class Shield:
    def __init__(self, bus, procs, config_path=None, data_dir="data"):
        self.bus = bus
        self.procs = procs                  # ProcWatcher: .state is the tracked tree
        self.config_path = config_path or DEFAULT_CONFIG
        self.cfg = load_config(self.config_path)
        self.data_dir = data_dir
        self.lock = threading.Lock()
        self.actions = []                   # in-memory audit tail
        self.blocked = {}                   # host/ip -> {ts, reason, hits}
        self.frozen = {}                    # pid -> {ts, cmd}
        from .egress import EgressPolicy
        self.egress = EgressPolicy(self.cfg.get("egress", {}))
        self.egress_events = []             # recent classifications, for the UI
        self._recent = []                   # action timestamps, for the rate limit
        self._tripped = False
        os.makedirs(data_dir, exist_ok=True)

    # ---------------- config ----------------
    @property
    def mode(self):
        return self.cfg.get("mode", "off")

    def set_mode(self, mode):
        if mode not in ("off", "monitor", "armed"):
            raise Refused(f"unknown mode {mode!r}")
        self.cfg["mode"] = mode
        self._tripped = False
        self._audit("mode", None, "ok", f"mode set to {mode}", actor="operator")
        return self.status()

    def set_auto(self, enabled):
        self.cfg.setdefault("auto", {})["enabled"] = bool(enabled)
        self._audit("auto", None, "ok",
                    f"auto-response {'enabled' if enabled else 'disabled'}", actor="operator")
        return self.status()

    def save_config(self):
        with open(self.config_path, "w") as fh:
            json.dump(self.cfg, fh, indent=2)

    def status(self):
        safety = self.cfg.get("safety", {})
        return {
            "mode": self.mode,
            "auto": self.cfg.get("auto", {}),
            "tripped": self._tripped,
            "frozen": [{"pid": p, **v} for p, v in self.frozen.items()],
            "blocked": [{"host": h, **v} for h, v in self.blocked.items()],
            "egress": {**self.egress.as_dict(),
                       "recent": self.egress_events[-40:][::-1],
                       "counts": self._egress_counts()},
            "recentActions": self.actions[-60:][::-1],
            "rateLimit": safety.get("maxActionsPerMinute"),
            "actionsLastMinute": len(self._recent),
            "capabilities": {
                "kill": safety.get("allowKill", False),
                "freeze": safety.get("allowFreeze", False),
                "sinkhole": safety.get("allowSinkhole", False),
            },
            "configPath": self.config_path,
        }

    def _egress_counts(self):
        out = {"blocked": 0, "allowed": 0}
        for e in self.egress_events:
            out["blocked" if e["verdict"] == "block" else "allowed"] += 1
        return out

    def egress_update(self, op, which=None, entry=None, mode=None, persist=True):
        """Operator edits to the egress lists, from the dashboard."""
        if op == "mode":
            res = self.egress.set_mode(mode)
            msg = f"egress policy mode set to {mode}"
        elif op == "add":
            res = self.egress.add(which, entry)
            msg = f"{entry} added to the egress {which} list"
        elif op == "remove":
            res = self.egress.remove(which, entry)
            msg = f"{entry} removed from the egress {which} list"
        else:
            raise Refused(f"unknown egress operation {op!r}")
        self.cfg["egress"] = self.egress.cfg
        if persist:
            try:
                self.save_config()
            except OSError as exc:
                msg += f" (in memory only — could not write config: {exc})"
        self._audit("egress-" + op, {"list": which, "entry": entry}, "ok", msg, actor="operator")
        return res

    # ---------------- guards ----------------
    def _check_rate(self):
        now = time.time()
        self._recent = [t for t in self._recent if now - t < 60]
        cap = self.cfg.get("safety", {}).get("maxActionsPerMinute", 12)
        if len(self._recent) >= cap:
            # Disarm rather than keep firing: a rule loop that acts on its own
            # side effects would otherwise take down the whole tree.
            self.cfg["mode"] = "monitor"
            self._tripped = True
            self.bus and self.bus.publish("shield", {
                "event": "circuit-breaker",
                "message": f"{cap} actions in 60s — shield disarmed to monitor mode"})
            raise Refused(f"rate limit ({cap}/min) hit — shield disarmed to monitor mode")
        self._recent.append(now)

    def _session_pids(self):
        return {p.get("root") for p in (self.procs.state or {}).values()} | {
            p["pid"] for p in (self.procs.state or {}).values() if p.get("depth") == 0}

    def check_target(self, pid, action):
        """Raise Refused unless it is safe to signal this pid."""
        safety = self.cfg.get("safety", {})
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            raise Refused("invalid pid")
        if pid <= 1:
            raise Refused("refusing to signal pid <= 1")
        if pid == os.getpid() or pid == os.getppid():
            raise Refused("refusing to signal the monitor itself")

        tree = self.procs.state or {}
        proc = tree.get(pid)
        if safety.get("requireInTree", True) and proc is None:
            raise Refused("pid is not in the tracked Claude process tree")
        cmd = (proc or {}).get("cmd", "")

        for pat in safety.get("protectPatterns", []):
            if pat and pat in cmd:
                raise Refused(f"protected process (matches {pat!r})")

        if safety.get("protectSessionProcess", True) and proc is not None:
            if proc.get("depth") == 0 or proc.get("pid") == proc.get("root"):
                raise Refused("refusing to signal the session's own process "
                              "(protectSessionProcess) — this would hang or end the session")
            if proc.get("sessionId") and proc.get("pid") in self._session_pids():
                raise Refused("refusing to signal a session root process")

        cap = {"kill": "allowKill", "freeze": "allowFreeze", "resume": "allowFreeze"}.get(action)
        if cap and not safety.get(cap, False):
            raise Refused(f"{action} is disabled in shield config ({cap}=false)")
        return proc

    # ---------------- actions ----------------
    def act(self, action, target=None, reason="", actor="operator", finding=None):
        """Single entry point. Honours mode, guards, rate limit and audit."""
        if action not in ACTIONS:
            raise Refused(f"unknown action {action!r}")
        if action in ("none", "alert"):
            return self._audit(action, target, "ok", reason, actor, finding)
        if self.mode == "off":
            return self._audit(action, target, "refused", "shield mode is off", actor, finding)

        dry = self.mode != "armed"
        try:
            if action in ("freeze", "resume", "kill"):
                proc = self.check_target((target or {}).get("pid"), action)
                if dry:
                    return self._audit(action, target, "dry-run",
                                       f"would {action} pid {target.get('pid')} "
                                       f"({(proc or {}).get('name')})", actor, finding)
                self._check_rate()
                return self._signal(action, int(target["pid"]), proc, reason, actor, finding)

            if action == "sinkhole":
                host = (target or {}).get("host")
                return self._sinkhole(host, reason, actor, finding, dry)

            if action == "unsinkhole":
                host = (target or {}).get("host")
                self.blocked.pop(host, None)
                return self._audit(action, target, "ok", f"unblocked {host}", actor, finding)
        except Refused as exc:
            return self._audit(action, target, "refused", str(exc), actor, finding)
        except Exception as exc:  # a countermeasure must never crash the monitor
            return self._audit(action, target, "error", repr(exc), actor, finding)

    def _signal(self, action, pid, proc, reason, actor, finding):
        safety = self.cfg.get("safety", {})
        name = (proc or {}).get("name", "?")
        if action == "freeze":
            os.kill(pid, signal.SIGSTOP)
            self.frozen[pid] = {"ts": time.time(), "cmd": (proc or {}).get("cmd", "")[:200]}
            after = safety.get("autoResumeAfterS", 0)
            if after:
                threading.Timer(after, self._auto_resume, args=(pid,)).start()
            return self._audit(action, {"pid": pid}, "ok",
                               f"SIGSTOP sent to {name} ({pid})"
                               + (f", auto-resume in {after}s" if after else ""),
                               actor, finding)
        if action == "resume":
            os.kill(pid, signal.SIGCONT)
            self.frozen.pop(pid, None)
            return self._audit(action, {"pid": pid}, "ok",
                               f"SIGCONT sent to {name} ({pid})", actor, finding)
        if action == "kill":
            os.kill(pid, signal.SIGTERM)
            grace = safety.get("killGraceS", 3)
            deadline = time.time() + grace
            while time.time() < deadline:
                try:
                    os.kill(pid, 0)
                except OSError:
                    return self._audit(action, {"pid": pid}, "ok",
                                       f"SIGTERM ended {name} ({pid})", actor, finding)
                time.sleep(0.1)
            os.kill(pid, signal.SIGKILL)
            self.frozen.pop(pid, None)
            return self._audit(action, {"pid": pid}, "ok",
                               f"SIGKILL after {grace}s grace — {name} ({pid})", actor, finding)

    def _auto_resume(self, pid):
        try:
            os.kill(pid, signal.SIGCONT)
            self.frozen.pop(pid, None)
            self._audit("resume", {"pid": pid}, "ok", "auto-resume timer", actor="shield")
        except OSError:
            self.frozen.pop(pid, None)

    def _sinkhole(self, host, reason, actor, finding, dry):
        sk = self.cfg.get("sinkhole", {})
        if not self.cfg.get("safety", {}).get("allowSinkhole", False):
            raise Refused("sinkhole is disabled in shield config")
        if not host:
            raise Refused("no host given")
        # egress.never is authoritative and is checked first, so an operator
        # cannot sinkhole the model API by hand any more than a policy can.
        probe = self.egress.classify({"remoteHost": host, "remoteName": host, "remotePort": ""})
        if probe["list"] == "never":
            raise Refused(f"{host} is protected by egress.never ({probe['matched']})")
        for pfx in sk.get("neverBlock", []):
            if str(host).startswith(pfx) or pfx in str(host):
                raise Refused(f"{host} is on the neverBlock list ({pfx})")
        if dry:
            return self._audit("sinkhole", {"host": host}, "dry-run",
                               f"would block {host}", actor, finding)
        self._check_rate()
        self.blocked[host] = {"ts": time.time(), "reason": reason, "hits": 0}
        notes = [f"{host} added to blocklist; enforcement={sk.get('enforcement')}"]
        if sk.get("writeFirewallRules", True):
            notes.append("rules written to " + self._write_rules())
        cmd = sk.get("applyCommand")
        if cmd:
            # Only ever a template the user configured themselves.
            out = subprocess.run(cmd.format(ip=host), shell=True, capture_output=True,
                                 text=True, timeout=15)
            notes.append(f"applyCommand rc={out.returncode} {out.stderr.strip()[:120]}")
        return self._audit("sinkhole", {"host": host}, "ok", "; ".join(notes), actor, finding)

    def _write_rules(self):
        """Emit pfctl / hosts snippets for a human to review and apply."""
        pf = os.path.join(self.data_dir, "shield-block.pf.conf")
        hosts = os.path.join(self.data_dir, "shield-block.hosts")
        ips = [h for h in self.blocked if re.match(r"^[0-9a-fA-F:.]+$", h)]
        names = [h for h in self.blocked if h not in ips]
        with open(pf, "w") as fh:
            fh.write("# Generated by claudemon. Review, then apply yourself:\n"
                     "#   sudo pfctl -t claudemon_block -T add " + " ".join(ips or ["<ip>"]) + "\n"
                     "#   sudo pfctl -f " + pf + " -e\n"
                     "table <claudemon_block> persist { " + ", ".join(ips) + " }\n"
                     "block drop quick to <claudemon_block>\n")
        with open(hosts, "w") as fh:
            fh.write("# Generated by claudemon. Append to /etc/hosts as root to sinkhole:\n")
            for n in names:
                fh.write(f"0.0.0.0 {n}\n")
        return os.path.basename(pf) + " / " + os.path.basename(hosts)

    # ---------------- enforcement + auto-response ----------------
    def on_connection(self, conn):
        """Classify an observed outbound connection against the egress policy."""
        if self.mode == "off":
            return
        if not conn.get("remoteHost"):
            return

        verdict = self.egress.classify(conn)
        # Runtime sinkholes sit on top of the configured policy: an operator
        # blocking a host from the dashboard must take effect without an edit.
        host, name = conn.get("remoteHost") or "", conn.get("remoteName") or ""
        sunk = next((h for h in self.blocked
                     if h and (host == h or host.startswith(h) or h in name)), None)
        if sunk and verdict["list"] != "never":
            self.blocked[sunk]["hits"] += 1
            verdict = {**verdict, "verdict": "block", "list": "sinkhole", "matched": sunk,
                       "reason": f"{verdict['peer']} was sinkholed by an operator",
                       "enforced": True}

        record = {**verdict, "ts": time.time(), "pid": conn.get("pid"),
                  "command": conn.get("command"), "sessionId": conn.get("sessionId")}
        if verdict["verdict"] == "block" or self.egress.cfg.get("logAllowed"):
            self.egress_events.append(record)
            if len(self.egress_events) > 500:
                del self.egress_events[:200]
            if self.bus:
                self.bus.publish("egress", record)

        if verdict["verdict"] != "block":
            return

        action = {"freeze-owner": "freeze", "kill-owner": "kill"}.get(
            self.egress.cfg.get("onViolation", "alert")
            if verdict["list"] != "sinkhole"
            else self.cfg.get("sinkhole", {}).get("enforcement", "freeze-owner"))
        if not action:
            return self._audit("egress-block", {"host": verdict["peer"], "pid": conn.get("pid")},
                               "ok", verdict["reason"], actor="shield")
        if self.egress.mode == "monitor" and verdict["list"] != "sinkhole":
            return self._audit("egress-block", {"host": verdict["peer"]}, "dry-run",
                               verdict["reason"] + " (egress policy is in monitor mode)",
                               actor="shield")
        self.act(action, {"pid": conn.get("pid")},
                 reason=f"egress policy: {verdict['reason']}", actor="shield")

    def on_finding(self, f):
        """Automatic response to a rule finding, if enabled."""
        auto = self.cfg.get("auto", {})
        if self.mode == "off" or not auto.get("enabled"):
            return
        from .rules import SEVERITY_ORDER
        if f.get("sev", 0) < SEVERITY_ORDER.get(auto.get("minSeverity", "critical"), 4):
            return
        action = (auto.get("byRule", {}).get(f.get("ruleId"))
                  or auto.get("byCategory", {}).get(f.get("category"))
                  or auto.get("bySeverity", {}).get(f.get("severity"))
                  or "alert")
        if action in ("none", "alert"):
            return self._audit(action, None, "ok",
                               f"auto: {f.get('ruleId')} {f.get('name')}",
                               actor="shield", finding=f)
        target = {}
        if action == "sinkhole":
            target = {"host": (f.get("evidence") or "").split(":")[0]}
        else:
            target = {"pid": self._pid_for_finding(f)}
            if not target["pid"]:
                return self._audit(action, None, "refused",
                                   "no process could be attributed to this finding",
                                   actor="shield", finding=f)
        return self.act(action, target,
                        reason=f"auto-response to {f.get('ruleId')}",
                        actor="shield", finding=f)

    def _pid_for_finding(self, f):
        """Best-effort: the process a finding refers to.

        Findings from `proc`/`net` carry a pid. Transcript findings do not — a
        tool call is not a process — so those cannot be auto-actioned by pid.
        """
        for key in ("pid",):
            if f.get(key):
                return f[key]
        ctx = f.get("context") or ""
        m = re.search(r"\bpid (\d+)", ctx)
        return int(m.group(1)) if m else None

    # ---------------- audit ----------------
    def _audit(self, action, target, result, message, actor="operator", finding=None):
        rec = {
            "ts": time.time(), "action": action, "target": target, "result": result,
            "message": message, "actor": actor, "mode": self.mode,
            "ruleId": (finding or {}).get("ruleId"),
            "severity": (finding or {}).get("severity"),
        }
        with self.lock:
            self.actions.append(rec)
            if len(self.actions) > 2000:
                del self.actions[:500]
        try:
            path = os.path.join(self.data_dir,
                                self.cfg.get("audit", {}).get("logFile", "shield-actions.jsonl"))
            with open(path, "a") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
        except OSError:
            pass
        if self.bus:
            self.bus.publish("shield", {"event": "action", **rec})
        return rec


class ShieldWatcher(threading.Thread):
    """Routes findings and connections into the shield."""

    daemon = True

    def __init__(self, bus, shield):
        super().__init__(name="shield-watcher")
        self.bus = bus
        self.shield = shield
        self.sub = bus.subscribe()
        self.stop_flag = threading.Event()

    def run(self):
        import queue as _q
        while not self.stop_flag.is_set():
            try:
                ev = self.sub.get(timeout=1.0)
            except _q.Empty:
                continue
            try:
                if ev["kind"] == "finding":
                    self.shield.on_finding(ev["data"])
                elif ev["kind"] == "net" and ev["data"].get("change") == "open":
                    self.shield.on_connection(ev["data"])
            except Exception as exc:
                self.bus.publish("error", {"where": "shield", "error": repr(exc)})
