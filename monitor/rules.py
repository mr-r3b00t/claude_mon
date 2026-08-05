"""Detection engine: flags agent behaviour that could lead to a security incident.

This is deliberately *detection, not judgement*. A finding means "a human should
be able to see that this happened" — it does not assert the action was malicious
or unauthorised. An authorised pentest and a compromise produce identical
telemetry; the point is that neither passes unseen.

Rules live in rules/default.json so they can be edited without touching code.
Correlation rules (sequences across events) are implemented here because they
need state.
"""

import hashlib
import json
import os
import re
import threading
import time

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_RULES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "default.json")

# Tools and shell constructs that mutate state rather than read it.
WRITE_TOOLS = {"Write", "Edit", "NotebookEdit"}
# NB: the redirect branch excludes `2>`, `&>`, `>/dev/null`, and the arrows in
# `=>` / `->`. Stderr suppression appears in almost every read-only command, and
# an arrow inside an echoed string is not a redirect — both made read-only
# enumeration look like persistence.
WRITE_SHELL = re.compile(
    r"((?<![0-9&=<>\-])>>?\s*(?!/dev/null|&)[^\s|&;]|\btee\b|\bcp\b|\bmv\b|\binstall\b|"
    r"\bln\s+-s|\bchmod\b|\bchown\b|\bsed\s+-i|\brm\b|\btouch\b|\bmkdir\b|"
    r"\bdefaults\s+write\b|\blaunchctl\s+(load|bootstrap)|\bcrontab\b|\bdd\b|"
    r"\btar\s+[^\n]*-[a-z]*x)", re.I)

# Editing the ruleset drags every detection pattern through the haystack, so the
# tool detects itself. The exclusion is deliberately narrow: it keys off the FILE
# BEING TOUCHED, not off any mention of a filename in the command. A substring
# check over the whole command was the first attempt and it was a real hole —
# any command could disable its own detection by naming a monitor file in a
# comment. This remains a blind spot, but only for writes to the ruleset itself.
SELF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SELF_PATHS = ("rules/default.json",)

PATH_FIELDS = ("file_path", "notebook_path", "path")


def compile_rule(r):
    # Command-line flags are case-sensitive: a case-insensitive `-F` matches
    # the `-f` in `pgrep -f`, which is not an upload.
    flags = re.M if r.get("caseSensitive") else (re.I | re.M)
    r["_re"] = [re.compile(p, flags) for p in r.get("match", [])]
    r["_not"] = [re.compile(p, flags) for p in r.get("not", [])]
    return r


def load_rules(path=None):
    with open(path or DEFAULT_RULES) as fh:
        spec = json.load(fh)
    for r in spec.get("rules", []):
        compile_rule(r)
    return spec


def validate_spec(spec):
    """Errors that would make a ruleset unusable. Empty list means it will load.

    Run before writing to disk — a ruleset that fails to compile would leave the
    detection engine dead on the next start, which is the one failure mode a
    security tool must not have.
    """
    errors = []
    if not isinstance(spec, dict):
        return ["ruleset must be a JSON object"]
    rules = spec.get("rules")
    if not isinstance(rules, list):
        return ["'rules' must be a list"]
    seen = set()
    for i, r in enumerate(rules):
        where = f"rule[{i}]"
        if not isinstance(r, dict):
            errors.append(f"{where}: must be an object")
            continue
        rid = r.get("id")
        where = rid or where
        if not rid:
            errors.append(f"{where}: missing 'id'")
        elif rid in seen:
            errors.append(f"{where}: duplicate id")
        else:
            seen.add(rid)
        if not r.get("name"):
            errors.append(f"{where}: missing 'name'")
        if r.get("severity") not in SEVERITY_ORDER:
            errors.append(f"{where}: severity must be one of {list(SEVERITY_ORDER)}")
        if not r.get("category"):
            errors.append(f"{where}: missing 'category'")
        targets = r.get("targets")
        if not isinstance(targets, list) or not targets:
            errors.append(f"{where}: 'targets' must be a non-empty list")
        else:
            bad = [t for t in targets if t not in ("tool_use", "tool_result", "proc", "net")]
            if bad:
                errors.append(f"{where}: unknown targets {bad}")
        if r.get("scan") not in (None, "command", "content", "both"):
            errors.append(f"{where}: 'scan' must be command, content or both")
        special = any(r.get(k) for k in ("scopeCheck", "egressCheck", "portCheck", "listenOnly"))
        if not r.get("match") and not special:
            errors.append(f"{where}: needs 'match' patterns (or a built-in check)")
        for key in ("match", "not"):
            for p in r.get(key) or []:
                try:
                    re.compile(p)
                except re.error as exc:
                    errors.append(f"{where}: invalid regex in '{key}': {p!r} — {exc}")
    return errors


def _allowed_dirs():
    """Session cwd plus anything the user granted in Claude Code settings."""
    dirs = []
    try:
        with open(os.path.expanduser("~/.claude/settings.json")) as fh:
            cfg = json.load(fh)
        dirs = list((cfg.get("permissions") or {}).get("additionalDirectories") or [])
    except (OSError, ValueError):
        pass
    return [os.path.realpath(os.path.expanduser(d)) for d in dirs]


class Engine:
    def __init__(self, bus, rules_path=None, dedupe_window_s=45):
        self.bus = bus
        self.rules_path = rules_path or DEFAULT_RULES
        self.spec = load_rules(rules_path)
        self.rules = self.spec["rules"]
        self.cfg = self.spec.get("settings", {})
        self.extra_dirs = _allowed_dirs()
        self.findings = []
        self.lock = threading.Lock()
        self.dedupe = {}
        self.dedupe_window_s = dedupe_window_s
        self.counts = {}
        # correlation state
        self._secret_reads = []     # (ts, sessionId, evidence)
        self._enum_events = []      # ts of discovery-ish actions

    # ---------- haystacks ----------
    # Two distinct scopes, because conflating them is a false-positive factory:
    #   command — what the agent asked the system to DO
    #   content — file bodies it wrote and output it read back
    # A command rule matched against a file body flags source code that merely
    # mentions `rm` or defines a variable named `ag`.
    CONTENT_FIELDS = ("content", "new_string", "old_string", "prompt")

    @classmethod
    def _haystack(cls, kind, d, scope="command"):
        if kind == "tool_use":
            raw = d.get("input")
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except ValueError:
                    raw = {"_": raw}
            if not isinstance(raw, dict):
                raw = {"_": raw}
            if scope == "content":
                return "\n".join(str(raw[f]) for f in cls.CONTENT_FIELDS if raw.get(f))
            args = {k: v for k, v in raw.items() if k not in cls.CONTENT_FIELDS}
            return "\n".join(str(x) for x in
                             (d.get("tool"), d.get("summary"), json.dumps(args, default=str)) if x)
        if kind == "tool_result":
            return str(d.get("text") or "") if scope == "content" else ""
        if kind == "proc":
            return str(d.get("cmd") or "") if scope == "command" else ""
        if kind == "net":
            if scope != "command":
                return ""
            return " ".join(str(x) for x in (d.get("remoteName"), d.get("remoteHost"),
                                             d.get("remotePort"), d.get("command")) if x)
        return ""

    @staticmethod
    def _is_write(kind, d):
        if kind == "tool_use":
            if d.get("tool") in WRITE_TOOLS:
                return True
            if d.get("tool") in ("Bash", "BashOutput"):
                return bool(WRITE_SHELL.search(str(d.get("summary") or "") +
                                               str(d.get("input") or "")))
            return False
        if kind == "proc":
            return bool(WRITE_SHELL.search(str(d.get("cmd") or "")))
        return False

    def _paths_in(self, d):
        """File paths named by a tool call.

        Tool input is clipped for display, so a long Write leaves invalid JSON.
        Falling back to the summary (which is the file_path for write tools) and
        to a regex keeps path-based logic working on truncated records.
        """
        out = []
        raw = d.get("input")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                for m in re.finditer(r'"(?:file_path|notebook_path|path)"\s*:\s*"([^"]+)"', raw):
                    out.append(m.group(1))
                raw = None
        if isinstance(raw, dict):
            for f in PATH_FIELDS:
                if raw.get(f):
                    out.append(str(raw[f]))
        summary = d.get("summary")
        if d.get("tool") in WRITE_TOOLS and isinstance(summary, str) and summary.startswith("/"):
            out.append(summary)
        return out

    # ---------- evaluation ----------
    def _is_self(self, kind, d):
        """True only when the event writes the ruleset file itself.

        Scoped to the path being edited. Anything broader — matching the command
        text — lets an event opt out of detection just by mentioning a filename.
        """
        if kind != "tool_use" or d.get("tool") not in WRITE_TOOLS:
            return False
        for p in self._paths_in(d):
            if any(p.endswith(sp) for sp in SELF_PATHS):
                return True
            try:
                if os.path.realpath(p).startswith(SELF_DIR + os.sep):
                    return True  # claudemon does not scan its own source tree
            except (OSError, ValueError):
                continue
        return False

    def evaluate(self, kind, d, ts=None, dedupe=True):
        """kind: tool_use | tool_result | proc | net. Returns new findings.

        `dedupe=False` bypasses the repeat-suppression window. The pre-execution
        gate MUST use it: suppression is right for a findings feed, but a gate
        that goes quiet on a repeat lets the same call through on the second
        attempt. Every gated attempt has to be judged on its own.
        """
        ts = ts or time.time()
        if self._is_self(kind, d):
            return []
        hays = {"command": self._haystack(kind, d, "command"),
                "content": self._haystack(kind, d, "content")}
        hay = hays["command"] or hays["content"]
        is_write = self._is_write(kind, d)
        out = []

        for rule in self.rules:
            if rule.get("enabled") is False:
                continue
            if kind not in rule.get("targets", []):
                continue
            if rule.get("writeOnly") and not is_write:
                continue
            scan = rule.get("scan", "command")
            scopes = ("command", "content") if scan == "both" else (scan,)
            rule_hay = "\n".join(hays[s] for s in scopes if hays[s])

            ev = None
            if rule.get("scopeCheck"):
                ev = self._scope_hit(kind, d, is_write)
            elif rule.get("egressCheck"):
                ev = self._egress_hit(kind, d)
            elif rule.get("portCheck"):
                ev = self._port_hit(kind, d)
            elif rule.get("listenOnly"):
                ev = self._listen_hit(kind, d)
            elif rule["_re"]:
                if not rule_hay:
                    continue
                for rx in rule["_re"]:
                    m = rx.search(rule_hay)
                    if m:
                        ev = m.group(0)[:200]
                        break
            if not ev:
                continue
            if any(rx.search(rule_hay or hay) for rx in rule["_not"]):
                continue

            f = self._emit(rule, kind, d, ts, ev, hay, force=not dedupe)
            if f:
                out.append(f)

        out.extend(self._correlate(kind, d, ts, out))
        return out

    def _scope_hit(self, kind, d, is_write):
        if kind != "tool_use" or not is_write:
            return None
        cwd = os.path.realpath(d.get("cwd") or os.getcwd())
        allowed = [cwd] + self.extra_dirs
        for p in self._paths_in(d):
            if not p.startswith("/"):
                continue
            rp = os.path.realpath(p)
            # /tmp and the agent's own scratch space are noise, not scope breaks.
            if rp.startswith("/tmp") or rp.startswith("/private/tmp") or rp.startswith("/var/folders"):
                continue
            if not any(rp == a or rp.startswith(a + os.sep) for a in allowed):
                return p[:200]
        return None

    def _egress_hit(self, kind, d):
        if kind != "net" or d.get("change") != "open" or not d.get("remoteHost"):
            return None
        host = f"{d.get('remoteName') or ''} {d.get('remoteHost') or ''}".lower()
        if any(a.lower() in host for a in self.cfg.get("egressAllowHosts", [])):
            return None
        # Some endpoints have no PTR record, so name-based allowlisting alone
        # leaves the model API itself looking unrecognised.
        ip = str(d.get("remoteHost") or "")
        if any(ip.startswith(pfx) for pfx in self.cfg.get("egressAllowIPs", [])):
            return None
        if str(d.get("remoteHost", "")).startswith(("127.", "::1", "192.168.", "10.", "172.")):
            return None
        return f"{d.get('remoteName') or d.get('remoteHost')}:{d.get('remotePort')}"

    def _port_hit(self, kind, d):
        if kind != "net" or d.get("change") != "open" or not d.get("remoteHost"):
            return None
        port = str(d.get("remotePort") or "")
        if port in self.cfg.get("egressAllowPorts", []) or not port:
            return None
        if str(d.get("remoteHost", "")).startswith(("127.", "::1")):
            return None
        return f"{d.get('remoteHost')}:{port}"

    def _listen_hit(self, kind, d):
        if kind != "net" or d.get("remoteHost"):
            return None
        if str(d.get("state") or "").upper() != "LISTEN":
            return None
        return f"listen {d.get('localHost')}:{d.get('localPort')} ({d.get('command')})"

    # ---------- correlation ----------
    def _correlate(self, kind, d, ts, fired):
        out = []
        cats = {f["category"] for f in fired}
        sid = d.get("sessionId")

        if "credential-access" in cats:
            self._secret_reads.append((ts, sid, fired[0]["evidence"]))
        if any(c in cats for c in ("discovery", "collection")):
            self._enum_events.append(ts)

        win = self.cfg.get("secretEgressWindowS", 180)
        self._secret_reads = [x for x in self._secret_reads if ts - x[0] <= max(win, 600)]
        self._enum_events = [t for t in self._enum_events
                             if ts - t <= self.cfg.get("enumBurstWindowS", 60)]

        # Credential access followed by outbound transfer — the exfil shape.
        if cats & {"exfiltration", "command-and-control"}:
            recent = [x for x in self._secret_reads if ts - x[0] <= win]
            if recent:
                out.append(self._emit(
                    {"id": "CHAIN-001", "name": "Credential access followed by egress",
                     "severity": "critical", "category": "exfiltration", "mitre": "T1041",
                     "rationale": "A secret was accessed and data left the host within "
                                  f"{win}s. Ordering alone is not proof, but this is the "
                                  "sequence that defines credential exfiltration.",
                     "check": "Compare what was read against what was sent. Rotate the "
                              "credential if you cannot rule the transfer out."},
                    kind, d, ts,
                    f"{len(recent)} prior credential access → {fired[0]['evidence']}",
                    "", force=True))

        # Several distinct secret stores touched in one window.
        hwin = self.cfg.get("harvestWindowS", 300)
        hits = {x[2] for x in self._secret_reads if ts - x[0] <= hwin}
        if len(hits) >= self.cfg.get("harvestThreshold", 4) and "credential-access" in cats:
            out.append(self._emit(
                {"id": "CHAIN-002", "name": "Multiple credential stores accessed",
                 "severity": "high", "category": "credential-access", "mitre": "T1552",
                 "rationale": f"{len(hits)} distinct credential locations touched within "
                              f"{hwin}s. Sweeping several stores is harvesting behaviour "
                              "rather than reading one config for a task.",
                 "check": "List the stores. A task normally needs one, not several."},
                kind, d, ts, "; ".join(sorted(hits)[:6]), "", force=True))

        # Sustained enumeration burst.
        thr = self.cfg.get("enumBurstThreshold", 120)
        if len(self._enum_events) >= thr:
            self._enum_events = []
            out.append(self._emit(
                {"id": "CHAIN-003", "name": "Sustained enumeration burst",
                 "severity": "medium", "category": "discovery", "mitre": "T1083",
                 "rationale": f"Over {thr} discovery actions in "
                              f"{self.cfg.get('enumBurstWindowS', 60)}s. Broad, fast "
                              "enumeration is how an agent maps a host before acting on it.",
                 "check": "Check what the enumeration was feeding into."},
                kind, d, ts, f"{thr}+ discovery actions", "", force=True))
        return [f for f in out if f]

    # ---------- emit ----------
    def _emit(self, rule, kind, d, ts, evidence, hay, force=False):
        key = hashlib.sha1(
            f"{rule['id']}|{evidence}|{d.get('sessionId')}".encode()).hexdigest()[:16]
        with self.lock:
            last = self.dedupe.get(key)
            if last is not None and not force and ts - last < self.dedupe_window_s:
                return None
            self.dedupe[key] = ts

        f = {
            "key": key,
            "ruleId": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "sev": SEVERITY_ORDER.get(rule["severity"], 0),
            "category": rule["category"],
            "mitre": rule.get("mitre"),
            "ts": ts,
            "source": kind,
            "evidence": evidence,
            "rationale": rule.get("rationale"),
            "check": rule.get("check"),
            "sessionId": d.get("sessionId"),
            "agentLabel": d.get("agentLabel"),
            "tool": d.get("tool"),
            "cwd": d.get("cwd"),
            "context": (self._haystack(kind, d) or hay)[:1200],
        }
        with self.lock:
            self.findings.append(f)
            if len(self.findings) > 5000:
                del self.findings[:1000]
            self.counts[f["severity"]] = self.counts.get(f["severity"], 0) + 1
        if self.bus:
            self.bus.publish("finding", f)
        return f

    # ---------- live feed ----------
    def on_event(self, kind, data):
        """Route a bus event into the engine."""
        if kind == "activity":
            ev = data.get("event")
            if ev in ("tool_use", "tool_result"):
                self.evaluate(ev, data, _epoch(data.get("ts")))
        elif kind == "proc" and data.get("change") == "spawn":
            self.evaluate("proc", data, data.get("ts"))
        elif kind == "net":
            self.evaluate("net", data, data.get("ts"))

    def reload(self, path=None):
        """Swap in a ruleset from disk without restarting.

        Findings are kept: they are a record of what happened, and discarding
        them on a config edit would lose history for no reason.
        """
        spec = load_rules(path or self.rules_path)
        errors = validate_spec(spec)
        if errors:
            raise ValueError("; ".join(errors[:5]))
        with self.lock:
            self.spec, self.rules = spec, spec["rules"]
            self.cfg = spec.get("settings", {})
        if self.bus:
            self.bus.publish("config", {"what": "rules", "rules": len(self.rules)})
        return len(self.rules)

    def snapshot(self, min_sev=0, limit=1000):
        with self.lock:
            rows = [f for f in self.findings if f["sev"] >= min_sev]
        rows.sort(key=lambda f: (f["sev"], f["ts"]), reverse=True)
        return rows[:limit]

    def summary(self):
        with self.lock:
            rows = list(self.findings)
        by_sev, by_cat, by_rule = {}, {}, {}
        for f in rows:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
            by_rule[f["ruleId"]] = by_rule.get(f["ruleId"], 0) + 1
        return {"total": len(rows), "bySeverity": by_sev, "byCategory": by_cat,
                "byRule": by_rule, "rules": len(self.rules)}


def _epoch(ts):
    if isinstance(ts, (int, float)):
        return float(ts)
    if not ts:
        return time.time()
    import datetime
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


class RuleWatcher(threading.Thread):
    """Feeds every bus event through the engine."""

    daemon = True

    def __init__(self, bus, engine):
        super().__init__(name="rule-watcher")
        self.bus = bus
        self.engine = engine
        self.sub = bus.subscribe()
        self.stop_flag = threading.Event()

    def run(self):
        import queue as _q
        while not self.stop_flag.is_set():
            try:
                ev = self.sub.get(timeout=1.0)
            except _q.Empty:
                continue
            if ev["kind"] == "finding":
                continue
            try:
                self.engine.on_event(ev["kind"], ev["data"])
            except Exception as exc:
                self.bus.publish("error", {"where": "rules", "error": repr(exc)})


def backfill(engine, sessions, agents, data_dir, limit=6000):
    """Run the ruleset over history so the Cyber tab is populated on first open."""
    from . import recorder as recorder_mod
    from . import transcript as transcript_mod

    items = []
    for s in sessions:
        if s.get("transcript"):
            for e in transcript_mod.read_tail(s["transcript"], s["sessionId"], limit):
                items.append((_epoch(e.get("ts")), e.get("event"), e))
    for a in agents:
        for e in transcript_mod.read_tail(a["transcript"], a["parentSessionId"], limit):
            e = dict(e, agentLabel=a.get("description"))
            items.append((_epoch(e.get("ts")), e.get("event"), e))
    for ev in recorder_mod.read_events(data_dir, kinds=("proc", "net")):
        d = ev.get("data") or {}
        if ev["kind"] == "proc" and d.get("change") != "spawn":
            continue
        items.append((ev.get("ts"), ev["kind"], d))

    items.sort(key=lambda x: x[0] or 0)
    # Historical findings must not be published to the bus: subscribers would
    # replay them as if they had just happened, and the "new findings" badge
    # would count the entire backlog.
    bus, engine.bus = engine.bus, None
    try:
        for ts, kind, d in items:
            if kind in ("tool_use", "tool_result", "proc", "net"):
                try:
                    engine.evaluate(kind, d, ts)
                except Exception:
                    continue
    finally:
        engine.bus = bus
    return len(engine.findings)
