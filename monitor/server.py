"""Loopback HTTP server: static dashboard, JSON snapshots, SSE event stream, hook ingest."""

import json
import mimetypes
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import config as config_mod
from . import history as history_mod
from . import sessions as sessions_mod
from . import transcript as transcript_mod

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


class SessionRegistry(threading.Thread):
    """Periodically rediscovers sessions so collectors share one view."""

    daemon = True

    def __init__(self, bus, interval=2.0, max_age_s=1800):
        super().__init__(name="session-registry")
        self.bus = bus
        self.interval = interval
        self.max_age_s = max_age_s
        self.lock = threading.Lock()
        self._sessions = sessions_mod.discover(max_age_s)
        self._agents = sessions_mod.discover_subagents(max_age_s)
        self._known = {s["sessionId"]: s.get("alive") for s in self._sessions}
        self._known_agents = set()
        self.stop_flag = threading.Event()

    def get(self):
        with self.lock:
            return list(self._sessions)

    def get_agents(self):
        with self.lock:
            return list(self._agents)

    def run(self):
        while not self.stop_flag.is_set():
            try:
                found = sessions_mod.discover(self.max_age_s)
                agents = sessions_mod.discover_subagents(self.max_age_s)
                with self.lock:
                    self._sessions = found
                    self._agents = agents
                for a in agents:
                    if a["agentId"] not in self._known_agents:
                        self._known_agents.add(a["agentId"])
                        self.bus.publish("agent", {"change": "spawn", **a})
                for s in found:
                    prev = self._known.get(s["sessionId"], "__new__")
                    if prev == "__new__":
                        self.bus.publish("session", {"change": "seen", **s})
                    elif prev != s.get("alive"):
                        self.bus.publish("session", {
                            "change": "alive" if s.get("alive") else "ended", **s})
                    self._known[s["sessionId"]] = s.get("alive")
            except Exception as exc:
                self.bus.publish("error", {"where": "sessions", "error": repr(exc)})
            self.stop_flag.wait(self.interval)


class App:
    """Shared handles the HTTP handler reads from."""

    def __init__(self, bus, registry, procs, net, data_dir="data", engine=None,
                 shield=None, gate=None):
        self.bus = bus
        self.registry = registry
        self.procs = procs
        self.net = net
        self.data_dir = data_dir
        self.engine = engine
        self.shield = shield
        self.gate = gate
        self.started = time.time()
        self.hook_events = 0


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "claudemon"

        def log_message(self, fmt, *args):
            pass  # keep the console clean; errors go to the event stream

        # -- helpers -------------------------------------------------
        def _send(self, code, body, ctype="application/json", extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, default=str).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _static(self, rel):
            path = os.path.normpath(os.path.join(WEB_DIR, rel.lstrip("/")))
            if not path.startswith(WEB_DIR) or not os.path.isfile(path):
                return self._send(404, {"error": "not found"})
            ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
            with open(path, "rb") as fh:
                self._send(200, fh.read(), ctype)

        # -- routes --------------------------------------------------
        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            route = u.path

            if route == "/":
                return self._static("index.html")
            if route in ("/app.js", "/style.css", "/history.js", "/cyber.js",
                         "/shield.js", "/config.js", "/favicon.ico"):
                return self._static(route)

            if route == "/api/state":
                procs = list(app.procs.state.values())
                procs.sort(key=lambda p: (p.get("root", 0), p.get("depth", 0), p["pid"]))
                return self._send(200, {
                    "now": time.time(),
                    "uptime": time.time() - app.started,
                    "sessions": app.registry.get(),
                    "agents": app.registry.get_agents(),
                    "procs": procs,
                    "net": app.net.state,
                    "hookEvents": app.hook_events,
                    "lastSeq": app.bus.backlog(limit=1)[-1]["seq"] if app.bus.backlog(limit=1) else 0,
                })

            if route == "/api/transcript":
                sid = (q.get("session") or [None])[0]
                limit = int((q.get("limit") or ["200"])[0])
                for s in app.registry.get():
                    if s["sessionId"] == sid and s.get("transcript"):
                        return self._send(200, {
                            "sessionId": sid,
                            "events": transcript_mod.read_tail(s["transcript"], sid, limit),
                        })
                return self._send(404, {"error": "unknown session or no transcript"})

            if route == "/api/history":
                sid = (q.get("session") or [None])[0]
                limit = int((q.get("limit") or ["4000"])[0])
                sessions = app.registry.get()
                target = next((s for s in sessions if s["sessionId"] == sid), None)
                if target is None:
                    target = sessions[0] if sessions else None
                if target is None:
                    return self._send(404, {"error": "no sessions"})
                return self._send(200, history_mod.build(
                    target, app.registry.get_agents(), app.data_dir, limit))

            if route == "/api/findings":
                if not app.engine:
                    return self._send(200, {"findings": [], "summary": {}, "disabled": True})
                min_sev = int((q.get("minSev") or ["0"])[0])
                limit = int((q.get("limit") or ["800"])[0])
                return self._send(200, {
                    "findings": app.engine.snapshot(min_sev, limit),
                    "summary": app.engine.summary(),
                })

            if route == "/api/rules":
                if not app.engine:
                    return self._send(200, {"rules": []})
                return self._send(200, {
                    "settings": app.engine.cfg,
                    "rules": [{k: v for k, v in r.items() if not k.startswith("_")}
                              for r in app.engine.rules],
                })

            if route == "/api/config":
                if not app.engine:
                    return self._send(200, {"error": "detection engine disabled"})
                return self._send(200, config_mod.snapshot(app.engine, app.shield))

            if route == "/api/shield":
                if not app.shield:
                    return self._send(200, {"disabled": True})
                st = app.shield.status()
                st["gate"] = app.gate.status() if app.gate else {"enabled": False}
                return self._send(200, st)

            if route == "/api/events":
                return self._sse(int((q.get("after") or ["0"])[0]))

            return self._send(404, {"error": "not found"})

        def do_POST(self):
            u = urlparse(self.path)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return self._send(400, {"error": "bad payload"})

            if u.path == "/api/hook":
                app.hook_events += 1
                app.bus.publish("hook", payload)
                return self._send(200, {"ok": True})

            if u.path == "/api/gate":
                # Synchronous: Claude Code is blocked waiting on this. Any
                # failure here must resolve to "allow" rather than an error the
                # hook has to interpret.
                if not app.gate:
                    return self._send(200, {"decision": "allow", "reason": "gate not configured"})
                try:
                    rec = app.gate.decide(payload)
                    from . import gate as gate_mod
                    return self._send(200, {**rec, "hookResponse": gate_mod.hook_response(rec)})
                except Exception as exc:
                    app.bus.publish("error", {"where": "gate", "error": repr(exc)})
                    return self._send(200, {"decision": "allow",
                                            "reason": f"gate error, failing open: {exc!r}"})

            if u.path.startswith("/api/config/"):
                origin = self.headers.get("Origin") or ""
                if origin and (self.headers.get("Host") or "") not in origin:
                    return self._send(403, {"error": "cross-origin request refused"})
                if not app.engine:
                    return self._send(400, {"error": "detection engine disabled"})
                what = u.path.rsplit("/", 1)[-1]
                try:
                    if what == "rules":
                        ok, msgs, bak = config_mod.save_rules(app.engine, payload)
                        return self._send(200 if ok else 400,
                                          {"ok": ok, "messages": msgs, "backup": bak})
                    if what == "shield":
                        if not app.shield:
                            return self._send(400, {"error": "shield disabled"})
                        ok, msgs, bak = config_mod.save_shield(app.shield, payload)
                        return self._send(200 if ok else 400,
                                          {"ok": ok, "messages": msgs, "backup": bak})
                    if what == "test":
                        return self._send(200, config_mod.test_patterns(
                            payload.get("match"), payload.get("sample", ""),
                            payload.get("caseSensitive", False), payload.get("not")))
                    if what == "reload":
                        n = app.engine.reload()
                        return self._send(200, {"ok": True, "messages": [f"{n} rules reloaded"]})
                    if what == "restore":
                        target = (app.engine.rules_path if payload.get("of") == "rules"
                                  else app.shield.config_path)
                        config_mod.restore(target, payload.get("file", ""))
                        if payload.get("of") == "rules":
                            app.engine.reload()
                        else:
                            app.shield.cfg = config_mod.json.load(open(target))
                        return self._send(200, {"ok": True, "messages": ["restored from backup"]})
                except Exception as exc:
                    return self._send(400, {"ok": False, "messages": [str(exc)]})
                return self._send(404, {"error": "not found"})

            if u.path == "/api/shield/egress":
                if not app.shield:
                    return self._send(400, {"error": "shield disabled"})
                origin = self.headers.get("Origin") or ""
                if origin and (self.headers.get("Host") or "") not in origin:
                    return self._send(403, {"error": "cross-origin request refused"})
                try:
                    app.shield.egress_update(
                        payload.get("op"), payload.get("list"),
                        payload.get("entry"), payload.get("mode"))
                    st = app.shield.status()
                    st["gate"] = app.gate.status() if app.gate else {"enabled": False}
                    return self._send(200, st)
                except Exception as exc:
                    return self._send(400, {"error": str(exc)})

            if u.path in ("/api/shield/action", "/api/shield/mode"):
                if not app.shield:
                    return self._send(400, {"error": "shield disabled"})
                # Countermeasures are state-changing, so require a same-origin
                # POST rather than something a page could trigger cross-site.
                origin = self.headers.get("Origin") or ""
                host = self.headers.get("Host") or ""
                if origin and host not in origin:
                    return self._send(403, {"error": "cross-origin request refused"})
                try:
                    if u.path.endswith("/mode"):
                        if "auto" in payload:
                            return self._send(200, app.shield.set_auto(payload["auto"]))
                        if "gate" in payload:
                            pre = app.shield.cfg.setdefault("preExecution", {})
                            if "enabled" in payload["gate"]:
                                pre["enabled"] = bool(payload["gate"]["enabled"])
                            if payload["gate"].get("mode"):
                                pre["mode"] = payload["gate"]["mode"]
                            app.shield._audit("gate-config", None, "ok",
                                              f"gate enabled={pre.get('enabled')} "
                                              f"mode={pre.get('mode')}", actor="operator")
                            st = app.shield.status()
                            st["gate"] = app.gate.status() if app.gate else {"enabled": False}
                            return self._send(200, st)
                        return self._send(200, app.shield.set_mode(payload.get("mode")))
                    rec = app.shield.act(
                        payload.get("action"), payload.get("target") or {},
                        reason=payload.get("reason", "operator action from dashboard"),
                        actor="operator")
                    return self._send(200, {"result": rec, "status": app.shield.status()})
                except Exception as exc:
                    return self._send(400, {"error": str(exc)})

            return self._send(404, {"error": "not found"})

        def _sse(self, after):
            sub = app.bus.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                for ev in app.bus.backlog(after=after, limit=400):
                    self._emit(ev)
                last_ping = time.time()
                while True:
                    try:
                        ev = sub.get(timeout=1.0)
                        self._emit(ev)
                    except queue.Empty:
                        if time.time() - last_ping > 10:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                            last_ping = time.time()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                app.bus.unsubscribe(sub)

        def _emit(self, ev):
            data = json.dumps(ev, default=str)
            self.wfile.write(f"id: {ev['seq']}\ndata: {data}\n\n".encode())
            self.wfile.flush()

    return Handler


def serve(app, host="127.0.0.1", port=8787):
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    return httpd
