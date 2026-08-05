#!/usr/bin/env python3
"""claudemon — watch what Claude Code is doing, live.

Streams reasoning, tool calls, tool results, token usage, spawned processes,
network connections and debug logs to a local web dashboard.

    ./claudemon.py                 # dashboard on http://127.0.0.1:8787
    ./claudemon.py --tui           # terminal stream instead of the web UI
    ./claudemon.py --port 9000 --open
"""

import argparse
import json
import os
import sys
import threading
import time
import webbrowser

from monitor.bus import Bus
from monitor.debuglog import DebugLogWatcher
from monitor.net import NetWatcher
from monitor.procs import ProcWatcher
from monitor.recorder import Recorder
from monitor.rules import Engine, RuleWatcher, backfill
from monitor.server import App, SessionRegistry, serve
from monitor.gate import Gate
from monitor.shield import Shield, ShieldWatcher

DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

RESET = "\033[0m"
COLOURS = {
    "thinking": "\033[38;5;140m",
    "text": "\033[38;5;250m",
    "tool_use": "\033[38;5;39m",
    "tool_result": "\033[38;5;245m",
    "prompt": "\033[38;5;220m",
    "usage": "\033[38;5;108m",
    "spawn": "\033[38;5;208m",
    "exit": "\033[38;5;95m",
    "open": "\033[38;5;44m",
    "close": "\033[38;5;95m",
    "hook": "\033[38;5;213m",
    "debug": "\033[38;5;242m",
    "error": "\033[38;5;196m",
}


def build(args):
    bus = Bus(ring_size=args.ring)
    registry = SessionRegistry(bus, interval=args.session_interval, max_age_s=args.max_age)
    procs = ProcWatcher(bus, registry.get, interval=args.proc_interval,
                        include_desktop=args.include_desktop)
    net = NetWatcher(bus, lambda: procs.pids, lambda: procs.state, interval=args.net_interval)
    # Imported late so --no-transcript can skip the watcher entirely.
    from monitor.transcript import TranscriptWatcher

    transcripts = TranscriptWatcher(bus, registry.get, registry.get_agents,
                                    interval=args.tail_interval)

    registry.start()
    procs.start()
    net.start()
    if not args.no_record:
        Recorder(bus, args.data_dir).start()
    if not args.no_transcript:
        transcripts.start()
    if not args.no_debug_log:
        DebugLogWatcher(bus, extra_globs=args.debug_glob).start()

    engine = None
    if not args.no_rules:
        engine = Engine(bus, args.rules)
        if not args.no_backfill:
            n = backfill(engine, registry.get(), registry.get_agents(), args.data_dir)
            print(f"  ruleset: {len(engine.rules)} rules, {n} findings from history", flush=True)
        RuleWatcher(bus, engine).start()

    shield = None
    if not args.no_shield:
        shield = Shield(bus, procs, args.shield_config, args.data_dir)
        if args.shield_mode:
            shield.cfg["mode"] = args.shield_mode
        ShieldWatcher(bus, shield).start()
        auto = shield.cfg.get("auto", {}).get("enabled")
        print(f"  shield: mode={shield.mode} auto-response={'on' if auto else 'off'}", flush=True)
        if shield.mode == "armed":
            print("  ⚠  ARMED — countermeasures will execute against the agent process tree", flush=True)

    gate = None
    if shield and engine and not args.no_gate:
        gate = Gate(engine, shield, bus)
        if args.gate_mode:
            shield.cfg.setdefault("preExecution", {})["mode"] = args.gate_mode
            shield.cfg["preExecution"]["enabled"] = args.gate_mode != "off"
        pre = shield.cfg.get("preExecution", {})
        print(f"  pre-exec gate: {'on' if gate.enabled() else 'off'} "
              f"mode={pre.get('mode')} fail={pre.get('failMode')}", flush=True)
        if gate.enabled() and pre.get("mode") in ("ask", "block"):
            print("  ⚠  gate can interrupt tool calls — requires the PreToolUse hook "
                  "(python3 install-hooks.py --apply)", flush=True)
    return bus, registry, procs, net, engine, shield, gate


def run_tui(bus, args):
    """Plain-text live stream — useful over ssh or beside the web UI."""
    sub = bus.subscribe()
    colour = sys.stdout.isatty() and not args.no_colour

    def paint(key, s):
        return f"{COLOURS.get(key, '')}{s}{RESET}" if colour else s

    print(paint("usage", "claudemon — streaming. Ctrl-C to stop.\n"))
    while True:
        ev = sub.get()
        t = time.strftime("%H:%M:%S", time.localtime(ev["ts"]))
        kind, d = ev["kind"], ev["data"]
        line = None
        if kind == "activity":
            e = d.get("event")
            sid = (d.get("sessionId") or "?")[:8]
            if d.get("agentLabel"):
                sid = f"🤖{d['agentLabel'][:18]}"
            if e == "thinking":
                line = paint(e, f"[{t}] {sid} 🧠 {d['text'][:args.width]}")
            elif e == "text":
                line = paint(e, f"[{t}] {sid} 💬 {d['text'][:args.width]}")
            elif e == "tool_use":
                line = paint(e, f"[{t}] {sid} 🔧 {d['tool']}: {d['summary'][:args.width]}")
            elif e == "tool_result":
                mark = "❌" if d.get("isError") else "↩︎"
                line = paint(e, f"[{t}] {sid} {mark} {(d.get('text') or '')[:args.width]}")
            elif e == "prompt":
                line = paint(e, f"[{t}] {sid} 👤 {d['text'][:args.width]}")
            elif e == "usage":
                u = d.get("usage") or {}
                line = paint(e, f"[{t}] {sid} 📊 {d.get('model')} in={u.get('input_tokens')} "
                                f"out={u.get('output_tokens')} cr={u.get('cache_read_input_tokens')} "
                                f"cw={u.get('cache_creation_input_tokens')}")
        elif kind == "proc":
            line = paint(d["change"], f"[{t}] {'⊕' if d['change'] == 'spawn' else '⊖'} "
                                      f"pid {d['pid']} {d['cmd'][:args.width]}")
        elif kind == "net":
            line = paint(d["change"], f"[{t}] {'🌐' if d['change'] == 'open' else '🔌'} "
                                      f"{d['command']}[{d['pid']}] → "
                                      f"{d.get('remoteHost')}:{d.get('remotePort')} {d.get('state','')}")
        elif kind == "hook":
            line = paint("hook", f"[{t}] 🪝 {d.get('hook_event_name')} {d.get('tool_name','')}")
        elif kind == "debug":
            line = paint("debug", f"[{t}] 🐞 {d['line'][:args.width]}")
        elif kind == "error":
            line = paint("error", f"[{t}] ‼️  {d.get('where')}: {d.get('error')}")
        elif kind == "session":
            line = paint("usage", f"[{t}] ▶ session {d.get('name')} {d['change']} "
                                  f"pid={d.get('pid')} cwd={d.get('cwd')}")
        elif kind == "agent":
            line = paint("hook", f"[{t}] 🤖 agent {d['change']}: {d.get('description')} "
                                 f"({d.get('agentType')})")
        elif kind == "gate":
            icon = {"block": "⛔", "ask": "❓", "warn": "⚠"}.get(d.get("decision"), "🚦")
            line = paint("error" if d.get("decision") == "block" else "prompt",
                         f"[{t}] {icon} gate {d.get('decision').upper()} {d.get('tool')} "
                         f"— {str(d.get('reason'))[:args.width]}")
        elif kind == "shield":
            icon = {"freeze": "🧊", "kill": "💀", "resume": "▶", "sinkhole": "🕳"}.get(d.get("action"), "🛡")
            line = paint("error" if d.get("result") == "ok" else "prompt",
                         f"[{t}] {icon} shield {d.get('action')} [{d.get('result')}] "
                         f"{str(d.get('message'))[:args.width]}")
        elif kind == "finding":
            from monitor.rules import SEVERITY_ORDER
            if d.get("sev", 0) >= SEVERITY_ORDER.get(args.min_sev, 1):
                sev = d["severity"].upper()
                colour = "error" if d["sev"] >= 3 else "prompt" if d["sev"] == 2 else "debug"
                line = paint(colour, f"[{t}] 🚨 {sev:<8} {d['ruleId']} {d['name']} "
                                     f"— {str(d.get('evidence'))[:args.width]}")
        if line:
            print(line, flush=True)


def main():
    p = argparse.ArgumentParser(description="Monitor Claude Code in near-real time.")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default loopback)")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--tui", action="store_true", help="stream to the terminal instead of serving the UI")
    p.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    p.add_argument("--max-age", type=int, default=1800,
                   help="seconds of transcript mtime staleness still counted as a session")
    p.add_argument("--tail-interval", type=float, default=0.25)
    p.add_argument("--proc-interval", type=float, default=1.0)
    p.add_argument("--net-interval", type=float, default=2.0)
    p.add_argument("--session-interval", type=float, default=2.0)
    p.add_argument("--ring", type=int, default=4000, help="events kept for replay")
    p.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                   help="where recorded process/network history is kept")
    p.add_argument("--no-record", action="store_true",
                   help="do not persist events (History tab loses proc/net detail)")
    p.add_argument("--include-desktop", action="store_true",
                   help="also watch the Claude desktop app's process tree (noisy)")
    p.add_argument("--no-transcript", action="store_true")
    p.add_argument("--no-debug-log", action="store_true")
    p.add_argument("--debug-glob", action="append", default=[],
                   help="extra log file glob to tail (repeatable)")
    p.add_argument("--shield-config", default=None, help="path to shield.json")
    p.add_argument("--shield-mode", default=None, choices=["off", "monitor", "armed"],
                   help="override the configured shield mode for this run")
    p.add_argument("--no-shield", action="store_true", help="disable countermeasures entirely")
    p.add_argument("--gate-mode", default=None, choices=["off", "warn", "ask", "block"],
                   help="pre-execution gate: strongest verdict it may return")
    p.add_argument("--no-gate", action="store_true", help="disable the pre-execution gate")
    p.add_argument("--rules", default=None, help="path to a ruleset JSON (default rules/default.json)")
    p.add_argument("--no-rules", action="store_true", help="disable the detection engine")
    p.add_argument("--no-backfill", action="store_true",
                   help="do not run the ruleset over existing history at startup")
    p.add_argument("--min-sev", default="low",
                   choices=["info", "low", "medium", "high", "critical"],
                   help="TUI: minimum severity to print")
    p.add_argument("--no-colour", action="store_true")
    p.add_argument("--width", type=int, default=160, help="TUI truncation width")
    p.add_argument("--json", action="store_true", help="TUI: emit raw JSON lines")
    args = p.parse_args()

    bus, registry, procs, net, engine, shield, gate = build(args)

    if args.tui and args.json:
        sub = bus.subscribe()
        while True:
            print(json.dumps(sub.get(), default=str), flush=True)

    if args.tui:
        try:
            run_tui(bus, args)
        except KeyboardInterrupt:
            print("\nbye")
        return

    app = App(bus, registry, procs, net, args.data_dir, engine, shield, gate)
    httpd = serve(app, args.host, args.port)
    url = f"http://{args.host}:{args.port}/"
    print(f"claudemon → {url}", flush=True)
    print(f"  sessions found: {len(registry.get())}   (Ctrl-C to stop)")
    if args.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
