#!/usr/bin/env python3
"""Claude Code hook -> claudemon.

Two jobs, depending on the event:

  PreToolUse   Ask the monitor for a verdict BEFORE the tool runs and act on it.
               This is synchronous — Claude Code is waiting — so it is bounded
               by a short timeout and fails open by default.

  everything   Fire-and-forget telemetry. Never blocks, never delays.
  else

Failure handling is the important part. If the monitor is down, slow, or
returns nonsense, the default is to ALLOW: a monitoring tool must not wedge the
agent when it is not running. Set preExecution.failMode to "closed" in
shield.json if you would rather stop than proceed unobserved.

Exit codes: 0 = proceed, 2 = block (Claude Code reads stderr for the reason).
The structured JSON verdict is also written to stdout, so the decision lands
whichever convention the running version honours.
"""

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("CLAUDEMON_URL", "http://127.0.0.1:8787").rstrip("/")
if BASE.endswith("/api/hook"):                      # tolerate the older setting
    BASE = BASE[: -len("/api/hook")]
HOOK_URL = BASE + "/api/hook"
GATE_URL = BASE + "/api/gate"
TELEMETRY_TIMEOUT = float(os.environ.get("CLAUDEMON_TIMEOUT", "0.4"))
GATE_TIMEOUT = float(os.environ.get("CLAUDEMON_GATE_TIMEOUT", "1.5"))
MAX_BYTES = 256 * 1024


def post(url, payload, timeout):
    req = urllib.request.Request(
        url, data=json.dumps(payload, default=str).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def allow(reason=""):
    if reason:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "allow",
            "permissionDecisionReason": reason}}))
    sys.exit(0)


def gate(payload):
    try:
        res = post(GATE_URL, payload, GATE_TIMEOUT)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # Monitor unreachable or too slow.
        if os.environ.get("CLAUDEMON_FAIL") == "closed":
            sys.stderr.write(
                "claudemon pre-execution gate unreachable and fail mode is CLOSED "
                f"({exc}). Refusing the call. Start claudemon, or set "
                "preExecution.failMode to \"open\" in shield.json.\n")
            sys.exit(2)
        allow()

    decision = (res.get("decision") or "allow") if isinstance(res, dict) else "allow"
    response = res.get("hookResponse") if isinstance(res, dict) else None
    if response:
        print(json.dumps(response))
    if decision == "block":
        sys.stderr.write((response or {}).get("reason")
                         or res.get("reason") or "Blocked by claudemon.")
        sys.stderr.write("\n")
        sys.exit(2)
    sys.exit(0)


def main():
    try:
        raw = sys.stdin.read(MAX_BYTES)
        payload = json.loads(raw) if raw.strip() else {}
    except (ValueError, OSError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload["_hookPid"] = os.getpid()

    if payload.get("hook_event_name") == "PreToolUse":
        gate(payload)

    try:
        post(HOOK_URL, payload, TELEMETRY_TIMEOUT)
    except (urllib.error.URLError, OSError, ValueError):
        pass  # telemetry is best-effort and must never delay a tool call
    sys.exit(0)


if __name__ == "__main__":
    main()
