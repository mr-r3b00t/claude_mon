#!/usr/bin/env python3
"""Add (or remove) claudemon hooks in ~/.claude/settings.json.

Two things come from installing these:

  Telemetry   sub-second, authoritative events — you see a tool call at the
              moment it is requested rather than when the transcript is flushed.

  Gating      the PreToolUse hook is the ONLY way to stop a tool call before it
              runs. Without it the pre-execution gate can record a verdict but
              cannot act on one. See preExecution in shield.json.

Both are optional; claudemon works without either. The hook fails open and
always exits 0 unless the gate deliberately blocks, so a monitor that is down
never wedges the agent.

    python3 install-hooks.py            # show what would change
    python3 install-hooks.py --apply    # write settings.json (backup kept)
    python3 install-hooks.py --remove --apply
"""

import argparse
import json
import os
import shutil
import sys
import time

SETTINGS = os.path.expanduser("~/.claude/settings.json")
HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks", "claudemon_hook.py")
MARKER = "claudemon_hook.py"

EVENTS = ["UserPromptSubmit", "PreToolUse", "PostToolUse", "Notification",
          "Stop", "SubagentStop", "SessionStart", "SessionEnd", "PreCompact"]


def entry():
    return {"matcher": "*", "hooks": [{"type": "command", "command": f"python3 {HOOK}", "timeout": 5}]}


def load():
    if not os.path.exists(SETTINGS):
        return {}
    with open(SETTINGS) as fh:
        return json.load(fh)


def mutate(cfg, remove):
    hooks = cfg.setdefault("hooks", {})
    for ev in EVENTS:
        lst = [e for e in hooks.get(ev, [])
               if MARKER not in json.dumps(e)]
        if not remove:
            lst.append(entry())
        if lst:
            hooks[ev] = lst
        else:
            hooks.pop(ev, None)
    if not hooks:
        cfg.pop("hooks", None)
    return cfg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="actually write settings.json")
    ap.add_argument("--remove", action="store_true", help="remove claudemon hooks")
    args = ap.parse_args()

    if not os.path.exists(HOOK):
        sys.exit(f"hook script missing: {HOOK}")

    cfg = load()
    new = mutate(json.loads(json.dumps(cfg)), args.remove)
    if new == cfg:
        print("no change needed")
        return
    print(f"--- {SETTINGS} (proposed) ---")
    print(json.dumps(new, indent=2))
    if not args.apply:
        print("\ndry run — re-run with --apply to write")
        return
    if os.path.exists(SETTINGS):
        bak = f"{SETTINGS}.bak.{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(SETTINGS, bak)
        print(f"backup: {bak}")
    os.makedirs(os.path.dirname(SETTINGS), exist_ok=True)
    with open(SETTINGS, "w") as fh:
        json.dump(new, fh, indent=2)
    print("written. Restart Claude Code sessions to pick the hooks up.")


if __name__ == "__main__":
    main()
