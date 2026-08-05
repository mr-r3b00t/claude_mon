#!/usr/bin/env python3
"""Shield safety tests: the guards must hold before the features matter.

    python3 tests/test_shield.py

Every case here is a way the shield could hurt the user: signalling init,
signalling the session that owns the work, signalling an unrelated process,
acting while disarmed, or looping until the tree is gone. A real child process
is spawned to prove freeze/resume/kill actually work.
"""

import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor.shield import Shield  # noqa: E402

PASS, FAIL = [], []


def check(label, cond, detail=""):
    (PASS if cond else FAIL).append(label)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}" + (f"   {detail}" if not cond and detail else ""))


class FakeProcs:
    """Stands in for ProcWatcher.state."""

    def __init__(self, state):
        self.state = state


def make(tmp, state, **cfg):
    sh = Shield(None, FakeProcs(state), data_dir=tmp)
    sh.cfg["mode"] = cfg.pop("mode", "armed")
    sh.cfg["safety"].update(cfg)
    return sh


def main():
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp")
    os.makedirs(tmp, exist_ok=True)

    # A real child to act on: sleeps quietly, does nothing else.
    child = subprocess.Popen(["sleep", "120"])
    tree = {
        child.pid: {"pid": child.pid, "ppid": os.getpid(), "cmd": "sleep 120",
                    "name": "sleep", "depth": 2, "root": 999, "sessionId": "s1"},
        999: {"pid": 999, "ppid": 1, "cmd": "/path/claude-code/claude --x",
              "name": "claude", "depth": 0, "root": 999, "sessionId": "s1"},
        1234: {"pid": 1234, "ppid": 999, "cmd": "/usr/bin/sshd -D",
               "name": "sshd", "depth": 1, "root": 999},
    }

    try:
        print("-- guards must refuse " + "-" * 40)
        sh = make(tmp, tree)
        check("refuses pid 1", sh.act("kill", {"pid": 1})["result"] == "refused")
        check("refuses pid 0", sh.act("kill", {"pid": 0})["result"] == "refused")
        check("refuses the monitor itself",
              sh.act("kill", {"pid": os.getpid()})["result"] == "refused")
        check("refuses a pid outside the tracked tree",
              sh.act("kill", {"pid": 424242})["result"] == "refused")
        check("refuses the session's own process (depth 0)",
              sh.act("freeze", {"pid": 999})["result"] == "refused")
        check("refuses a protected pattern (sshd)",
              sh.act("kill", {"pid": 1234})["result"] == "refused")
        check("refuses a bad pid value",
              sh.act("kill", {"pid": "not-a-pid"})["result"] == "refused")

        print("\n-- mode gating " + "-" * 47)
        sh_off = make(tmp, tree, mode="off")
        check("mode=off performs nothing",
              sh_off.act("kill", {"pid": child.pid})["result"] == "refused")
        sh_mon = make(tmp, tree, mode="monitor")
        r = sh_mon.act("kill", {"pid": child.pid})
        check("mode=monitor is a dry run", r["result"] == "dry-run", str(r))
        check("dry run left the process alive", child.poll() is None)

        print("\n-- capability switches " + "-" * 39)
        sh_nk = make(tmp, tree, allowKill=False)
        check("allowKill=false refuses kill",
              sh_nk.act("kill", {"pid": child.pid})["result"] == "refused")
        sh_nf = make(tmp, tree, allowFreeze=False)
        check("allowFreeze=false refuses freeze",
              sh_nf.act("freeze", {"pid": child.pid})["result"] == "refused")

        print("\n-- sinkhole guards " + "-" * 43)
        sh_s = make(tmp, tree)
        sh_s.cfg["safety"]["allowSinkhole"] = True
        check("refuses to block the model API",
              sh_s.act("sinkhole", {"host": "160.79.104.10"})["result"] == "refused")
        check("refuses to block localhost",
              sh_s.act("sinkhole", {"host": "127.0.0.1"})["result"] == "refused")
        r = sh_s.act("sinkhole", {"host": "evil.example"})
        check("blocks an ordinary host", r["result"] == "ok", str(r))
        check("blocklist updated", "evil.example" in sh_s.blocked)
        check("firewall rules generated for manual review",
              os.path.exists(os.path.join(tmp, "shield-block.pf.conf")))
        sh_s.cfg["safety"]["allowSinkhole"] = False
        check("allowSinkhole=false refuses",
              sh_s.act("sinkhole", {"host": "other.example"})["result"] == "refused")

        print("\n-- circuit breaker " + "-" * 43)
        sh_r = make(tmp, tree, maxActionsPerMinute=3)
        for _ in range(3):
            sh_r.act("freeze", {"pid": child.pid})
        r = sh_r.act("freeze", {"pid": child.pid})
        check("rate limit refuses beyond the cap", r["result"] == "refused", str(r))
        check("breaker disarms to monitor mode", sh_r.mode == "monitor")
        check("breaker is reported in status", sh_r.status()["tripped"] is True)
        os.kill(child.pid, signal.SIGCONT)

        print("\n-- actions actually work " + "-" * 37)
        sh2 = make(tmp, tree)
        r = sh2.act("freeze", {"pid": child.pid})
        time.sleep(0.3)
        state = subprocess.run(["ps", "-o", "state=", "-p", str(child.pid)],
                               capture_output=True, text=True).stdout.strip()
        check("freeze stops the process", r["result"] == "ok" and state.startswith("T"),
              f"result={r['result']} ps state={state!r}")
        check("frozen list tracks it", child.pid in sh2.frozen)

        r = sh2.act("resume", {"pid": child.pid})
        time.sleep(0.3)
        state = subprocess.run(["ps", "-o", "state=", "-p", str(child.pid)],
                               capture_output=True, text=True).stdout.strip()
        check("resume restarts it", r["result"] == "ok" and not state.startswith("T"),
              f"ps state={state!r}")
        check("frozen list cleared", child.pid not in sh2.frozen)

        r = sh2.act("kill", {"pid": child.pid})
        time.sleep(0.3)
        check("kill ends the process", r["result"] == "ok" and child.poll() is not None,
              f"result={r['result']} rc={child.poll()}")

        print("\n-- audit " + "-" * 53)
        log = os.path.join(tmp, "shield-actions.jsonl")
        check("every action is written to the audit log", os.path.exists(log))
        with open(log) as fh:
            lines = fh.readlines()
        check("refusals are audited too, not just successes",
              any('"refused"' in ln for ln in lines))

    finally:
        if child.poll() is None:
            try:
                os.kill(child.pid, signal.SIGCONT)
                child.kill()
            except OSError:
                pass

    total = len(PASS) + len(FAIL)
    print(f"\n{len(PASS)}/{total} passed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
