"""Pre-execution gate: decide on a tool call BEFORE Claude Code runs it.

Driven by a PreToolUse hook, which is synchronous — Claude Code waits for the
verdict. Two consequences shape everything here:

  * It must be fast. Regex evaluation over one command plus a loopback round
    trip is ~2 ms; the hook's own timeout is the real ceiling.
  * It must fail open by default. A monitor that is down, slow or mid-restart
    must not wedge the user's agent. Fail-closed is available for people who
    would rather stop than proceed unseen, but it is not the default.

Verdicts, weakest to strongest:

  allow   proceed silently
  warn    proceed, but record it — the finding is in the Cyber tab either way
  ask     hand the decision to the human via Claude Code's permission prompt
  block   refuse the call; Claude is told why and continues without it

`mode` caps the strongest verdict the gate can return, so a single setting
turns real blocking on or off without editing per-rule policy.
"""

import time

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STRENGTH = {"allow": 0, "warn": 1, "ask": 2, "block": 3}
CAP_BY_MODE = {"off": "allow", "warn": "warn", "ask": "ask", "block": "block"}


class Gate:
    def __init__(self, engine, shield, bus=None):
        self.engine = engine
        self.shield = shield
        self.bus = bus
        self.decisions = []
        self.counts = {"allow": 0, "warn": 0, "ask": 0, "block": 0}

    @property
    def cfg(self):
        return (self.shield.cfg.get("preExecution") or {}) if self.shield else {}

    def enabled(self):
        if not self.engine or not self.shield:
            return False
        if self.shield.mode == "off":
            return False           # shield mode is the master switch
        return bool(self.cfg.get("enabled"))

    def status(self):
        return {
            "enabled": self.enabled(),
            "mode": self.cfg.get("mode", "warn"),
            "minSeverity": self.cfg.get("minSeverity", "critical"),
            "failMode": self.cfg.get("failMode", "open"),
            "counts": dict(self.counts),
            "recent": self.decisions[-40:][::-1],
        }

    def decide(self, payload):
        """payload: a Claude Code PreToolUse hook body."""
        tool = payload.get("tool_name") or payload.get("tool") or "?"
        tool_input = payload.get("tool_input") or {}
        session = payload.get("session_id")
        cwd = payload.get("cwd")

        if not self.enabled():
            return self._record(tool, "allow", "gate disabled", None, session, tool_input)

        if tool in (self.cfg.get("allowTools") or []):
            return self._record(tool, "allow", f"{tool} is on the gate's allowTools list",
                                None, session, tool_input)

        # Shape the proposed call like a transcript tool_use so one ruleset
        # covers both pre-execution and observed activity.
        from .transcript import summarise_tool
        import json as _json
        ev = {
            "tool": tool,
            "summary": summarise_tool(tool, tool_input),
            "input": _json.dumps(tool_input, default=str)[:4000],
            "cwd": cwd,
            "sessionId": session,
            "preExec": True,
        }
        # dedupe=False is load-bearing: a repeat of the same dangerous call must
        # be judged again, not waved through because it was seen a moment ago.
        findings = self.engine.evaluate("tool_use", ev, time.time(), dedupe=False) or []
        findings = [f for f in findings
                    if f["ruleId"] not in (self.cfg.get("allowRules") or [])]
        if not findings:
            return self._record(tool, "allow", "no rule matched", None, session, tool_input)

        worst = max(findings, key=lambda f: f["sev"])

        # An explicit byRule/byCategory entry is a deliberate policy statement
        # and applies regardless of minSeverity. The floor only governs the
        # generic bySeverity path — otherwise setting byCategory for a
        # high-severity family would silently do nothing under a critical floor.
        explicit = (self.cfg.get("byRule", {}).get(worst["ruleId"])
                    or self.cfg.get("byCategory", {}).get(worst["category"]))
        if explicit:
            want = explicit
        else:
            floor = SEVERITY_ORDER.get(self.cfg.get("minSeverity", "critical"), 4)
            if worst["sev"] < floor:
                return self._record(tool, "warn",
                                    f"{worst['ruleId']} {worst['name']} (below gate threshold)",
                                    worst, session, tool_input)
            want = self.cfg.get("bySeverity", {}).get(worst["severity"]) or "warn"

        cap = CAP_BY_MODE.get(self.cfg.get("mode", "warn"), "warn")
        decision = want if STRENGTH.get(want, 1) <= STRENGTH[cap] else cap
        reason = f"{worst['ruleId']} · {worst['name']} — {worst['evidence']}"
        if decision != want:
            reason += f" (would {want}; gate mode is {self.cfg.get('mode')})"
        return self._record(tool, decision, reason, worst, session, tool_input, wouldBe=want)

    def _record(self, tool, decision, reason, finding, session, tool_input, wouldBe=None):
        rec = {
            "ts": time.time(), "tool": tool, "decision": decision, "reason": reason,
            "wouldBe": wouldBe, "sessionId": session,
            "ruleId": (finding or {}).get("ruleId"),
            "severity": (finding or {}).get("severity"),
            "check": (finding or {}).get("check"),
            "summary": str(tool_input)[:300],
        }
        self.counts[decision] = self.counts.get(decision, 0) + 1
        self.decisions.append(rec)
        if len(self.decisions) > 1000:
            del self.decisions[:300]
        if decision != "allow":
            if self.bus:
                self.bus.publish("gate", rec)
            if self.shield:
                self.shield._audit("gate-" + decision, {"tool": tool}, "ok",
                                   reason, actor="gate", finding=finding)
        return rec


def hook_response(rec):
    """Translate a verdict into a Claude Code PreToolUse hook response.

    Both the structured field and the exit code are emitted by the caller so the
    verdict lands whichever convention the running version honours.
    """
    decision = rec["decision"]
    mapped = {"allow": "allow", "warn": "allow", "ask": "ask", "block": "deny"}[decision]
    reason = rec["reason"]
    if decision == "block":
        reason = ("Blocked by claudemon pre-execution gate: " + reason +
                  (f"\nWhat to check: {rec['check']}" if rec.get("check") else "") +
                  "\nIf this is expected, allow the rule in shield.json "
                  "(preExecution.allowRules) or lower preExecution.mode.")
    elif decision == "ask":
        reason = "claudemon flagged this call: " + reason
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": mapped,
            "permissionDecisionReason": reason,
        },
        # Older convention, kept so the verdict is honoured either way.
        "decision": "block" if decision == "block" else "approve",
        "reason": reason,
    }
