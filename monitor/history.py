"""Builds an explorable action graph for one session.

Correlation rules, strongest first:
  tool_result -> tool_use      exact, by toolUseId
  subagent    -> Agent call    exact, by the toolUseId in the subagent .meta.json
  process     -> Bash call     heuristic, nearest preceding Bash within a window
  connection  -> tool/turn     heuristic, nearest preceding node within a window

The heuristic links are marked `inferred: true` so the UI can say so rather than
implying the transcript recorded a causal link it does not actually contain.
"""

import datetime
import itertools
import os

from . import recorder as recorder_mod
from . import transcript as transcript_mod

PROC_WINDOW_S = 180     # a Bash call may keep spawning children for a while
NET_WINDOW_S = 120


def to_epoch(ts):
    if isinstance(ts, (int, float)):
        return float(ts)
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _clip(s, n=160):
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n] + "…"


class GraphBuilder:
    def __init__(self):
        self.nodes = []
        self.ids = itertools.count(1)

    def add(self, ntype, label, parent, t=None, **meta):
        node = {"id": next(self.ids), "type": ntype, "label": label,
                "parent": parent, "t": t, **meta}
        self.nodes.append(node)
        return node

    def walk_transcript(self, events, root_id, tool_index, agent_node_for=None):
        """Append nodes for one transcript's events under `root_id`.

        Returns the list of (node, epoch) tool anchors created, for later
        process/network correlation.
        """
        turn = root_id
        anchors = []
        for e in events:
            t = to_epoch(e.get("ts"))
            ev = e.get("event")
            if ev == "prompt":
                turn = self.add("prompt", _clip(e.get("text"), 120), root_id, t,
                                text=e.get("text"), sidechain=e.get("sidechain"))["id"]
            elif ev == "thinking":
                self.add("think", _clip(e.get("text"), 120), turn, t, text=e.get("text"))
            elif ev == "text":
                self.add("say", _clip(e.get("text"), 120), turn, t, text=e.get("text"))
            elif ev == "tool_use":
                n = self.add("tool", e.get("tool") or "?", turn, t,
                             summary=_clip(e.get("summary"), 200),
                             input=e.get("input"), toolUseId=e.get("toolUseId"),
                             tool=e.get("tool"))
                if e.get("toolUseId"):
                    tool_index[e["toolUseId"]] = n
                anchors.append((n, t))
            elif ev == "tool_result":
                n = tool_index.get(e.get("toolUseId"))
                if n is not None:
                    n["result"] = _clip(e.get("text"), 4000)
                    n["isError"] = bool(e.get("isError"))
                    if t and n.get("t"):
                        n["durMs"] = int((t - n["t"]) * 1000)
                else:  # orphan result (its call predates the window we read)
                    self.add("tool", "result", turn, t,
                             result=_clip(e.get("text"), 2000),
                             isError=bool(e.get("isError")), orphan=True)
            elif ev == "usage":
                u = e.get("usage") or {}
                # Attach cost-of-turn to the enclosing turn rather than as a node.
                for node in self.nodes:
                    if node["id"] == turn:
                        node["outTokens"] = node.get("outTokens", 0) + (u.get("output_tokens") or 0)
                        node["model"] = e.get("model")
                        break
        return anchors


def build(session, agents, data_dir, limit=4000):
    """session: a discover() entry. agents: discover_subagents() entries."""
    gb = GraphBuilder()
    tool_index = {}

    root = gb.add("session", session.get("name") or session["sessionId"][:8], None,
                  to_epoch(session.get("startedAt", 0) / 1000 if session.get("startedAt") else None),
                  cwd=session.get("cwd"), sessionId=session["sessionId"],
                  pid=session.get("pid"), version=session.get("version"))

    events = []
    if session.get("transcript"):
        events = transcript_mod.read_tail(session["transcript"], session["sessionId"], limit)
    anchors = gb.walk_transcript(events, root["id"], tool_index)

    # Subagents hang off the exact Agent/Task call that spawned them.
    mine = [a for a in agents if a["parentSessionId"] == session["sessionId"]]
    for a in mine:
        parent_tool = tool_index.get(a.get("toolUseId"))
        parent_id = parent_tool["id"] if parent_tool else root["id"]
        sub_events = transcript_mod.read_tail(a["transcript"], session["sessionId"], limit)
        first_t = next((to_epoch(e.get("ts")) for e in sub_events if e.get("ts")), None)
        an = gb.add("agent", a.get("description") or a["agentId"][:10], parent_id, first_t,
                    agentType=a.get("agentType"), agentId=a["agentId"],
                    spawnDepth=a.get("spawnDepth"),
                    linked=bool(parent_tool), active=a.get("active"))
        anchors += gb.walk_transcript(sub_events, an["id"], tool_index)

    # --- heuristic attachment of observed processes and sockets ---
    times = [t for _, t in anchors if t]
    since = (min(times) - 60) if times else None
    until = (max(times) + 600) if times else None
    recorded = recorder_mod.read_events(data_dir, since=since, until=until,
                                        kinds=("proc", "net"))

    bash_anchors = sorted(((n, t) for n, t in anchors
                           if t and n.get("tool") in ("Bash", "BashOutput")),
                          key=lambda x: x[1])
    all_anchors = sorted(((n, t) for n, t in anchors if t), key=lambda x: x[1])

    def nearest(cands, ts, window):
        best = None
        for n, t in cands:
            if t <= ts and ts - t <= window:
                best = n
            elif t > ts:
                break
        return best

    for ev in recorded:
        d, ts = ev.get("data") or {}, ev.get("ts")
        if ev["kind"] == "proc" and d.get("change") == "spawn":
            host = nearest(bash_anchors, ts, PROC_WINDOW_S) or nearest(all_anchors, ts, PROC_WINDOW_S)
            if not host:
                continue
            gb.add("proc", d.get("name") or "?", host["id"], ts, inferred=True,
                   pid=d.get("pid"), ppid=d.get("ppid"), cmd=_clip(d.get("cmd"), 400))
        elif ev["kind"] == "net" and d.get("change") == "open":
            host = nearest(all_anchors, ts, NET_WINDOW_S)
            if not host:
                continue
            gb.add("net", (d.get("remoteName") or d.get("remoteHost") or "?"), host["id"], ts,
                   inferred=True, port=d.get("remotePort"), state=d.get("state"),
                   proc=d.get("command"), pid=d.get("pid"), ip=d.get("remoteHost"))

    return {
        "sessionId": session["sessionId"],
        "name": session.get("name"),
        "cwd": session.get("cwd"),
        "nodes": gb.nodes,
        "agents": len(mine),
        "recordedFrom": os.path.basename(data_dir),
        "counts": _counts(gb.nodes),
    }


def _counts(nodes):
    out = {}
    for n in nodes:
        out[n["type"]] = out.get(n["type"], 0) + 1
    return out
