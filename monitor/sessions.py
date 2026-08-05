"""Discovery of live Claude Code sessions and their transcript files."""

import glob
import json
import os
import time

CLAUDE_HOME = os.path.expanduser("~/.claude")
SESSIONS_DIR = os.path.join(CLAUDE_HOME, "sessions")
PROJECTS_DIR = os.path.join(CLAUDE_HOME, "projects")


def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError, TypeError):
        return False
    return True


def _transcript_for(session_id, cwd=None):
    """Locate <sid>.jsonl. Fast path derives the project slug from cwd."""
    if cwd:
        slug = cwd.replace("/", "-")
        p = os.path.join(PROJECTS_DIR, slug, session_id + ".jsonl")
        if os.path.exists(p):
            return p
    try:
        for proj in os.listdir(PROJECTS_DIR):
            p = os.path.join(PROJECTS_DIR, proj, session_id + ".jsonl")
            if os.path.exists(p):
                return p
    except OSError:
        pass
    return None


def read_session_files():
    """Sessions registered by a running claude process."""
    out = []
    try:
        names = os.listdir(SESSIONS_DIR)
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(SESSIONS_DIR, name)) as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            continue
        sid = d.get("sessionId")
        if not sid:
            continue
        alive = pid_alive(d.get("pid"))
        out.append(
            {
                "sessionId": sid,
                "pid": d.get("pid"),
                "cwd": d.get("cwd"),
                "version": d.get("version"),
                "kind": d.get("kind"),
                "entrypoint": d.get("entrypoint"),
                "name": d.get("name") or sid[:8],
                "startedAt": d.get("startedAt"),
                "alive": alive,
                "transcript": _transcript_for(sid, d.get("cwd")),
                "source": "session-file",
            }
        )
    return out


def recent_transcripts(max_age_s):
    """Transcripts touched recently — catches sessions with no session file."""
    out = []
    now = time.time()
    try:
        projects = os.listdir(PROJECTS_DIR)
    except OSError:
        return out
    for proj in projects:
        pdir = os.path.join(PROJECTS_DIR, proj)
        try:
            entries = os.listdir(pdir)
        except OSError:
            continue
        for fn in entries:
            if not fn.endswith(".jsonl"):
                continue
            path = os.path.join(pdir, fn)
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if now - mtime > max_age_s:
                continue
            out.append(
                {
                    "sessionId": fn[:-6],
                    "pid": None,
                    "cwd": "/" + proj.strip("-").replace("-", "/"),
                    "version": None,
                    "kind": None,
                    "entrypoint": None,
                    "name": fn[:8],
                    "startedAt": None,
                    "alive": False,
                    "transcript": path,
                    "mtime": mtime,
                    "source": "transcript",
                }
            )
    return out


def discover_subagents(max_age_s=1800, active_window_s=60):
    """Subagent (Agent/Task) transcripts.

    These do NOT live beside the session transcript — they are one level deeper,
    at <project>/<parentSessionId>/subagents/agent-<agentId>.jsonl, with a
    sibling .meta.json giving the agent type and description. A one-level scan
    of the project directory misses them entirely.
    """
    out = []
    now = time.time()
    pattern = os.path.join(PROJECTS_DIR, "*", "*", "subagents", "agent-*.jsonl")
    for path in glob.glob(pattern):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if now - mtime > max_age_s:
            continue
        agent_id = os.path.basename(path)[len("agent-"):-len(".jsonl")]
        parent = os.path.basename(os.path.dirname(os.path.dirname(path)))
        meta = {}
        try:
            with open(path[: -len(".jsonl")] + ".meta.json") as fh:
                meta = json.load(fh)
        except (OSError, ValueError):
            pass
        out.append(
            {
                "agentId": agent_id,
                "parentSessionId": parent,
                "transcript": path,
                "agentType": meta.get("agentType"),
                "description": meta.get("description") or agent_id[:12],
                "spawnDepth": meta.get("spawnDepth"),
                "toolUseId": meta.get("toolUseId"),
                "mtime": mtime,
                "active": (now - mtime) < active_window_s,
            }
        )
    out.sort(key=lambda a: a["mtime"], reverse=True)
    return out


def discover(max_age_s=1800):
    """Merged view; session-file entries win over inferred ones."""
    by_sid = {}
    for s in recent_transcripts(max_age_s):
        by_sid[s["sessionId"]] = s
    for s in read_session_files():
        prev = by_sid.get(s["sessionId"], {})
        if prev.get("mtime"):
            s["mtime"] = prev["mtime"]
        if not s.get("transcript"):
            s["transcript"] = prev.get("transcript")
        by_sid[s["sessionId"]] = s
    sessions = list(by_sid.values())
    sessions.sort(key=lambda s: (s["alive"], s.get("mtime") or 0), reverse=True)
    return sessions
