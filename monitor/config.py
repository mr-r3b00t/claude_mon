"""Reading and writing claudemon's own configuration from the dashboard.

Writes are guarded the same way in every case: validate first, keep a
timestamped backup, write, then reload. A config edit must never be able to
leave the detection engine dead — an invalid ruleset is rejected before it
touches disk, not after.
"""

import json
import os
import re
import shutil
import time

from .rules import compile_rule, validate_spec

MAX_BACKUPS = 20


def backup(path):
    if not os.path.exists(path):
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = f"{path}.bak.{stamp}"
    shutil.copy2(path, dest)
    _prune(path)
    return dest


def _prune(path):
    d, base = os.path.dirname(path) or ".", os.path.basename(path)
    try:
        baks = sorted(f for f in os.listdir(d) if f.startswith(base + ".bak."))
    except OSError:
        return
    for old in baks[:-MAX_BACKUPS]:
        try:
            os.remove(os.path.join(d, old))
        except OSError:
            pass


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)     # atomic: never leave a half-written config


def strip_internal(spec):
    """Drop compiled-regex fields before serialising."""
    out = json.loads(json.dumps(
        {k: v for k, v in spec.items() if not k.startswith("_re")},
        default=lambda o: None))
    for r in out.get("rules", []):
        for k in ("_re", "_not"):
            r.pop(k, None)
    return out


def save_rules(engine, spec):
    """Validate, back up, write, reload. Returns (ok, message, backup_path)."""
    errors = validate_spec(spec)
    if errors:
        return False, errors, None
    clean = strip_internal(spec)
    bak = backup(engine.rules_path)
    write_json(engine.rules_path, clean)
    try:
        n = engine.reload()
    except ValueError as exc:
        if bak:                                   # should not happen — validated above
            shutil.copy2(bak, engine.rules_path)
            engine.reload()
        return False, [f"reload failed, rolled back: {exc}"], bak
    return True, [f"{n} rules saved and reloaded"], bak


def save_shield(shield, cfg):
    errors = validate_shield(cfg)
    if errors:
        return False, errors, None
    bak = backup(shield.config_path)
    write_json(shield.config_path, cfg)
    shield.cfg = cfg
    return True, ["shield configuration saved"], bak


def validate_shield(cfg):
    errors = []
    if not isinstance(cfg, dict):
        return ["shield config must be a JSON object"]
    if cfg.get("mode") not in ("off", "monitor", "armed"):
        errors.append("mode must be off, monitor or armed")
    pre = cfg.get("preExecution") or {}
    if pre and pre.get("mode") not in (None, "off", "warn", "ask", "block"):
        errors.append("preExecution.mode must be off, warn, ask or block")
    if pre.get("failMode") not in (None, "open", "closed"):
        errors.append("preExecution.failMode must be open or closed")
    from .egress import validate as validate_egress
    errors += validate_egress(cfg.get("egress") or {})
    sk = cfg.get("sinkhole") or {}
    if sk.get("enforcement") not in (None, "freeze-owner", "kill-owner", "none"):
        errors.append("sinkhole.enforcement must be freeze-owner, kill-owner or none")
    safety = cfg.get("safety") or {}
    if not safety.get("protectSessionProcess", True):
        errors.append("protectSessionProcess=false is refused: it would allow the shield "
                      "to freeze or kill the session that owns your work")
    if not safety.get("requireInTree", True):
        errors.append("requireInTree=false is refused: it would allow the shield to signal "
                      "processes unrelated to the agent")
    try:
        cap = int(safety.get("maxActionsPerMinute", 12))
        if cap < 1 or cap > 240:
            errors.append("maxActionsPerMinute must be between 1 and 240")
    except (TypeError, ValueError):
        errors.append("maxActionsPerMinute must be a number")
    return errors


def test_patterns(patterns, sample, case_sensitive=False, nots=None):
    """Try candidate patterns against sample text — the rule-authoring aid."""
    flags = re.M if case_sensitive else (re.I | re.M)
    results = []
    for p in patterns or []:
        try:
            rx = re.compile(p, flags)
        except re.error as exc:
            results.append({"pattern": p, "error": str(exc)})
            continue
        m = rx.search(sample or "")
        results.append({"pattern": p, "matched": bool(m),
                        "text": m.group(0)[:200] if m else None,
                        "span": [m.start(), m.end()] if m else None})
    excluded = None
    for p in nots or []:
        try:
            if re.search(p, sample or "", flags):
                excluded = p
                break
        except re.error:
            continue
    hit = any(r.get("matched") for r in results) and not excluded
    return {"results": results, "wouldFire": hit, "excludedBy": excluded}


def snapshot(engine, shield):
    return {
        "rulesPath": engine.rules_path if engine else None,
        "shieldPath": shield.config_path if shield else None,
        "ruleset": strip_internal(engine.spec) if engine else {},
        "shield": shield.cfg if shield else {},
        "categories": sorted({r.get("category") for r in (engine.rules if engine else [])
                              if r.get("category")}),
        "backups": _list_backups(engine, shield),
    }


def _list_backups(engine, shield):
    out = []
    for path in filter(None, [engine.rules_path if engine else None,
                              shield.config_path if shield else None]):
        d, base = os.path.dirname(path) or ".", os.path.basename(path)
        try:
            for f in sorted(os.listdir(d), reverse=True):
                if f.startswith(base + ".bak."):
                    out.append({"file": f, "of": base,
                                "ts": os.path.getmtime(os.path.join(d, f))})
        except OSError:
            continue
    return out[:20]


def restore(path, backup_name):
    d = os.path.dirname(path) or "."
    src = os.path.join(d, backup_name)
    if not os.path.exists(src) or not backup_name.startswith(os.path.basename(path) + ".bak."):
        raise ValueError("unknown backup")
    backup(path)
    shutil.copy2(src, path)
    return src
