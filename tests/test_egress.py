#!/usr/bin/env python3
"""Egress policy tests.

    python3 tests/test_egress.py

Precedence is the whole point: never > block > allow > mode default. If an
allowlist can be typo'd into cutting the agent off from its own API, nobody
will leave it on.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor.egress import EgressPolicy, Matcher, validate  # noqa: E402

PASS, FAIL = [], []


def check(label, cond, detail=""):
    (PASS if cond else FAIL).append(label)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}" + (f"   {detail}" if not cond and detail else ""))


def conn(ip, name=None, port="443"):
    return {"remoteHost": ip, "remoteName": name, "remotePort": port}


def main():
    print("-- entry forms " + "-" * 47)
    cases = [
        ("1.2.3.4", conn("1.2.3.4"), True),
        ("1.2.3.4", conn("1.2.3.5"), False),
        ("10.0.0.0/8", conn("10.4.5.6"), True),
        ("10.0.0.0/8", conn("11.4.5.6"), False),
        ("160.79.104.", conn("160.79.104.10"), True),
        ("160.79.104.", conn("160.79.105.10"), False),
        ("api.example.com", conn("1.1.1.1", "api.example.com"), True),
        ("api.example.com", conn("1.1.1.1", "cdn.example.com"), False),
        ("*.example.com", conn("1.1.1.1", "cdn.example.com"), True),
        ("*.example.com", conn("1.1.1.1", "example.com"), True),
        ("*.example.com", conn("1.1.1.1", "notexample.com"), False),
        (".example.com", conn("1.1.1.1", "a.b.example.com"), True),
        ("example.com:443", conn("1.1.1.1", "example.com", "443"), True),
        ("example.com:443", conn("1.1.1.1", "example.com", "8080"), False),
        (":4444", conn("9.9.9.9", None, "4444"), True),
        (":4444", conn("9.9.9.9", None, "443"), False),
        ("*", conn("9.9.9.9"), True),
        # IPv6: `::1` starts with a colon but is an address, not a port shorthand
        ("::1", conn("::1", None, "80"), True),
        ("::1", conn("::2", None, "80"), False),
        ("fe80::/10", conn("fe80::1", None, "80"), True),
        ("[::1]:8787", conn("::1", None, "8787"), True),
        ("[::1]:8787", conn("::1", None, "9999"), False),
        (":4444", conn("::1", None, "4444"), True),
    ]
    for entry, c, want in cases:
        m = Matcher(entry)
        got = m.matches((c["remoteHost"] or "").lower(),
                        (c["remoteName"] or "").lower(), c["remotePort"])
        check(f"{entry!r} vs {c['remoteName'] or c['remoteHost']}:{c['remotePort']} -> {want}",
              got == want, f"got {got} (kind={m.kind})")

    print("\n-- precedence " + "-" * 48)
    p = EgressPolicy({"mode": "blocklist",
                      "never": ["160.79.104.0/23"],
                      "allow": ["*.example.com"],
                      "block": ["evil.example.com", "*.example.com"]})
    r = p.classify(conn("160.79.104.10"))
    check("never beats block", r["verdict"] == "allow" and r["list"] == "never", str(r))
    r = p.classify(conn("1.1.1.1", "evil.example.com"))
    check("block beats allow", r["verdict"] == "block" and r["list"] == "block", str(r))

    print("\n-- modes " + "-" * 53)
    base = {"never": ["127.0.0.0/8"], "allow": ["*.github.com"], "block": ["*.ngrok.io"]}
    for mode, host, want in [
        ("monitor", "unknown.example", "allow"),
        ("monitor", "x.ngrok.io", "block"),
        ("blocklist", "unknown.example", "allow"),
        ("blocklist", "x.ngrok.io", "block"),
        ("allowlist", "unknown.example", "block"),
        ("allowlist", "api.github.com", "allow"),
        ("allowlist", "x.ngrok.io", "block"),
    ]:
        r = EgressPolicy({**base, "mode": mode}).classify(conn("9.9.9.9", host))
        check(f"mode={mode:<9} {host:<18} -> {want}", r["verdict"] == want, str(r))

    r = EgressPolicy({**base, "mode": "monitor"}).classify(conn("9.9.9.9", "x.ngrok.io"))
    check("monitor mode classifies but does not enforce", r["enforced"] is False, str(r))
    r = EgressPolicy({**base, "mode": "blocklist"}).classify(conn("9.9.9.9", "x.ngrok.io"))
    check("blocklist mode marks the block as enforced", r["enforced"] is True, str(r))

    print("\n-- the agent cannot be cut off " + "-" * 31)
    strict = EgressPolicy({"mode": "allowlist", "never": ["160.79.104.0/23", "127.0.0.0/8"],
                           "allow": [], "block": ["*"]})
    r = strict.classify(conn("160.79.104.10"))
    check("model API survives allowlist + block-everything",
          r["verdict"] == "allow" and r["list"] == "never", str(r))
    r = strict.classify(conn("127.0.0.1", None, "8787"))
    check("loopback survives too", r["verdict"] == "allow", str(r))
    r = strict.classify(conn("203.0.113.9", "anything.example"))
    check("everything else is denied", r["verdict"] == "block", str(r))

    print("\n-- list management " + "-" * 43)
    p = EgressPolicy({"mode": "blocklist", "allow": [], "block": []})
    p.add("allow", "a.example.com")
    check("add to allow", "a.example.com" in p.as_dict()["allow"])
    p.add("block", "a.example.com")
    d = p.as_dict()
    check("adding to block removes it from allow",
          "a.example.com" in d["block"] and "a.example.com" not in d["allow"], str(d))
    p.remove("block", "a.example.com")
    check("remove works", "a.example.com" not in p.as_dict()["block"])
    try:
        p.add("allow", "")
        check("empty entry is refused", False)
    except ValueError:
        check("empty entry is refused", True)
    try:
        p.set_mode("nonsense")
        check("bad mode is refused", False)
    except ValueError:
        check("bad mode is refused", True)

    print("\n-- validation " + "-" * 48)
    check("valid config passes",
          validate({"mode": "blocklist", "never": ["127.0.0.0/8"]}) == [])
    check("bad mode reported", any("mode" in e for e in validate({"mode": "nope"})))
    check("bad onViolation reported",
          any("onViolation" in e for e in validate({"onViolation": "explode"})))
    errs = validate({"mode": "allowlist", "never": []})
    check("allowlist with an empty never list is refused",
          any("never" in e for e in errs), str(errs))

    total = len(PASS) + len(FAIL)
    print(f"\n{len(PASS)}/{total} passed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
