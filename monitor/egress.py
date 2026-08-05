"""Egress policy: one authoritative allow/block list for outbound connections.

Entry forms, all matched against the peer of an observed connection:

    1.2.3.4              exact IP
    10.0.0.0/8           CIDR
    160.79.104.          IP prefix (trailing dot)
    api.example.com      exact hostname
    *.example.com        domain and any subdomain
    .example.com         same, shorthand
    example.com:443      host and port together
    :4444                port, any host
    *                    everything

Precedence is fixed and does not depend on list order:

    never  >  block  >  allow  >  the mode default

`never` exists so a policy cannot cut the agent off from the model API or from
loopback — an allowlist typo would otherwise strand the agent mid-task, and a
security control that breaks the thing it protects will simply get turned off.
Explicit block beats explicit allow, so a broad allow entry cannot silently
re-permit something you named as forbidden.

Modes:

    monitor     classify and record; enforce nothing (default)
    blocklist   deny what is listed, allow the rest       (default-allow)
    allowlist   allow only what is listed, deny the rest  (default-deny)
"""

import ipaddress

MODES = ("monitor", "blocklist", "allowlist")


def _norm(s):
    return str(s or "").strip().lower().rstrip(".")


class Matcher:
    """One policy entry, pre-parsed so matching stays cheap per connection."""

    __slots__ = ("raw", "kind", "host", "port", "net", "prefix")

    def __init__(self, entry):
        self.raw = str(entry).strip()
        self.kind = self.host = self.port = self.net = self.prefix = None
        e = self.raw.lower()
        if not e:
            self.kind = "none"
            return
        if e == "*":
            self.kind = "any"
            return
        # ":4444" is the port shorthand — but "::1" is IPv6 loopback, so the
        # remainder has to be all digits before this is treated as a port.
        if e.startswith(":") and e[1:].isdigit():
            self.kind, self.port = "port", e[1:]
            return
        # "[::1]:8080" — bracketed IPv6 with a port
        if e.startswith("[") and "]" in e:
            host, _, rest = e[1:].partition("]")
            if rest.startswith(":") and rest[1:].isdigit():
                self.port = rest[1:]
            e = host
        # host:port for everything else; an unbracketed IPv6 literal has
        # several colons, so require exactly one.
        elif e.count(":") == 1:
            h, _, p = e.partition(":")
            if p.isdigit():
                e, self.port = h, p
        if "/" in e:
            try:
                self.net = ipaddress.ip_network(e, strict=False)
                self.kind = "cidr"
                return
            except ValueError:
                pass
        if e.startswith("*."):
            self.kind, self.host = "suffix", e[2:].rstrip(".")
            return
        if e.startswith("."):
            self.kind, self.host = "suffix", e[1:].rstrip(".")
            return
        if e.endswith("."):
            self.kind, self.prefix = "prefix", e
            return
        try:
            ipaddress.ip_address(e)
            self.kind, self.host = "ip", e
            return
        except ValueError:
            pass
        self.kind, self.host = "host", e.rstrip(".")

    def matches(self, ip, name, port):
        if self.kind == "none":
            return False
        if self.port and str(port or "") != self.port:
            return False
        if self.kind == "any":
            return True
        if self.kind == "port":
            return True                       # port already checked above
        if self.kind == "cidr":
            try:
                return ipaddress.ip_address(ip) in self.net
            except ValueError:
                return False
        if self.kind == "prefix":
            return bool(ip) and ip.startswith(self.prefix)
        if self.kind == "ip":
            return ip == self.host
        if self.kind == "host":
            return name == self.host
        if self.kind == "suffix":
            return bool(name) and (name == self.host or name.endswith("." + self.host))
        return False

    def __repr__(self):
        return f"<{self.kind} {self.raw}>"


class EgressPolicy:
    def __init__(self, cfg=None):
        self.load(cfg or {})

    def load(self, cfg):
        self.cfg = cfg or {}
        self.mode = self.cfg.get("mode", "monitor")
        if self.mode not in MODES:
            self.mode = "monitor"
        self.never = [Matcher(e) for e in self.cfg.get("never", [])]
        self.allow = [Matcher(e) for e in self.cfg.get("allow", [])]
        self.block = [Matcher(e) for e in self.cfg.get("block", [])]
        return self

    def as_dict(self):
        return {
            "mode": self.mode,
            "never": [m.raw for m in self.never],
            "allow": [m.raw for m in self.allow],
            "block": [m.raw for m in self.block],
            "onViolation": self.cfg.get("onViolation", "alert"),
            "logAllowed": bool(self.cfg.get("logAllowed")),
        }

    @staticmethod
    def _peer(conn):
        ip = _norm(conn.get("remoteHost"))
        name = _norm(conn.get("remoteName"))
        return ip, name, str(conn.get("remotePort") or "")

    def _first(self, matchers, ip, name, port):
        for m in matchers:
            if m.matches(ip, name, port):
                return m
        return None

    def classify(self, conn):
        """Return {verdict, reason, matched, list, mode}. verdict: allow|block."""
        ip, name, port = self._peer(conn)
        peer = f"{name or ip}:{port}"

        m = self._first(self.never, ip, name, port)
        if m:
            return self._r("allow", "never", m, peer,
                           f"{peer} is on the never-block list ({m.raw}) — protected")

        m = self._first(self.block, ip, name, port)
        if m:
            return self._r("block", "block", m, peer,
                           f"{peer} matches block entry {m.raw}")

        m = self._first(self.allow, ip, name, port)
        if m:
            return self._r("allow", "allow", m, peer,
                           f"{peer} matches allow entry {m.raw}")

        if self.mode == "allowlist":
            return self._r("block", "default", None, peer,
                           f"{peer} is not on the allowlist (default-deny)")
        if self.mode == "blocklist":
            return self._r("allow", "default", None, peer,
                           f"{peer} is not on the blocklist (default-allow)")
        return self._r("allow", "default", None, peer,
                       f"{peer} unclassified — policy is in monitor mode")

    def _r(self, verdict, which, matcher, peer, reason):
        return {"verdict": verdict, "list": which, "matched": matcher.raw if matcher else None,
                "peer": peer, "reason": reason, "mode": self.mode,
                "enforced": self.mode != "monitor" and verdict == "block"}

    # -------- list management --------
    def add(self, which, entry):
        if which not in ("allow", "block"):
            raise ValueError("list must be allow or block")
        entry = str(entry).strip()
        if not entry:
            raise ValueError("empty entry")
        Matcher(entry)                                   # parse now, fail loudly
        other = "block" if which == "allow" else "allow"
        lst = self.cfg.setdefault(which, [])
        # An entry cannot sit on both lists; the newest instruction wins.
        self.cfg[other] = [e for e in self.cfg.get(other, []) if e != entry]
        if entry not in lst:
            lst.append(entry)
        self.load(self.cfg)
        return self.as_dict()

    def remove(self, which, entry):
        if which not in ("allow", "block"):
            raise ValueError("list must be allow or block")
        self.cfg[which] = [e for e in self.cfg.get(which, []) if e != entry]
        self.load(self.cfg)
        return self.as_dict()

    def set_mode(self, mode):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.cfg["mode"] = self.mode = mode
        return self.as_dict()


def validate(cfg):
    errors = []
    if not isinstance(cfg, dict):
        return ["egress config must be an object"]
    if cfg.get("mode") not in (None,) + MODES:
        errors.append(f"egress.mode must be one of {MODES}")
    if cfg.get("onViolation") not in (None, "alert", "freeze-owner", "kill-owner"):
        errors.append("egress.onViolation must be alert, freeze-owner or kill-owner")
    for key in ("never", "allow", "block"):
        v = cfg.get(key)
        if v is None:
            continue
        if not isinstance(v, list):
            errors.append(f"egress.{key} must be a list")
            continue
        for e in v:
            m = Matcher(e)
            if m.kind == "none":
                errors.append(f"egress.{key}: empty entry")
    if cfg.get("mode") == "allowlist" and not cfg.get("never"):
        errors.append("egress.never is empty while mode is allowlist — the agent would "
                      "lose its own API connection. Keep the model API and loopback there.")
    return errors
