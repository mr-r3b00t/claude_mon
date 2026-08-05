/* claudemon dashboard: SSE stream -> activity log + live panels */
const $ = (s) => document.querySelector(s);
const MAX_ROWS = 3000;

const KINDS = [
  ["thinking", "reasoning"], ["text", "output"], ["tool_use", "tools"],
  ["tool_result", "results"], ["prompt", "prompts"], ["usage", "tokens"],
  ["proc", "procs"], ["net", "net"], ["hook", "hooks"], ["debug", "debug"],
];
const state = {
  filters: new Set(JSON.parse(localStorage.getItem("cm.filters") || "null") ||
                   KINDS.map(([k]) => k)),
  session: "", search: "", follow: true, events: 0, lastSeq: 0,
  tokens: {}, rate: [],
};

/* ---------- filter chips ---------- */
const fBox = $("#filters");
for (const [k, label] of KINDS) {
  const el = document.createElement("span");
  el.className = "chip" + (state.filters.has(k) ? " on" : "");
  el.dataset.k = k; el.textContent = label;
  el.onclick = () => {
    state.filters.has(k) ? state.filters.delete(k) : state.filters.add(k);
    el.classList.toggle("on");
    localStorage.setItem("cm.filters", JSON.stringify([...state.filters]));
    applyFilter();
  };
  fBox.appendChild(el);
}
$("#search").oninput = (e) => { state.search = e.target.value.toLowerCase(); applyFilter(); };
$("#session-filter").onchange = (e) => { state.session = e.target.value; applyFilter(); };
$("#pause").onclick = (e) => {
  state.follow = !state.follow;
  e.target.classList.toggle("active", !state.follow);
  e.target.textContent = state.follow ? "⏸ follow" : "▶ paused";
};
$("#clear").onclick = () => { $("#log").innerHTML = ""; };

function visible(el) {
  if (!state.filters.has(el.dataset.k)) return false;
  if (state.session && el.dataset.sid !== state.session) return false;
  if (state.search && !el.textContent.toLowerCase().includes(state.search)) return false;
  return true;
}
function applyFilter() {
  for (const el of $("#log").children) el.style.display = visible(el) ? "" : "none";
}

/* ---------- helpers ---------- */
const pad = (n) => String(n).padStart(2, "0");
const hhmmss = (ts) => { const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const num = (n) => (n == null ? "–" : Number(n).toLocaleString());
const short = (s, n = 8) => (s ? String(s).slice(0, n) : "");

function addRow({ kind, sid, label, body, cls = "", agent = false, agentLabel = "" }) {
  const log = $("#log");
  const el = document.createElement("div");
  el.className = `ev ${kind} ${cls}${agent ? " agent" : ""}`;
  el.dataset.k = kind; el.dataset.sid = sid || "";
  el.innerHTML =
    `<span class="t">${hhmmss(Date.now() / 1000)}</span>` +
    `<span class="k">${agent ? "🤖 " : ""}${esc(label)}</span>` +
    `<span class="b">${agentLabel ? `<span class="tag agent-tag">🤖 ${esc(agentLabel)}</span>` : ""}${body}</span>`;
  const b = el.querySelector(".b");
  if (b.textContent.length > 320) {
    b.classList.add("trunc");
    b.onclick = () => b.classList.toggle("open");
  }
  el.style.display = visible(el) ? "" : "none";
  log.appendChild(el);
  while (log.children.length > MAX_ROWS) log.removeChild(log.firstChild);
  if (state.follow) log.scrollTop = log.scrollHeight;
}

/* ---------- event rendering ---------- */
function onActivity(d) {
  const sid = d.sessionId;
  const agent = !!d.sidechain;   // subagent (Agent/Task) work, not the main thread
  const agentLabel = d.agentLabel || "";
  const tag = (t) => `<span class="tag">${esc(t)}</span>`;
  const addRow = (o) => window.addRow({ ...o, agentLabel });
  switch (d.event) {
    case "thinking":
      return addRow({ kind: "thinking", sid, agent, label: "🧠 think", body: esc(d.text) });
    case "text":
      return addRow({ kind: "text", sid, agent, label: "💬 say", body: esc(d.text) });
    case "tool_use":
      return addRow({ kind: "tool_use", sid, agent, label: "🔧 " + esc(d.tool),
        body: tag(d.tool) + esc(d.summary) + `\n${esc(d.input)}` });
    case "tool_result":
      return addRow({ kind: "tool_result", sid, agent, label: d.isError ? "❌ error" : "↩︎ result",
        cls: d.isError ? "err" : "", body: esc(d.text) });
    case "prompt":
      return addRow({ kind: "prompt", sid, agent, label: agent ? "🤖 task" : "👤 prompt", body: esc(d.text) });
    case "usage": {
      const u = d.usage || {};
      accumTokens(sid, u);
      return addRow({ kind: "usage", sid, agent, label: "📊 tokens",
        body: `${tag(d.model || "?")}in ${num(u.input_tokens)} · out ${num(u.output_tokens)}` +
              ` · cache read ${num(u.cache_read_input_tokens)} · cache write ${num(u.cache_creation_input_tokens)}` +
              (d.stopReason ? ` · stop=${esc(d.stopReason)}` : "") +
              (d.effort ? ` · effort=${esc(d.effort)}` : "") });
    }
    case "queue":
      return addRow({ kind: "debug", sid, label: "queue", body: esc(d.op + " " + (d.text || "")) });
    case "title":
      return addRow({ kind: "debug", sid, label: "title", body: esc(d.text) });
    default:
      return addRow({ kind: "debug", sid, label: esc(d.event || "?"), body: esc(d.text || "") });
  }
}

function accumTokens(sid, u) {
  const t = (state.tokens[sid] ||= { in: 0, out: 0, cr: 0, cw: 0, turns: 0 });
  t.in += u.input_tokens || 0;
  t.out += u.output_tokens || 0;
  t.cr += u.cache_read_input_tokens || 0;
  t.cw += u.cache_creation_input_tokens || 0;
  t.turns += 1;
  renderTokens();
}

function renderTokens() {
  const sids = state.session ? [state.session] : Object.keys(state.tokens);
  const sum = { in: 0, out: 0, cr: 0, cw: 0, turns: 0 };
  for (const s of sids) { const t = state.tokens[s]; if (!t) continue;
    for (const k of Object.keys(sum)) sum[k] += t[k]; }
  $("#tokens").innerHTML = [
    ["assistant turns", sum.turns], ["input", sum.in], ["output", sum.out],
    ["cache read", sum.cr], ["cache write", sum.cw],
    ["billable-ish total", sum.in + sum.out + sum.cw],
  ].map(([k, v]) => `<div class="tok"><span class="num">${k}</span><b>${num(v)}</b></div>`).join("");
}

function onProc(d) {
  addRow({ kind: "proc", sid: d.sessionId,
    label: d.change === "spawn" ? "⊕ spawn" : "⊖ exit",
    body: `<span class="tag">pid ${d.pid}</span><span class="tag">ppid ${d.ppid}</span>${esc(d.cmd)}` });
}
function onNet(d) {
  addRow({ kind: "net", sid: d.sessionId,
    label: d.change === "open" ? "🌐 open" : "🔌 close",
    body: `<span class="tag">${esc(d.command)}[${d.pid}]</span>` +
          `${esc(d.remoteHost)}:${esc(d.remotePort)}` +
          (d.remoteName ? ` <span class="num">(${esc(d.remoteName)})</span>` : "") +
          ` ${esc(d.state || "")}` });
}
function onHook(d) {
  const bits = [d.hook_event_name, d.tool_name].filter(Boolean).join(" ");
  addRow({ kind: "hook", sid: d.session_id,
    label: "🪝 hook", body: `<span class="tag">${esc(bits)}</span>` + esc(JSON.stringify(d.tool_input ?? d)) });
}

/* ---------- side panels ---------- */
function renderSessions(sessions) {
  const sel = $("#session-filter");
  const cur = sel.value;
  const opts = ['<option value="">all sessions</option>'].concat(
    sessions.map((s) => `<option value="${esc(s.sessionId)}">${esc(s.name)} — ${esc(s.cwd || "")}</option>`));
  sel.innerHTML = opts.join("");
  sel.value = cur;

  $("#sessions").innerHTML = sessions.map((s) => `
    <div class="row sess ${s.sessionId === state.session ? "sel" : ""}" data-sid="${esc(s.sessionId)}">
      <span class="dot ${s.alive ? "live" : "dead"}"></span>
      <span class="grow"><span class="sess-name">${esc(s.name)}</span>
        <span class="sess-meta"> ${esc(s.cwd || "")}</span></span>
      <span class="num">${s.pid ? "pid " + s.pid : ""} ${esc(s.version || "")}</span>
    </div>`).join("") || '<div class="row num">no sessions found</div>';
  for (const row of $("#sessions").children) {
    row.onclick = () => {
      state.session = state.session === row.dataset.sid ? "" : row.dataset.sid;
      $("#session-filter").value = state.session;
      applyFilter(); renderTokens();
      for (const r of $("#sessions").children) r.classList.toggle("sel", r.dataset.sid === state.session);
    };
  }
  $("#s-sessions").textContent = sessions.filter((s) => s.alive).length || sessions.length;
}

function renderAgents(agents) {
  const rows = agents.filter((a) => !state.session || a.parentSessionId === state.session);
  const live = rows.filter((a) => a.active).length;
  $("#agent-hint").textContent = rows.length ? `${live} running · ${rows.length - live} finished` : "";
  $("#agents").innerHTML = rows.map((a) => `
    <div class="row">
      <span class="dot ${a.active ? "live" : "dead"}"></span>
      <span class="grow"><span class="sess-name">${esc(a.description)}</span>
        <span class="sess-meta"> ${esc(a.agentType || "")}</span></span>
      <span class="num">depth ${a.spawnDepth ?? "?"}</span>
    </div>`).join("") || '<div class="row num">no subagents</div>';
}

function renderProcs(procs) {
  const rows = procs.filter((p) => !state.session || p.sessionId === state.session);
  $("#proc-hint").textContent = `${rows.length} in tree`;
  $("#s-procs").textContent = procs.length;
  const act = (p) => (typeof shieldAct === "function" && p.depth > 0)
    ? `<span class="rowacts">` +
      `<button class="mini" title="freeze (SIGSTOP)" onclick="event.stopPropagation();shieldAct('freeze',{pid:${p.pid}},'${esc(p.name)} pid ${p.pid}')">🧊</button>` +
      `<button class="mini danger" title="kill" onclick="event.stopPropagation();shieldAct('kill',{pid:${p.pid}},'${esc(p.name)} pid ${p.pid}')">💀</button></span>`
    : "";
  $("#procs").innerHTML = rows.map((p) => `
    <div class="row">
      <span class="num">${p.pid}</span>
      <span class="grow" title="${esc(p.cmd)}">${"  ".repeat(p.depth || 0)}${esc(p.name)} ${esc(p.cmd.slice(p.cmd.indexOf(" ") + 1, 90))}</span>
      <span class="num">${p.cpu.toFixed(1)}% ${(p.rssKb / 1024).toFixed(0)}M</span>
      ${act(p)}
    </div>`).join("") || '<div class="row num">no processes</div>';
}

function renderNet(conns) {
  const rows = conns.filter((c) => !state.session || c.sessionId === state.session);
  const est = rows.filter((c) => c.remoteHost).length;
  $("#net-hint").textContent = `${est} remote · ${rows.length - est} listening`;
  $("#s-conns").textContent = est;
  $("#net").innerHTML = rows.map((c) => `
    <div class="row">
      <span class="num">${c.pid}</span>
      <span class="grow ${c.remoteHost ? "est" : "listen"}" title="${esc(c.procCmd || "")}">
        ${c.remoteHost ? `${esc(c.remoteName || c.remoteHost)}:${esc(c.remotePort)}` : `listen ${esc(c.localHost)}:${esc(c.localPort)}`}
      </span>
      <span class="num">${esc(c.command)} ${esc(c.state || "")}</span>
      ${(typeof shieldAct === "function" && c.remoteHost)
        ? `<span class="rowacts">
             <button class="mini" title="add to egress allow list"
               onclick="event.stopPropagation();egressOp('add','allow','${esc(c.remoteName || c.remoteHost)}')">✓</button>
             <button class="mini danger" title="add to egress block list"
               onclick="event.stopPropagation();egressOp('add','block','${esc(c.remoteName || c.remoteHost)}')">✕</button>
             <button class="mini" title="sinkhole this host now"
               onclick="event.stopPropagation();shieldAct('sinkhole',{host:'${esc(c.remoteName || c.remoteHost)}'},'${esc(c.remoteName || c.remoteHost)}')">🕳</button></span>`
        : ""}
    </div>`).join("") || '<div class="row num">no sockets</div>';
}

let badgeCount = 0, badgeMax = 0;
function bumpBadge(f) {
  const b = document.getElementById("c-badge");
  const onCyber = document.querySelector('.tab[data-tab="cyber"]')?.classList.contains("active");
  if (!b || onCyber) return;
  badgeCount += 1;
  badgeMax = Math.max(badgeMax, f.sev || 0);
  b.textContent = badgeCount > 99 ? "99+" : badgeCount;
  b.className = "badge on sev" + badgeMax;
}

async function refreshState() {
  try {
    const r = await fetch("/api/state");
    const s = await r.json();
    renderSessions(s.sessions);
    renderAgents(s.agents || []);
    renderProcs(s.procs);
    renderNet(s.net);
  } catch (e) { /* server restarting; next tick retries */ }
}

/* ---------- SSE ---------- */
function connect() {
  const es = new EventSource(`/api/events?after=${state.lastSeq}`);
  es.onopen = () => { $("#conn").className = "conn on"; $("#conn").textContent = "live"; };
  es.onerror = () => { $("#conn").className = "conn off"; $("#conn").textContent = "reconnecting…"; };
  es.onmessage = (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch { return; }
    state.lastSeq = Math.max(state.lastSeq, ev.seq);
    state.events++; state.rate.push(Date.now());
    $("#s-events").textContent = state.events;
    const d = ev.data;
    if (ev.kind === "activity") onActivity(d);
    else if (ev.kind === "proc") onProc(d);
    else if (ev.kind === "net") onNet(d);
    else if (ev.kind === "hook") onHook(d);
    else if (ev.kind === "gate") {
      const icon = { block: "⛔", ask: "❓", warn: "⚠" }[d.decision] || "🚦";
      addRow({ kind: "debug", cls: "gate " + d.decision, sid: d.sessionId,
        label: `${icon} gate ${esc(d.decision)}`,
        body: `<span class="tag">${esc(d.tool)}</span>${esc(d.reason)}` });
      if (typeof shieldGet === "function") shieldGet();
    }
    else if (ev.kind === "finding") {
      addRow({ kind: "debug", cls: "finding sev" + d.sev, sid: d.sessionId,
        label: "🚨 " + esc(d.severity),
        body: `<span class="tag">${esc(d.ruleId)}</span>${esc(d.name)} — ${esc(String(d.evidence).slice(0, 160))}` });
      if (typeof onFinding === "function") onFinding(d);
      bumpBadge(d);
    }
    else if (ev.kind === "debug") addRow({ kind: "debug", label: "🐞 " + esc(d.file), body: esc(d.line) });
    else if (ev.kind === "error") addRow({ kind: "debug", cls: "error", label: "‼️ " + esc(d.where), body: esc(d.error) });
    else if (ev.kind === "session") {
      addRow({ kind: "debug", sid: d.sessionId, label: "▶ session",
        body: `${esc(d.change)} ${esc(d.name)} pid=${d.pid ?? "–"} ${esc(d.cwd || "")}` });
      refreshState();
    }
  };
}

setInterval(() => {
  const cut = Date.now() - 5000;
  state.rate = state.rate.filter((t) => t > cut);
  $("#s-rate").textContent = (state.rate.length / 5).toFixed(1);
}, 1000);

refreshState();
setInterval(refreshState, 2000);
connect();
