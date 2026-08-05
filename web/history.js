/* claudemon History tab: interactive flow/tree of actions, processes and connections.
   Hand-rolled SVG — no libraries, no CDN. */

const H = {
  data: null,
  collapsed: new Set(),
  hidden: new Set(JSON.parse(localStorage.getItem("cm.hgt") || "[]")),
  sel: null,
  view: { k: 1, x: 40, y: 0 },
  search: "",
  laidOut: [],
};

const NODE_W = 250, NODE_H = 26, X_GAP = 296, Y_STEP = 34;

const TYPES = {
  session: { c: "#c98a5a", i: "◆", n: "session" },
  prompt:  { c: "#e0b341", i: "👤", n: "prompts" },
  think:   { c: "#b48ee8", i: "🧠", n: "reasoning" },
  say:     { c: "#cfd6de", i: "💬", n: "output" },
  tool:    { c: "#4fa8e8", i: "🔧", n: "tools" },
  agent:   { c: "#e070c0", i: "🤖", n: "subagents" },
  proc:    { c: "#e08a4a", i: "⊕", n: "processes" },
  net:     { c: "#45c3c3", i: "🌐", n: "connections" },
};

const hEsc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const hTime = (t) => {
  if (!t) return "";
  const d = new Date(t * 1000);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
};

/* ---------- data ---------- */
async function loadHistory(sessionId) {
  const el = document.getElementById("h-status");
  el.textContent = "loading…";
  try {
    const r = await fetch("/api/history" + (sessionId ? `?session=${encodeURIComponent(sessionId)}` : ""));
    H.data = await r.json();
    if (H.data.error) { el.textContent = H.data.error; return; }
    const c = H.data.counts || {};
    el.textContent = `${H.data.nodes.length} nodes · ` +
      Object.entries(c).map(([k, v]) => `${v} ${k}`).join(" · ");
    // Open on a readable overview: tool detail folded, and earlier turns folded
    // too — a single long turn can carry a hundred tool calls, which buries the
    // shape of the session. The newest turn stays open.
    const prompts = H.data.nodes.filter((n) => n.type === "prompt");
    const newest = prompts.length ? prompts[prompts.length - 1].id : null;
    H.collapsed = new Set(
      H.data.nodes
        .filter((n) => n.type === "tool" || (n.type === "prompt" && n.id !== newest))
        .map((n) => n.id));
    // Subagents are the most interesting branches — never let a folded ancestor
    // hide one. Re-open the whole chain from each agent node up to the root.
    const byId = new Map(H.data.nodes.map((n) => [n.id, n]));
    for (const a of H.data.nodes.filter((n) => n.type === "agent")) {
      for (let p = a.parent; p != null; p = byId.get(p)?.parent) H.collapsed.delete(p);
    }
    render(true);
  } catch (e) {
    el.textContent = "failed to load history";
  }
}

/* ---------- layout: tidy left-to-right tree ---------- */
function layout() {
  const nodes = H.data.nodes.filter((n) => !H.hidden.has(n.type));
  const byId = new Map(nodes.map((n) => [n.id, { ...n, children: [] }]));
  const roots = [];
  for (const n of byId.values()) {
    // Re-parent onto the nearest visible ancestor so hiding a type does not
    // orphan its descendants.
    let p = n.parent;
    while (p != null && !byId.has(p)) {
      const orig = H.data.nodes.find((x) => x.id === p);
      p = orig ? orig.parent : null;
    }
    if (p == null) roots.push(n); else byId.get(p).children.push(n);
  }
  for (const n of byId.values()) {
    n.children.sort((a, b) => (a.t || 0) - (b.t || 0) || a.id - b.id);
  }

  let leaf = 0;
  const out = [];
  const visit = (n, depth) => {
    n.depth = depth;
    n.x = depth * X_GAP;
    const open = !H.collapsed.has(n.id);
    n.hasKids = n.children.length > 0;
    if (open && n.hasKids) {
      for (const c of n.children) visit(c, depth + 1);
      const ys = n.children.map((c) => c.y);
      n.y = (Math.min(...ys) + Math.max(...ys)) / 2;
    } else {
      n.y = leaf * Y_STEP;
      leaf += 1;
    }
    n.hiddenKids = (!open && n.hasKids) ? n.children.length : 0;
    out.push(n);
  };
  roots.forEach((r) => visit(r, 0));
  H.laidOut = out;
  return out;
}

/* ---------- render ---------- */
function render(fit = false) {
  if (!H.data) return;
  const nodes = layout();
  const svg = document.getElementById("h-svg");
  const shown = new Set(nodes.map((n) => n.id));

  const links = [];
  for (const n of nodes) {
    if (n.parent == null) continue;
    const p = nodes.find((x) => x.id === n.parent);
    if (!p || !shown.has(p.id) || H.collapsed.has(p.id)) continue;
    const x1 = p.x + NODE_W, y1 = p.y + NODE_H / 2, x2 = n.x, y2 = n.y + NODE_H / 2;
    const mx = x1 + (x2 - x1) / 2;
    links.push(`<path class="hl${n.inferred ? " inferred" : ""}" d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}"/>`);
  }

  const q = H.search.toLowerCase();
  const body = nodes.map((n) => {
    const T = TYPES[n.type] || TYPES.tool;
    const hit = q && JSON.stringify(n).toLowerCase().includes(q);
    const sub = nodeSub(n);
    const kids = n.hasKids ? `<g class="htoggle" data-toggle="${n.id}">
        <circle cx="${n.x + NODE_W + 9}" cy="${n.y + NODE_H / 2}" r="8"/>
        <text x="${n.x + NODE_W + 9}" y="${n.y + NODE_H / 2 + 3.5}">${H.collapsed.has(n.id) ? "+" : "−"}</text></g>` : "";
    return `<g class="hn ${n.type}${H.sel === n.id ? " sel" : ""}${hit ? " hit" : ""}${n.isError ? " err" : ""}" data-id="${n.id}">
      <rect x="${n.x}" y="${n.y}" width="${NODE_W}" height="${NODE_H}" rx="5"/>
      <rect class="bar" x="${n.x}" y="${n.y}" width="3" height="${NODE_H}"/>
      <text class="lbl" x="${n.x + 10}" y="${n.y + 17}">${hEsc(T.i)} ${hEsc(n.label || n.type)}</text>
      <text class="sub" x="${n.x + NODE_W - 8}" y="${n.y + 17}">${hEsc(sub)}</text>
    </g>${kids}`;
  }).join("");

  svg.innerHTML = `<g id="h-cam">${links.join("")}${body}</g>`;
  applyView();
  if (fit) fitView();
}

function nodeSub(n) {
  if (n.hiddenKids) {
    const own = n.type === "tool" && n.durMs != null ? `${(n.durMs / 1000).toFixed(1)}s ` : "";
    return `${own}+${n.hiddenKids}`;
  }
  if (n.type === "tool") return n.durMs != null ? `${(n.durMs / 1000).toFixed(1)}s` : hTime(n.t);
  if (n.type === "proc") return `pid ${n.pid}`;
  if (n.type === "net") return `:${n.port || "?"}`;
  if (n.type === "agent") return n.agentType || "";
  if (n.type === "prompt") return n.outTokens ? `${n.outTokens} out` : hTime(n.t);
  return hTime(n.t);
}

function applyView() {
  const cam = document.getElementById("h-cam");
  if (cam) cam.setAttribute("transform", `translate(${H.view.x},${H.view.y}) scale(${H.view.k})`);
}

function fitView() {
  if (!H.laidOut.length) return;
  const svg = document.getElementById("h-svg");
  const w = svg.clientWidth || 900, h = svg.clientHeight || 600;
  const maxX = Math.max(...H.laidOut.map((n) => n.x)) + NODE_W + 40;
  const maxY = Math.max(...H.laidOut.map((n) => n.y)) + NODE_H + 20;
  // Never shrink past legibility — pan/scroll instead of rendering a smudge.
  H.view.k = Math.max(0.32, Math.min(1, Math.min(w / maxX, h / maxY)));
  H.view.x = 20; H.view.y = 16;
  applyView();
}

/* ---------- detail panel ---------- */
function showDetail(id) {
  H.sel = id;
  const n = H.data.nodes.find((x) => x.id === id);
  const el = document.getElementById("h-detail");
  if (!n) { el.innerHTML = ""; return; }
  const T = TYPES[n.type] || TYPES.tool;
  const rows = [];
  const add = (k, v) => { if (v != null && v !== "") rows.push([k, v]); };
  add("type", n.type);
  add("time", n.t ? new Date(n.t * 1000).toLocaleString() : "");
  if (n.type === "tool") {
    add("tool", n.tool); add("summary", n.summary);
    add("duration", n.durMs != null ? `${(n.durMs / 1000).toFixed(2)}s` : "");
    add("status", n.isError ? "ERROR" : (n.result != null ? "ok" : "no result recorded"));
  }
  if (n.type === "proc") { add("pid", n.pid); add("ppid", n.ppid); }
  if (n.type === "net") { add("ip", n.ip); add("port", n.port); add("state", n.state); add("process", n.proc); }
  if (n.type === "agent") {
    add("agent type", n.agentType); add("spawn depth", n.spawnDepth);
    add("linked to call", n.linked ? "yes (exact, via toolUseId)" : "no — attached to session root");
  }
  if (n.type === "session") { add("cwd", n.cwd); add("pid", n.pid); add("version", n.version); }
  add("model", n.model); add("output tokens", n.outTokens);

  const blocks = [];
  if (n.text) blocks.push(["text", n.text]);
  if (n.cmd) blocks.push(["command", n.cmd]);
  if (n.input) blocks.push(["input", n.input]);
  if (n.result) blocks.push(["result", n.result]);

  el.innerHTML =
    `<div class="hd-title" style="color:${T.c}">${hEsc(T.i)} ${hEsc(n.label || n.type)}</div>` +
    (n.inferred ? `<div class="hd-warn">time-correlated, not a recorded causal link</div>` : "") +
    `<table class="hd-tab">${rows.map(([k, v]) =>
      `<tr><th>${hEsc(k)}</th><td>${hEsc(v)}</td></tr>`).join("")}</table>` +
    blocks.map(([k, v]) =>
      `<div class="hd-block"><div class="hd-bk">${hEsc(k)}</div><pre>${hEsc(v)}</pre></div>`).join("");
  render();
}

/* ---------- wiring ---------- */
let inited = false;
function initHistory() {
  if (inited) return;
  inited = true;
  const chips = document.getElementById("h-filters");
  for (const [k, T] of Object.entries(TYPES)) {
    const el = document.createElement("span");
    el.className = "chip" + (H.hidden.has(k) ? "" : " on");
    el.dataset.k = k; el.textContent = T.n;
    el.style.setProperty("--chip", T.c);
    el.onclick = () => {
      H.hidden.has(k) ? H.hidden.delete(k) : H.hidden.add(k);
      el.classList.toggle("on");
      localStorage.setItem("cm.hgt", JSON.stringify([...H.hidden]));
      render();
    };
    chips.appendChild(el);
  }

  const svg = document.getElementById("h-svg");
  svg.addEventListener("click", (e) => {
    const tog = e.target.closest("[data-toggle]");
    if (tog) {
      const id = +tog.dataset.toggle;
      H.collapsed.has(id) ? H.collapsed.delete(id) : H.collapsed.add(id);
      return render();
    }
    const g = e.target.closest(".hn");
    if (g) showDetail(+g.dataset.id);
  });

  let drag = null;
  svg.addEventListener("mousedown", (e) => { drag = { x: e.clientX, y: e.clientY, vx: H.view.x, vy: H.view.y }; });
  window.addEventListener("mousemove", (e) => {
    if (!drag) return;
    H.view.x = drag.vx + (e.clientX - drag.x);
    H.view.y = drag.vy + (e.clientY - drag.y);
    applyView();
  });
  window.addEventListener("mouseup", () => { drag = null; });
  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = svg.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const k = Math.min(2.5, Math.max(0.12, H.view.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
    H.view.x = mx - (mx - H.view.x) * (k / H.view.k);
    H.view.y = my - (my - H.view.y) * (k / H.view.k);
    H.view.k = k;
    applyView();
  }, { passive: false });

  document.getElementById("h-fit").onclick = () => fitView();
  document.getElementById("h-expand").onclick = () => { H.collapsed.clear(); render(true); };
  document.getElementById("h-collapse").onclick = () => {
    H.collapsed = new Set(H.data.nodes.filter((n) => n.type === "prompt" || n.type === "agent").map((n) => n.id));
    render(true);
  };
  document.getElementById("h-reload").onclick = () =>
    loadHistory(document.getElementById("session-filter").value);
  document.getElementById("h-search").oninput = (e) => { H.search = e.target.value; render(); };

  const VIEWS = ["live", "history", "cyber", "config"];
  for (const btn of document.querySelectorAll(".tab")) {
    btn.onclick = () => {
      const want = btn.dataset.tab;
      for (const b of document.querySelectorAll(".tab")) b.classList.toggle("active", b === btn);
      for (const v of VIEWS) {
        const el = document.getElementById("view-" + v);
        if (el) el.style.display = v === want ? "" : "none";
      }
      if (want === "history" && !H.data) loadHistory(document.getElementById("session-filter").value);
      if (want === "config" && typeof loadConfig === "function") loadConfig();
      if (want === "cyber") {
        loadFindings();
        const b = document.getElementById("c-badge");
        if (b) { b.textContent = ""; b.className = "badge"; }
      }
    };
  }
}

document.addEventListener("DOMContentLoaded", initHistory);
if (document.readyState !== "loading") initHistory();
