/* claudemon Cyber tab: rule findings, live + backfilled from history. */

const C = {
  findings: [],
  seen: new Set(),
  sel: null,
  minSev: Number(localStorage.getItem("cm.minSev") || 0),
  cat: "",
  search: "",
  rules: [],
};

const SEV = [
  { k: "info", n: "info", c: "#6d7581" },
  { k: "low", n: "low", c: "#4fa8e8" },
  { k: "medium", n: "medium", c: "#e0b341" },
  { k: "high", n: "high", c: "#e08a4a" },
  { k: "critical", n: "critical", c: "#e05a5a" },
];

const cEsc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const cTime = (t) => {
  const d = new Date((t || 0) * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};

function sevColour(s) {
  return (SEV.find((x) => x.k === s) || SEV[0]).c;
}

async function loadFindings() {
  try {
    const r = await fetch("/api/findings?limit=1200");
    const d = await r.json();
    if (d.disabled) {
      document.getElementById("c-list").innerHTML =
        '<div class="row num">detection engine disabled (--no-rules)</div>';
      return;
    }
    C.findings = d.findings || [];
    C.seen = new Set(C.findings.map((f) => f.key + f.ts));
    renderCyber(d.summary || {});
  } catch (e) { /* retried on next tick */ }
}

async function loadRuleList() {
  try {
    const r = await fetch("/api/rules");
    const d = await r.json();
    C.rules = d.rules || [];
  } catch (e) { C.rules = []; }
}

/* live findings arrive on the SSE stream */
function onFinding(f) {
  const k = f.key + f.ts;
  if (C.seen.has(k)) return;
  C.seen.add(k);
  C.findings.unshift(f);
  if (C.findings.length > 1500) C.findings.pop();
  renderCyber();
  if (f.sev >= 3) flashAlert(f);
}

function flashAlert(f) {
  const el = document.getElementById("c-alert");
  el.style.display = "";
  el.style.borderColor = sevColour(f.severity);
  el.innerHTML = `<b style="color:${sevColour(f.severity)}">${cEsc(f.severity.toUpperCase())}</b> ` +
    `${cEsc(f.ruleId)} · ${cEsc(f.name)} — ${cEsc(String(f.evidence).slice(0, 120))}`;
}

function visibleFindings() {
  return C.findings.filter((f) => {
    if (f.sev < C.minSev) return false;
    if (C.cat && f.category !== C.cat) return false;
    if (C.search && !JSON.stringify(f).toLowerCase().includes(C.search)) return false;
    return true;
  });
}

function renderCyber(summary) {
  const rows = visibleFindings();
  const counts = {};
  for (const f of C.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  document.getElementById("c-tiles").innerHTML = SEV.slice().reverse().map((s) => `
    <div class="tile ${C.minSev === SEVIDX(s.k) ? "on" : ""}" data-sev="${s.k}"
         style="--tc:${s.c}"><b>${counts[s.k] || 0}</b><span>${s.n}</span></div>`).join("");
  for (const t of document.querySelectorAll("#c-tiles .tile")) {
    t.onclick = () => {
      const idx = SEVIDX(t.dataset.sev);
      C.minSev = C.minSev === idx ? 0 : idx;
      localStorage.setItem("cm.minSev", C.minSev);
      renderCyber();
    };
  }

  const cats = [...new Set(C.findings.map((f) => f.category))].sort();
  const sel = document.getElementById("c-cat");
  if (sel.dataset.n !== String(cats.length)) {
    sel.dataset.n = cats.length;
    sel.innerHTML = '<option value="">all categories</option>' +
      cats.map((c) => `<option value="${cEsc(c)}">${cEsc(c)}</option>`).join("");
    sel.value = C.cat;
  }

  document.getElementById("c-count").textContent =
    `${rows.length} shown · ${C.findings.length} total · ${C.rules.length} rules`;

  document.getElementById("c-list").innerHTML = rows.length ? rows.map((f) => `
    <div class="find ${C.sel === f.key + f.ts ? "sel" : ""}" data-k="${cEsc(f.key + f.ts)}"
         style="--tc:${sevColour(f.severity)}">
      <span class="f-sev">${cEsc(f.severity)}</span>
      <span class="f-time">${cTime(f.ts)}</span>
      <span class="f-id">${cEsc(f.ruleId)}</span>
      <span class="f-name">${cEsc(f.name)}</span>
      <span class="f-who">${f.agentLabel ? "🤖 " + cEsc(f.agentLabel) : "main"}</span>
      <span class="f-ev">${cEsc(String(f.evidence).slice(0, 120))}</span>
    </div>`).join("")
    : '<div class="row num">no findings at this severity — nothing matched, which is the expected steady state</div>';

  for (const el of document.querySelectorAll("#c-list .find")) {
    el.onclick = () => {
      C.sel = el.dataset.k;
      const f = C.findings.find((x) => x.key + x.ts === C.sel);
      showFinding(f);
      renderCyber();
    };
  }
}

const SEVIDX = (k) => SEV.findIndex((s) => s.k === k);

function showFinding(f) {
  const el = document.getElementById("c-detail");
  if (!f) { el.innerHTML = ""; return; }
  const rule = C.rules.find((r) => r.id === f.ruleId) || {};
  const row = (k, v) => v ? `<tr><th>${cEsc(k)}</th><td>${cEsc(v)}</td></tr>` : "";
  el.innerHTML = `
    <div class="hd-title" style="color:${sevColour(f.severity)}">
      ${cEsc(f.severity.toUpperCase())} · ${cEsc(f.ruleId)}</div>
    <div class="c-name">${cEsc(f.name)}</div>
    <table class="hd-tab">
      ${row("category", f.category)}
      ${row("ATT&CK", f.mitre)}
      ${row("when", new Date(f.ts * 1000).toLocaleString())}
      ${row("observed in", f.source)}
      ${row("actor", f.agentLabel ? "subagent: " + f.agentLabel : "main session")}
      ${row("tool", f.tool)}
      ${row("cwd", f.cwd)}
    </table>
    <div class="hd-block"><div class="hd-bk">evidence</div><pre>${cEsc(f.evidence)}</pre></div>
    <div class="hd-block"><div class="hd-bk">why this matters</div>
      <div class="c-prose">${cEsc(f.rationale || rule.rationale || "")}</div></div>
    <div class="hd-block"><div class="hd-bk">what to check</div>
      <div class="c-prose">${cEsc(f.check || rule.check || "")}</div></div>
    ${typeof shieldButtonsFor === "function" ? shieldButtonsFor(f) : ""}
    <div class="hd-block"><div class="hd-bk">full context</div><pre>${cEsc(f.context)}</pre></div>`;
}

function initCyber() {
  document.getElementById("c-cat").onchange = (e) => { C.cat = e.target.value; renderCyber(); };
  document.getElementById("c-search").oninput = (e) => {
    C.search = e.target.value.toLowerCase(); renderCyber();
  };
  document.getElementById("c-reload").onclick = () => loadFindings();
  document.getElementById("c-alert").onclick = (e) => { e.target.style.display = "none"; };
  loadRuleList();
}

document.addEventListener("DOMContentLoaded", initCyber);
if (document.readyState !== "loading") initCyber();
