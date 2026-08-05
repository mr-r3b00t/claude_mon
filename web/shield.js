/* claudemon Shield: countermeasure controls and audit trail. */

const S = { status: null, busy: false };

const sEsc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const sTime = (t) => {
  const d = new Date((t || 0) * 1000), p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};

async function shieldGet() {
  try {
    const r = await fetch("/api/shield");
    S.status = await r.json();
    renderShield();
  } catch (e) { /* retried on the next tick */ }
}

async function shieldPost(path, body) {
  if (S.busy) return;
  S.busy = true;
  try {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (d.status) S.status = d.status;
    else if (d.mode) S.status = d;
    renderShield();
    if (d.result) toast(d.result);
    if (d.error) toast({ result: "error", message: d.error, action: "?" });
  } catch (e) {
    toast({ result: "error", message: String(e), action: "?" });
  } finally {
    S.busy = false;
    shieldGet();
  }
}

function toast(rec) {
  const el = document.getElementById("s-toast");
  if (!el) return;
  const good = rec.result === "ok";
  el.style.display = "";
  el.className = "s-toast " + (good ? "ok" : rec.result === "dry-run" ? "dry" : "bad");
  el.textContent = `${rec.action} · ${rec.result} — ${rec.message || ""}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.style.display = "none"; }, 9000);
}

/* Destructive actions get an explicit confirmation when the shield is live. */
function confirmAction(action, label) {
  if (!S.status || S.status.mode !== "armed") return true;
  if (!["kill", "freeze", "sinkhole"].includes(action)) return true;
  return window.confirm(
    `Shield is ARMED — this will really happen.\n\n${action.toUpperCase()} ${label}\n\n` +
    (action === "kill" ? "The process is terminated. Unsaved work in it is lost."
     : action === "freeze" ? "The process is suspended until you resume it."
     : "The host is blocklisted and its connections are enforced against.") +
    "\n\nProceed?");
}

window.shieldAct = function (action, target, label) {
  if (!confirmAction(action, label || JSON.stringify(target))) return;
  shieldPost("/api/shield/action", { action, target, reason: `operator: ${label || ""}` });
};

function renderShield() {
  const st = S.status;
  const bar = document.getElementById("s-bar");
  if (!bar) return;
  if (!st || st.disabled) {
    bar.innerHTML = '<span class="s-off">shield disabled (--no-shield)</span>';
    return;
  }
  const modes = ["off", "monitor", "armed"];
  bar.innerHTML =
    `<span class="s-label">SHIELD</span>` +
    `<span class="s-modes">` + modes.map((m) =>
      `<button class="s-mode ${st.mode === m ? "on " + m : ""}" data-mode="${m}">${m}</button>`
    ).join("") + `</span>` +
    `<label class="s-auto"><input type="checkbox" id="s-auto" ${st.auto?.enabled ? "checked" : ""}>` +
    ` auto-respond <span class="num">≥ ${sEsc(st.auto?.minSeverity || "critical")}</span></label>` +
    `<span class="s-stat">${st.frozen.length} frozen · ${st.blocked.length} blocked · ` +
    `${st.actionsLastMinute}/${st.rateLimit} per min</span>` +
    (st.tripped ? `<span class="s-trip">circuit breaker tripped — disarmed</span>` : "") +
    (st.mode === "armed" ? `<span class="s-live">LIVE — actions execute</span>`
      : st.mode === "monitor" ? `<span class="s-dry">dry run — nothing executes</span>` : "");

  const g = st.gate || {};
  const gmodes = ["off", "warn", "ask", "block"];
  bar.innerHTML +=
    `<span class="s-gate">` +
    `<span class="s-label">PRE-EXEC</span>` +
    `<span class="s-modes">` + gmodes.map((m) =>
      `<button class="s-gmode ${(g.enabled ? g.mode : "off") === m ? "on " + m : ""}" ` +
      `data-gmode="${m}">${m}</button>`).join("") + `</span>` +
    `<span class="s-stat2">${g.enabled
      ? `${g.counts?.block || 0} blocked · ${g.counts?.ask || 0} asked · ` +
        `${g.counts?.warn || 0} warned · fail-${g.failMode}`
      : "not gating — needs the PreToolUse hook"}</span></span>`;

  for (const b of bar.querySelectorAll(".s-gmode")) {
    b.onclick = () => {
      const m = b.dataset.gmode;
      if ((m === "block" || m === "ask") &&
          !window.confirm(
            `Set the pre-execution gate to ${m.toUpperCase()}?\n\n` +
            (m === "block" ? "Matching tool calls will be REFUSED before they run."
                           : "Matching tool calls will prompt you for permission.") +
            "\n\nThis needs the PreToolUse hook installed:\n" +
            "  python3 install-hooks.py --apply\n\n" +
            "Without it the gate records but cannot interrupt. Proceed?")) return;
      shieldPost("/api/shield/mode", { gate: { enabled: m !== "off", mode: m } });
    };
  }

  for (const b of bar.querySelectorAll(".s-mode")) {
    b.onclick = () => {
      if (b.dataset.mode === "armed" &&
          !window.confirm("Arm the shield?\n\nCountermeasures will execute automatically " +
                          "against the agent's process tree according to shield.json.\n\n" +
                          "Session and system processes stay protected. Proceed?")) return;
      shieldPost("/api/shield/mode", { mode: b.dataset.mode });
    };
  }
  const auto = document.getElementById("s-auto");
  if (auto) auto.onchange = () => shieldPost("/api/shield/mode", { auto: auto.checked });

  const panel = document.getElementById("s-state");
  if (panel) {
    panel.innerHTML =
      (st.frozen.length ? st.frozen.map((f) => `
        <div class="row"><span class="num">pid ${f.pid}</span>
          <span class="grow" title="${sEsc(f.cmd)}">🧊 ${sEsc(f.cmd).slice(0, 60)}</span>
          <button class="btn" onclick="shieldAct('resume',{pid:${f.pid}},'pid ${f.pid}')">resume</button>
        </div>`).join("") : "") +
      (st.blocked.length ? st.blocked.map((b) => `
        <div class="row"><span class="num">${b.hits} hits</span>
          <span class="grow">🕳 ${sEsc(b.host)}</span>
          <button class="btn" onclick="shieldAct('unsinkhole',{host:'${sEsc(b.host)}'},'${sEsc(b.host)}')">unblock</button>
        </div>`).join("") : "") ||
      '<div class="row num">nothing frozen or blocked</div>';
  }

  renderEgress(st.egress || {});

  const log = document.getElementById("s-log");
  if (log) {
    log.innerHTML = st.recentActions.length ? st.recentActions.map((a) => `
      <div class="row s-act ${a.result}">
        <span class="num">${sTime(a.ts)}</span>
        <span class="s-a">${sEsc(a.action)}</span>
        <span class="s-r">${sEsc(a.result)}</span>
        <span class="grow" title="${sEsc(a.message)}">${sEsc(a.message)}</span>
        <span class="num">${sEsc(a.actor)}</span>
      </div>`).join("") : '<div class="row num">no actions taken</div>';
  }
}

/* ---------- egress allow / block lists ---------- */
window.egressOp = function (op, which, entry) {
  if (op === "mode" && which === "allowlist" &&
      !window.confirm("Switch egress policy to ALLOWLIST (default-deny)?\n\n" +
        "Anything not on the allow list — or on the never list — is treated as a " +
        "violation. Build the allow list first, or expect noise.\n\nProceed?")) return;
  shieldPost("/api/shield/egress",
    op === "mode" ? { op, mode: which } : { op, list: which, entry });
};

function renderEgress(eg) {
  const bar = document.getElementById("e-bar");
  if (!bar) return;
  const modes = [["monitor", "monitor"], ["blocklist", "block-list"], ["allowlist", "allow-list"]];
  bar.innerHTML =
    `<span class="s-modes">` + modes.map(([m, label]) =>
      `<button class="s-emode ${eg.mode === m ? "on " + m : ""}" data-em="${m}">${label}</button>`
    ).join("") + `</span>` +
    `<span class="num">on violation: ${sEsc(eg.onViolation || "alert")}</span>` +
    `<form id="e-add" class="e-add">
       <input id="e-entry" placeholder="host, *.domain, 10.0.0.0/8, :4444" spellcheck="false">
       <button type="button" class="mini" data-add="allow" title="add to allow list">＋allow</button>
       <button type="button" class="mini danger" data-add="block" title="add to block list">＋block</button>
     </form>`;
  for (const b of bar.querySelectorAll(".s-emode"))
    b.onclick = () => egressOp("mode", b.dataset.em);
  for (const b of bar.querySelectorAll("[data-add]")) {
    b.onclick = () => {
      const v = document.getElementById("e-entry").value.trim();
      if (v) egressOp("add", b.dataset.add, v);
    };
  }
  document.getElementById("e-entry").onkeydown = (e) => {
    if (e.key === "Enter") { e.preventDefault();
      const v = e.target.value.trim(); if (v) egressOp("add", "allow", v); }
  };

  const c = eg.counts || {};
  const hint = document.getElementById("e-hint");
  if (hint) hint.textContent =
    `${(eg.allow || []).length} allow · ${(eg.block || []).length} block · ` +
    `${(eg.never || []).length} never` + (c.blocked ? ` · ${c.blocked} violations` : "");

  const row = (kind, e) => `
    <div class="row e-row ${kind}">
      <span class="e-tag ${kind}">${kind}</span>
      <span class="grow">${sEsc(e)}</span>
      ${kind === "never" ? '<span class="num">protected</span>'
        : `<button class="mini" onclick="egressOp('remove','${kind}','${sEsc(e)}')">remove</button>`}
    </div>`;
  document.getElementById("e-lists").innerHTML =
    (eg.block || []).map((e) => row("block", e)).join("") +
    (eg.allow || []).map((e) => row("allow", e)).join("") +
    (eg.never || []).map((e) => row("never", e)).join("") +
    ((eg.recent || []).length
      ? `<div class="row e-head">recent decisions</div>` + eg.recent.slice(0, 12).map((r) => `
          <div class="row e-row ${r.verdict}">
            <span class="e-tag ${r.verdict === "block" ? "block" : "allow"}">${sEsc(r.verdict)}</span>
            <span class="grow" title="${sEsc(r.reason)}">${sEsc(r.peer)}</span>
            <span class="num">${sEsc(r.list)}${r.enforced ? " · enforced" : ""}</span>
          </div>`).join("")
      : "");
}

/* Action buttons offered for a selected finding, based on what it points at. */
window.shieldButtonsFor = function (f) {
  if (!S.status || S.status.disabled || S.status.mode === "off") return "";
  const btns = [];
  const host = (f.source === "net" && f.evidence) ? String(f.evidence).split(":")[0] : null;
  const pid = f.pid || (/\bpid (\d+)/.exec(f.context || "") || [])[1];
  if (pid) {
    btns.push(`<button class="btn act" onclick="shieldAct('freeze',{pid:${pid}},'pid ${pid}')">🧊 freeze pid ${pid}</button>`);
    btns.push(`<button class="btn act danger" onclick="shieldAct('kill',{pid:${pid}},'pid ${pid}')">💀 kill pid ${pid}</button>`);
  }
  if (host && !/^\d+$/.test(host)) {
    btns.push(`<button class="btn act" onclick="shieldAct('sinkhole',{host:'${sEsc(host)}'},'${sEsc(host)}')">🕳 sinkhole ${sEsc(host)}</button>`);
  }
  if (!btns.length) {
    return '<div class="hd-block"><div class="hd-bk">countermeasures</div>' +
           '<div class="c-prose num">no process or host is attributable to this finding — ' +
           'a tool call is not a process. Act from the Processes or Network panel instead.</div></div>';
  }
  return '<div class="hd-block"><div class="hd-bk">countermeasures</div>' +
         `<div class="s-btns">${btns.join("")}</div></div>`;
};

document.addEventListener("DOMContentLoaded", shieldGet);
if (document.readyState !== "loading") shieldGet();
setInterval(shieldGet, 4000);
