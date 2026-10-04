"use strict";
// AegisQ dashboard. All server data is inserted with textContent / DOM APIs, never innerHTML.

const TOKEN_KEY = "aegisq-token";
let token = null;
try { token = sessionStorage.getItem(TOKEN_KEY); } catch (_) { token = null; }
let overview = null;
let timers = [];

const $ = (sel) => document.querySelector(sel);
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const SVG = "http://www.w3.org/2000/svg";
function s(tag, attrs) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  return el;
}
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// ------------------------------------------------------------------ API --
class AuthError extends Error {}
async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...(opts.headers || {}), Authorization: `Bearer ${token}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) },
  });
  if (res.status === 401) throw new AuthError("unauthorized");
  if (res.status === 404) return null;
  if (!res.ok) {
    let msg = `${res.status}`;
    try {
      const d = (await res.json()).detail;
      if (Array.isArray(d)) msg = d.map((x) => `${(x.loc || []).slice(1).join(".") || "input"}: ${x.msg}`).join("; ");
      else if (d) msg = d;
    } catch (_) { /* ignore */ }
    throw new Error(msg);
  }
  const type = res.headers.get("content-type") || "";
  return type.includes("json") ? res.json() : res.text();
}
async function download(path, filename) {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) { alert(`Download failed (${res.status})`); return; }
  const url = URL.createObjectURL(await res.blob());
  const a = h("a", { href: url, download: filename });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ------------------------------------------------------------- tooltip --
const tip = () => $("#tooltip");
function showTip(evt, lines) {
  const t = tip();
  t.replaceChildren(...lines.map((l, i) => h(i === 0 ? "strong" : "div", {}, l)));
  t.classList.remove("hidden");
  const pad = 12, r = t.getBoundingClientRect();
  let x = evt.clientX + pad, y = evt.clientY + pad;
  if (x + r.width > window.innerWidth) x = evt.clientX - r.width - pad;
  if (y + r.height > window.innerHeight) y = evt.clientY - r.height - pad;
  t.style.left = `${Math.max(4, x)}px`; t.style.top = `${Math.max(4, y)}px`;
}
const hideTip = () => tip().classList.add("hidden");

// ------------------------------------------------------------- labels --
const STATUS = {
  pq_ready: ["good", "PQ ready"], classical: ["warning", "Classical"], tls12_only: ["serious", "TLS 1.2 only"],
  legacy_tls: ["critical", "Legacy TLS"], plaintext: ["critical", "Plaintext"], unreachable: ["muted", "Unreachable"],
  error: ["muted", "Error"],
};
const SEV = { critical: "critical", high: "serious", medium: "warning", low: "muted", none: "good", unknown: "muted" };
const badge = (kind, text) => h("span", { class: `badge s-${kind}` }, text);
const fmt = (n, d = 1) => (n === null || n === undefined ? "–" : Number(n).toFixed(d));

function severity(margin, status) {
  if (status === "pq_ready") return "none";
  if (status === "plaintext") return "critical";
  if (status === "unreachable" || status === "error") return "unknown";
  if (margin >= 10) return "critical";
  if (margin > 0) return "high";
  if (margin > -5) return "medium";
  return "low";
}

// ------------------------------------------------------------ overview --
function renderTiles(ov, z) {
  const tiles = $("#tiles");
  if (!ov.scan) {
    tiles.replaceChildren();
    $("#hero-title").textContent = "Find it. Rank it. Fix it safely.";
    return;
  }
  const sm = ov.scan.summary;
  const reachable = sm.total - sm.unreachable - sm.error;
  const pct = reachable ? Math.round((100 * sm.pq_ready) / reachable) : 0;
  const atRisk = ov.services.filter((r) => severity(r.x + r.y - (r.status === "plaintext" ? 0 : z), r.status) in { critical: 1, high: 1 }).length;
  $("#hero-title").textContent = reachable ? `${pct}% of your fleet is quantum-safe.` : "No reachable services yet.";
  $("#hero-sub").textContent =
    `${atRisk} of ${sm.total} services hold data that is already exposed to harvest-now, decrypt-later at Z = ${z} years. ` +
    "Every fix is proposed by the agent, approved by a named person, tested, verified, and rolled back if it fails.";
  const tile = (k, v, l) => h("div", { class: "tile" }, h("div", { class: "k" }, k), h("div", { class: "v" }, v), h("div", { class: "l" }, l));
  tiles.replaceChildren(
    tile("Post-quantum ready", `${pct}%`, `${sm.pq_ready} of ${reachable} reachable services complete a hybrid ML-KEM handshake`),
    tile("At risk now", atRisk, `X + Y > Z at Z = ${z}`),
    tile("Scanned", sm.total, "TLS and SSH services"),
    tile("Classical or old TLS", sm.classical + sm.tls12_only + sm.legacy_tls, "need a key-exchange upgrade"),
    tile("Plaintext HTTP", sm.plaintext, "readable today"),
  );
}

const years = (v) => `${fmt(Math.abs(v), Math.abs(v) % 1 ? 1 : 0)} year${Math.abs(v) === 1 ? "" : "s"}`;

// One plain sentence per server: why it got its risk level.
function why(r) {
  if (r.status === "pq_ready") return "Protected: completes a post-quantum handshake.";
  if (r.status === "plaintext") return "No encryption at all: readable today.";
  if (r.status === "unreachable" || r.status === "error") return "Could not connect, so the risk is unknown.";
  return r.margin > 0 ? `Exposed: data outlives the guess by ${years(r.margin)}.` : `Safe for now: ${years(r.margin)} to spare.`;
}

function renderRanking() {
  if (!overview) return;
  const z = Number($("#z").value);
  $("#z-out").textContent = z;
  renderTiles(overview, z);
  const tbody = $("#ranking tbody");
  $("#no-scan").classList.toggle("hidden", !!overview.scan);
  $("#ranking-hint").classList.toggle("hidden", !overview.scan);
  // Plaintext is readable today, so Z never discounts it (mirrors aegisq.risk).
  const marginOf = (r) => r.x + r.y - (r.status === "plaintext" ? 0 : z);
  const rows = overview.services.map((r) => ({ ...r, margin: marginOf(r), sev: severity(marginOf(r), r.status) }));
  const group = (r) => (r.sev === "none" ? 2 : r.sev === "unknown" ? 1 : 0);
  rows.sort((a, b) => group(a) - group(b) || b.margin - a.margin || b.x - a.x || a.name.localeCompare(b.name));
  const out = [];
  rows.forEach((r, i) => {
    const [sk, sl] = STATUS[r.status] || ["muted", r.status];
    const fact = (k, v) => h("div", { class: "fact" }, h("span", { class: "fact-k" }, k), h("span", {}, v));
    const detail = h("tr", { class: "detail hidden" }, h("td", { colspan: 6 },
      h("div", { class: "facts" },
        fact("Key exchange", r.group || "–"),
        fact("Data must stay secret for", `${years(r.x)} (${r.data_category} data, X)`),
        fact("Time to fix", `${years(r.y)}: ${r.y_reason} (Y)`),
        r.status === "pq_ready" || r.status === "unreachable" || r.status === "error" ? null
          : fact("Margin", `X + Y − Z = ${r.margin > 0 ? "+" : ""}${fmt(r.margin)} years${r.status === "plaintext" ? " (Z ignored: readable today)" : ""}`),
        fact("Managed", r.managed ? "Yes: the agent can propose a fix." : "No: scan only. Hand this to the server's owner.")),
      r.findings.length ? h("ul", { class: "findings" }, r.findings.map((f) => h("li", {}, f))) : null,
      r.errors.length ? h("div", { class: "bad" }, r.errors.join("; ")) : null));
    const row = h("tr", { class: "expandable", tabindex: 0, "aria-expanded": "false" },
      h("td", { class: "num muted" }, i + 1),
      h("td", {}, h("div", { class: "svc" }, r.name), h("div", { class: "muted small mono" }, r.endpoint),
        h("div", { class: "phone-only" }, badge(sk, sl))),
      h("td", {}, badge(sk, sl)),
      h("td", {}, r.data_category),
      h("td", {}, badge(SEV[r.sev], r.sev === "none" ? "safe" : r.sev), h("div", { class: "why" }, why(r))),
      h("td", { class: "chev", "aria-hidden": "true" }, h("span", {}, "›")));
    const toggle = () => { detail.classList.toggle("hidden"); row.setAttribute("aria-expanded", String(!detail.classList.contains("hidden"))); };
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    out.push(row, detail);
  });
  tbody.replaceChildren(...out);
  const exposed = rows.filter((r) => r.sev === "critical" || r.sev === "high").map((r) => r.name);
  const sum = $("#z-summary");
  if (!overview.scan) sum.replaceChildren();
  else if (!exposed.length) sum.replaceChildren(h("span", { class: "z-ok" }, `In ${years(z)}: no server has data already at risk.`));
  else sum.replaceChildren(h("span", {}, `In ${years(z)}: `, h("strong", {}, `${exposed.length} at risk now`)),
    ...exposed.map((n) => h("span", { class: "chip" }, n)));
}

async function loadOverview(first) {
  overview = await api("/api/overview");
  if (!overview) return;
  if (first) {
    $("#z").value = overview.z_default;
    $("#estimates tbody").replaceChildren(...overview.estimates.map((e) =>
      h("tr", {}, h("td", {}, e.estimate), h("td", {}, e.target), h("td", {}, e.logical_qubits), h("td", {}, e.physical_qubits), h("td", {}, e.runtime))));
    $("#estimate-note").textContent = overview.estimate_note;
    $("#rescan").disabled = !overview.can_rescan;
    $("#rescan").title = overview.can_rescan ? "" : "Start `aegisq serve --inventory FILE` to enable";
  }
  renderRanking();
}

// ----------------------------------------------------------- approvals --
function diffView(text) {
  const pre = h("div", { class: "diff", role: "region", "aria-label": "Proposed diff" });
  for (const line of text.split("\n")) {
    const cls = line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : "";
    pre.append(h("span", { class: cls }, line + "\n"));
  }
  return pre;
}

async function decide(id, approve) {
  let reason = null;
  if (!approve) {
    reason = prompt("Reason for rejecting (recorded in the audit log):");
    if (reason === null) return;
  } else if (!confirm("Apply this change? It will be tested, reloaded and verified, and rolled back automatically on failure.")) {
    return;
  }
  try {
    await api(`/api/approvals/${encodeURIComponent(id)}/decision`, { method: "POST", body: JSON.stringify({ approve, reason }) });
  } catch (e) { alert(`Decision failed: ${e.message}`); }
  loadApprovals();
}

async function loadApprovals() {
  const all = (await api("/api/approvals")) || [];
  const pending = all.filter((a) => a.status === "pending");
  const navCount = $("#nav-pending");
  navCount.classList.toggle("hidden", !pending.length);
  navCount.textContent = pending.length;
  const banner = $("#run-pending");
  banner.classList.toggle("hidden", !pending.length);
  banner.textContent = pending.length
    ? `${pending.length} change${pending.length > 1 ? "s" : ""} waiting for your approval (${pending.map((a) => a.service).join(", ")}) → review`
    : "";
  const box = $("#pending");
  if (!pending.length) box.replaceChildren(h("p", { class: "muted" }, "Nothing waiting for approval."));
  else box.replaceChildren(...pending.map((a) => h("div", { class: "pending-item" },
    h("div", { class: "row-between" }, h("strong", {}, a.service), h("span", { class: "muted small mono" }, `approval ${a.id} · expires ${new Date(a.expires_at * 1000).toLocaleTimeString()}`)),
    diffView(a.diff),
    h("div", { class: "btns" },
      h("button", { type: "button", onclick: () => decide(a.id, true) }, "Approve"),
      h("button", { type: "button", class: "danger", onclick: () => decide(a.id, false) }, "Reject")))));
  const decided = all.filter((a) => a.status !== "pending").slice(0, 30);
  $("#decided tbody").replaceChildren(...decided.map((a) => h("tr", {},
    h("td", { class: "small" }, new Date((a.decided_at || a.requested_at) * 1000).toLocaleString()),
    h("td", {}, a.service), h("td", {}, a.status), h("td", {}, a.decided_by || "–"), h("td", { class: "mono small" }, a.summary))));
}

// --------------------------------------------------------------- audit --
async function loadAudit() {
  const [rows, ver] = await Promise.all([api("/api/audit?limit=60"), api("/api/audit/verify")]);
  const b = $("#audit-badge");
  b.className = `badge badge-dark s-${ver && ver.ok ? "good" : "critical"}`;
  b.textContent = ver ? (ver.ok ? `audit intact · ${ver.entries}` : "audit TAMPERED") : "audit ?";
  b.title = ver && !ver.ok ? ver.error : `${ver ? (ver.keyed ? "HMAC" : "SHA-256") : ""} hash chain`;
  $("#audit tbody").replaceChildren(...(rows || []).slice().reverse().map((e) => h("tr", {},
    h("td", { class: "num" }, e.seq), h("td", { class: "small mono" }, e.ts.slice(0, 19).replace("T", " ")),
    h("td", {}, e.actor), h("td", { class: "mono" }, e.event),
    h("td", { class: "small mono" }, JSON.stringify(e.data).slice(0, 180)))));
}

// -------------------------------------------------------------- charts --
// Grouped bar chart (1-2 series) with dashed reference lines and per-group hover.
function barChart({ labels, series, refs = [], yMin, yMax, valueFmt = (v) => v.toFixed(4), title }) {
  const W = 640, H = 200, L = 46, R = 8, T = 8, B = 22;
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": title });
  const n = labels.length, k = series.length;
  const y = (v) => T + (H - T - B) * (1 - (v - yMin) / (yMax - yMin));
  for (let i = 0; i <= 4; i++) {
    const v = yMin + ((yMax - yMin) * i) / 4;
    svg.append(s("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "gridline" }));
    const t = s("text", { x: L - 4, y: y(v) + 3, "text-anchor": "end", class: "axis-text" }); t.textContent = valueFmt(v); svg.append(t);
  }
  const gw = (W - L - R) / n;
  const bw = Math.max(1, (gw - (gw > 4 ? 1 : 0)) / k);
  const zero = y(Math.max(yMin, Math.min(0, yMax)));
  labels.forEach((lab, i) => {
    series.forEach((ser, j) => {
      const v = ser.values[i];
      const yy = y(Math.max(yMin, Math.min(yMax, v)));
      svg.append(s("rect", { x: L + i * gw + j * bw, y: Math.min(yy, zero), width: Math.max(0.6, bw - (k > 1 ? 0.3 : 0)),
        height: Math.max(0.5, Math.abs(zero - yy)), class: ser.cls, rx: bw > 6 ? 2 : 0 }));
    });
    const hit = s("rect", { x: L + i * gw, y: T, width: gw, height: H - T - B, class: "hit" });
    hit.addEventListener("mousemove", (e) => showTip(e, [lab, ...series.map((ser) => `${ser.name}: ${valueFmt(ser.values[i])}`)]));
    hit.addEventListener("mouseleave", hideTip);
    svg.append(hit);
  });
  refs.forEach((r) => {
    svg.append(s("line", { x1: L, x2: W - R, y1: y(r.v), y2: y(r.v), class: "ref" }));
    const t = s("text", { x: W - R - 2, y: y(r.v) - 3, "text-anchor": "end", class: "axis-text" }); t.textContent = r.label; svg.append(t);
  });
  const xl = s("text", { x: L, y: H - 6, class: "axis-text" }); xl.textContent = `${n} qubits, ordered by readout quality`; svg.append(xl);
  return svg;
}

function heatmap(matrix, qubits, band) {
  const n = matrix.length, px = Math.max(3, Math.floor(400 / n));
  const c = h("canvas", { width: n * px, height: n * px, role: "img", "aria-label": "Qubit-to-qubit correlation heatmap" });
  const ctx = c.getContext("2d");
  const parse = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
  const neg = parse(css("--div-neg")), mid = parse(css("--div-mid")), pos = parse(css("--div-pos"));
  const m = Math.max(band * 3, 0.05);
  const mix = (a, b, t) => a.map((x, i) => Math.round(x + (b[i] - x) * t));
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) {
    const v = i === j ? 0 : matrix[i][j];
    const t = Math.min(1, Math.abs(v) / m);
    const [r, g, b] = v < 0 ? mix(mid, neg, t) : mix(mid, pos, t);
    ctx.fillStyle = `rgb(${r},${g},${b})`;
    ctx.fillRect(j * px, i * px, px, px);
  }
  c.addEventListener("mousemove", (e) => {
    const rect = c.getBoundingClientRect();
    const j = Math.floor(((e.clientX - rect.left) / rect.width) * n), i = Math.floor(((e.clientY - rect.top) / rect.height) * n);
    if (i < 0 || j < 0 || i >= n || j >= n) return hideTip();
    showTip(e, [`qubits ${qubits[i]} × ${qubits[j]}`, i === j ? "diagonal" : `r = ${matrix[i][j].toFixed(4)}`, `chance band ±${band.toFixed(3)}`]);
  });
  c.addEventListener("mouseleave", hideTip);
  return c;
}

function chartBox(title, sub, legend, el) {
  return h("div", { class: "chart" }, h("h3", {}, title), sub ? h("p", { class: "muted small" }, sub) : null, legend, el);
}

async function loadEntropy() {
  const d = await api("/api/entropy");
  if (!d) return;
  const box = $("#entropy");
  const q = d.qubits.map((x) => `qubit ${x}`);
  const band = d.noise_band;
  const absMax = (arr, floor) => Math.max(floor, ...arr.map(Math.abs)) * 1.15;
  const errMax = Math.max(0.01, ...d.readout_error_p01, ...d.readout_error_p10) * 1.15;
  const legend2 = h("div", { class: "legend" }, h("span", {}, h("i", { class: "sw1" }), "P(1 | prepared 0)"), h("span", {}, h("i", { class: "sw2" }), "P(0 | prepared 1)"));
  const kv = (pairs) => h("dl", { class: "kv" }, pairs.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  const tests = (side) => d.tests[side].map((t) => `${t.test}: p = ${t.p_value.toFixed(3)} ${t.pass ? "✓ pass" : "✗ FAIL"}`).join(" · ");
  box.replaceChildren(
    d.warning ? h("div", { class: "warn-banner" }, h("strong", {}, "Simulated run. "), d.warning) : null,
    h("div", { class: "grid2" },
      kv([
        ["Backend", d.backend], ["IBM job ID", d.job_id || "– (not a hardware job)"], ["Created", d.created],
        ["Raw bits", `${d.raw_bits.toLocaleString()} (${d.qubits.length} qubits × ${d.shots.toLocaleString()} shots)`],
        ["Min-entropy h", `${d.h_min.toFixed(4)} bits/bit (worst qubit ${d.worst_qubit}, SP 800-90B MCV, 99%)`],
        ["Extractor", `${d.extractor.type}: ${d.extractor.blocks} × ${d.extractor.block_in.toLocaleString()} → ${d.extractor.block_out.toLocaleString()} bits`],
        ["Output", `${d.extracted_bits.toLocaleString()} bits at ε = 2^-${d.eps_bits}`],
        ["Key fingerprint", d.key_fingerprint_sha256],
      ]),
      kv([
        ["Extracted bits", tests("extracted")], ["os.urandom", tests("os_urandom")],
        ["Correlations", `max |r| ${d.correlation_max_abs_offdiag.toFixed(4)}; ${d.correlation_outside_band} pairs outside ±${band.toFixed(3)}`],
        ["Autocorrelation", `${d.autocorr_outside_band} qubits outside ±${band.toFixed(3)} (expect ~5% by chance)`],
        ["Note", d.tests.note],
      ])),
    h("div", { class: "charts" },
      chartBox("Readout error per qubit", "Measured in the same job from the |0⟩ and |1⟩ calibration circuits", legend2,
        barChart({ labels: q, series: [{ name: "P(1|0)", cls: "bar1", values: d.readout_error_p01 }, { name: "P(0|1)", cls: "bar2", values: d.readout_error_p10 }], yMin: 0, yMax: errMax, title: "Readout error per qubit" })),
      chartBox("Raw bias per qubit", "Mean of raw bits − 0.5 (negative = leans to 0, from |1⟩ relaxing during readout)", null,
        barChart({ labels: q, series: [{ name: "bias", cls: "bar1", values: d.bias }], refs: [{ v: band / 2, label: "" }], yMin: -absMax(d.bias, 0.02), yMax: absMax(d.bias, 0.02), title: "Bias per qubit" })),
      chartBox("Min-entropy per qubit", "The smallest value becomes h for extraction (conservative)", null,
        barChart({ labels: q, series: [{ name: "h", cls: "bar1", values: d.min_entropy_per_qubit }], refs: [{ v: d.h_min, label: `h = ${d.h_min.toFixed(3)}` }],
          yMin: Math.max(0, Math.min(...d.min_entropy_per_qubit) - 0.05), yMax: 1, title: "Min-entropy per qubit" })),
      chartBox("Lag-1 autocorrelation (shot to shot)", `Dashed lines: ±${band.toFixed(3)}, what chance alone gives`, null,
        barChart({ labels: q, series: [{ name: "r", cls: "bar1", values: d.autocorr_lag1 }], refs: [{ v: band, label: `+${band.toFixed(3)}` }, { v: -band, label: `−${band.toFixed(3)}` }],
          yMin: -absMax(d.autocorr_lag1, band * 1.5), yMax: absMax(d.autocorr_lag1, band * 1.5), title: "Autocorrelation" })),
      chartBox("Qubit-to-qubit correlation", `Diverging scale saturates at ±${Math.max(band * 3, 0.05).toFixed(3)}; gray = no correlation`,
        h("div", { class: "legend" }, h("span", {}, h("i", { class: "swneg" }), "negative"), h("span", {}, h("i", { class: "swmid" }), "≈ 0"), h("span", {}, h("i", { class: "swpos" }), "positive")),
        heatmap(d.correlation_matrix, d.qubits, band))),
    h("h3", {}, "What is and isn't guaranteed"),
    h("div", { class: "scroll" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, h("th", {}, "Claim"), h("th", {}, "Status"), h("th", {}, "Why"))),
      h("tbody", {}, d.guarantees.map((g) => h("tr", {}, h("td", {}, g.claim), h("td", {}, g.status), h("td", {}, g.why)))))),
  );
}

async function loadExtras() {
  const [rw, bm, sh] = await Promise.all([api("/api/realworld"), api("/api/benchmark"), api("/api/shor")]);
  if (rw) {
    $("#realworld").replaceChildren(
      h("div", { class: "scroll" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, h("th", {}, "Group"), h("th", { class: "num" }, "Reachable"), h("th", { class: "num" }, "PQ ready"), h("th", { class: "num" }, "Share"), h("th", { class: "num" }, "Failed"))),
        h("tbody", {}, rw.groups.map((g) => h("tr", {}, h("td", {}, g.label), h("td", { class: "num" }, g.reachable), h("td", { class: "num" }, g.pq_ready), h("td", { class: "num" }, `${g.pq_pct}%`), h("td", { class: "num" }, g.failed_to_connect)))))),
      h("p", { class: "muted small" }, `${rw.method}. Tranco list ${rw.list_id}, seed ${rw.seed}, ${rw.duration_s} s.`));
  }
  if (bm) {
    const sz = bm.sizes;
    $("#benchmark").replaceChildren(
      h("div", { class: "scroll" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, h("th", {}, "Setting"), h("th", { class: "num" }, "n"), h("th", { class: "num" }, "p50 ms"), h("th", { class: "num" }, "p99 ms"), h("th", { class: "num" }, "Failures"))),
        h("tbody", {}, bm.results.map((r) => h("tr", {}, h("td", {}, r.label), h("td", { class: "num" }, r.n), h("td", { class: "num" }, fmt(r.p50_ms, 3)), h("td", { class: "num" }, fmt(r.p99_ms, 3)), h("td", { class: "num" }, r.failures)))))),
      h("p", { class: "small" }, `Key shares — client: ${sz.client_key_share.pq} vs ${sz.client_key_share.classical} bytes; server: ${sz.server_key_share.pq} vs ${sz.server_key_share.classical} bytes; +${sz.extra_bytes_per_handshake} bytes per handshake.`),
      h("p", { class: "small" }, sz.packet_split), h("p", { class: "muted small" }, bm.caveat));
  }
  if (sh) {
    $("#shor").replaceChildren(
      h("p", {}, `Order finding for N = ${sh.N}, a = ${sh.a} on ${sh.backend}${sh.job_id ? ` (job ${sh.job_id})` : ""}: period r = ${sh.period ?? "not found"}, factors ${sh.factors.length ? sh.factors.join(" × ") : "–"}.`),
      h("div", { class: "scroll" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, h("th", {}, "Measured"), h("th", { class: "num" }, "Share"), h("th", {}, "Phase"), h("th", { class: "num" }, "r guess"))),
        h("tbody", {}, sh.outcomes.slice(0, 8).map((o) => h("tr", {}, h("td", { class: "mono" }, o.bits), h("td", { class: "num" }, `${(o.share * 100).toFixed(1)}%`), h("td", {}, o.fraction), h("td", { class: "num" }, o.r)))))),
      h("p", { class: "muted small" }, sh.disclaimer));
  }
}

// ----------------------------------------------------------------- run --
let caps = null;
let jobState = {};          // id -> last seen status, to refresh results when a job finishes
let view = { id: null, since: 0, timer: null };

function option(value, label, ok, detail) {
  return h("option", { value, disabled: !ok }, ok ? label : `${label} — ${detail}`);
}

async function loadCapabilities() {
  caps = await api("/api/capabilities");
  if (!caps) return;
  $("#run-readonly").classList.toggle("hidden", caps.jobs);
  document.querySelectorAll("#run button, #run select, #run textarea, #run input").forEach((el) => {
    if (!caps.jobs && !el.closest("#job-view")) el.disabled = true;
  });
  if (!caps.jobs) return;
  const p = caps.planners;
  const sel = $("#planner");
  sel.replaceChildren(
    option("local", "Gemma 4 / local model", p.local.ok, p.local.detail),
    option("rules", "Rules (deterministic, no AI)", true, ""),
    option("claude", "Claude", p.claude.ok, p.claude.detail));
  sel.value = p.local.ok ? "local" : "rules";
  if (p.local.ok) sel.options[0].title = p.local.detail;
  const managed = caps.services.filter((s) => s.managed);
  $("#svc-list").replaceChildren(...(managed.length ? managed.map((s) => h("label", { class: "check" },
    h("input", { type: "checkbox", value: s.name, checked: true }), ` ${s.name} `, h("span", { class: "muted small mono" }, s.endpoint)))
    : [h("p", { class: "muted small" }, caps.inventory ? "The inventory has no managed services." : "Start the dashboard with --inventory FILE to migrate servers you manage.")]));
  $("#f-migrate button[type=submit]").disabled = !managed.length;
  $("#scan-inventory").disabled = !caps.inventory;
  $("#scan-inventory").title = caps.inventory ? "" : "Start the dashboard with --inventory FILE";
  const q = $("#ent-source"), sb = $("#shor-backend");
  q.options[1].disabled = sb.options[1].disabled = !caps.ibm.ok;
  if (!caps.ibm.ok) { q.options[1].textContent = `IBM quantum hardware — ${caps.ibm.detail}`; sb.options[1].textContent = q.options[1].textContent; }
  $("#f-quantum button[type=submit]").disabled = $("#run-shor").disabled = !caps.quantum.ok;
  if (!caps.quantum.ok) $("#f-quantum button[type=submit]").title = caps.quantum.detail;
}

async function runJob(payload, button) {
  if (button) button.disabled = true;
  try {
    const job = await api("/api/jobs", { method: "POST", body: JSON.stringify(payload) });
    await loadJobs();
    openJob(job.id);
  } catch (e) {
    if (e instanceof AuthError) return signOut("Your token was rejected.");
    alert(`Could not start: ${e.message}`);
  } finally {
    if (button) button.disabled = false;
  }
}

const JOB_STATUS = { running: ["warning", "running"], succeeded: ["good", "done"], failed: ["critical", "failed"], cancelled: ["muted", "cancelled"] };
function duration(j) {
  const s = Math.round(((j.finished || Date.now() / 1000) - j.created));
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`;
}

async function loadJobs() {
  const list = (await api("/api/jobs")) || [];
  let finishedNow = false;
  for (const j of list) {
    if (jobState[j.id] === "running" && j.status !== "running") finishedNow = true;
    jobState[j.id] = j.status;
  }
  $("#no-jobs").classList.toggle("hidden", list.length > 0);
  $("#jobs tbody").replaceChildren(...list.map((j) => {
    const [k, l] = JOB_STATUS[j.status] || ["muted", j.status];
    return h("tr", {},
      h("td", {}, j.label), h("td", {}, j.started_by), h("td", {}, badge(k, l)), h("td", { class: "small" }, duration(j)),
      h("td", { class: "small mono clip" }, j.last_line),
      h("td", {}, h("button", { type: "button", class: "ghost small-btn", onclick: () => openJob(j.id) }, "Output")));
  }));
  if (finishedNow) refreshResults();
}

function refreshResults() {
  guarded(() => loadOverview(false)); guarded(loadEntropy); guarded(loadExtras); guarded(loadAudit); guarded(loadApprovals);
}

function openJob(id) {
  if (view.timer) clearInterval(view.timer);
  view = { id, since: 0, timer: null };
  $("#job-log").textContent = "";
  $("#job-view").classList.remove("hidden");
  pollJob();
  view.timer = setInterval(pollJob, 1000);
  $("#job-view").scrollIntoView({ block: "nearest" });
}

async function pollJob() {
  const id = view.id;
  if (!id) return;
  let d;
  try { d = await api(`/api/jobs/${encodeURIComponent(id)}?since=${view.since}`); } catch (e) { return; }
  if (!d || view.id !== id) return;
  const log = $("#job-log");
  const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  if (d.log.length) log.append(document.createTextNode(d.log.join("\n") + "\n"));
  view.since = d.since + d.log.length;
  if (atBottom) log.scrollTop = log.scrollHeight;
  const [, l] = JOB_STATUS[d.status] || ["", d.status];
  $("#job-title").textContent = `${d.label} — ${l}${d.exit_code !== null && d.status !== "running" ? ` (exit ${d.exit_code})` : ""}`;
  $("#job-cancel").disabled = d.status !== "running";
  if (d.status !== "running" && view.timer) { clearInterval(view.timer); view.timer = null; loadJobs(); }
}

function wireRun() {
  $("#f-scan").addEventListener("submit", (e) => {
    e.preventDefault();
    const targets = $("#targets").value.trim();
    if (!targets) { alert("Enter at least one server, one per line."); return; }
    runJob({ kind: "scan", targets }, e.submitter);
  });
  $("#scan-inventory").addEventListener("click", (e) => runJob({ kind: "scan" }, e.currentTarget));
  $("#f-migrate").addEventListener("submit", (e) => {
    e.preventDefault();
    const boxes = [...document.querySelectorAll("#svc-list input[type=checkbox]")];
    const chosen = boxes.filter((b) => b.checked).map((b) => b.value);
    if (!chosen.length) { alert("Pick at least one service."); return; }
    runJob({ kind: "migrate", planner: $("#planner").value, services: chosen.length === boxes.length ? [] : chosen }, e.submitter);
  });
  $("#f-quantum").addEventListener("submit", (e) => { e.preventDefault(); runJob({ kind: "entropy", source: $("#ent-source").value }, e.submitter); });
  $("#run-shor").addEventListener("click", (e) => runJob({ kind: "shor", backend: $("#shor-backend").value }, e.currentTarget));
  $("#f-bench").addEventListener("submit", (e) => {
    e.preventDefault();
    const url = $("#bench-url").value.trim();
    if (!url) { alert("Enter an https:// URL of a server to benchmark."); return; }
    runJob({ kind: "benchmark", url, n: Number($("#bench-n").value) || 200, method: $("#bench-method").value }, e.submitter);
  });
  $("#run-realworld").addEventListener("click", (e) => runJob({ kind: "realworld" }, e.currentTarget));
  $("#job-cancel").addEventListener("click", async () => {
    if (!view.id || !confirm("Cancel this job? A migration rolls back anything not yet verified.")) return;
    try { await api(`/api/jobs/${encodeURIComponent(view.id)}/cancel`, { method: "POST" }); } catch (e) { alert(e.message); }
  });
  $("#job-close").addEventListener("click", () => {
    if (view.timer) clearInterval(view.timer);
    view = { id: null, since: 0, timer: null };
    $("#job-view").classList.add("hidden");
  });
}

// ---------------------------------------------------------------- tabs --
// One section at a time. Hashes from links inside the page (#approvals, #risk, ...) pick the right tab.
const TAB_OF = {
  "": "overview", overview: "overview", top: "overview", risk: "overview",
  run: "run", approvals: "approvals", quantum: "quantum", "entropy-section": "quantum", "shor-section": "quantum",
  measure: "measure", "measure-section": "measure", audit: "audit", "audit-section": "audit",
};
function showTab() {
  const key = location.hash.replace(/^#/, "");
  const tab = TAB_OF[key] || "overview";
  document.querySelectorAll("[data-tab]").forEach((el) => el.classList.toggle("tab-hidden", el.dataset.tab !== tab));
  document.querySelectorAll("[data-tab-link]").forEach((a) => {
    if (a.dataset.tabLink === tab) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  const target = key && document.getElementById(key);
  if (target && target.dataset.tab === undefined) target.scrollIntoView({ block: "start" });
  else window.scrollTo({ top: 0 });
}

// ---------------------------------------------------------------- main --
async function guarded(fn) {
  try { await fn(); } catch (e) {
    if (e instanceof AuthError) return signOut("Your token was rejected.");
    console.error(e);
  }
}

function signOut(msg) {
  timers.forEach(clearInterval); timers = [];
  if (view.timer) clearInterval(view.timer);
  view = { id: null, since: 0, timer: null };
  token = null;
  try { sessionStorage.removeItem(TOKEN_KEY); } catch (_) { /* ignore */ }
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  document.body.classList.add("signed-out");
  $("#login-error").textContent = msg || "";
  $("#who").textContent = "";
}

async function start() {
  try {
    const me = await api("/api/me");
    $("#who").textContent = me.identity;
  } catch (e) {
    return signOut(e instanceof AuthError ? "Invalid token." : `Cannot reach AegisQ: ${e.message}`);
  }
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  document.body.classList.remove("signed-out");
  await guarded(() => loadOverview(true));
  await Promise.all([guarded(loadCapabilities), guarded(loadJobs), guarded(loadApprovals), guarded(loadAudit), guarded(loadEntropy), guarded(loadExtras)]);
  timers.push(setInterval(() => guarded(loadJobs), 3000));
  timers.push(setInterval(() => guarded(loadApprovals), 3000));
  timers.push(setInterval(() => guarded(loadAudit), 5000));
  timers.push(setInterval(() => guarded(() => loadOverview(false)), 15000));
}

document.addEventListener("DOMContentLoaded", () => {
  window.addEventListener("hashchange", showTab);
  showTab();
  $("#z").addEventListener("input", renderRanking);
  $("#login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    token = $("#token").value.trim();
    try { sessionStorage.setItem(TOKEN_KEY, token); } catch (_) { /* private mode */ }
    start();
  });
  $("#logout").addEventListener("click", () => signOut(""));
  $("#cbom-link").addEventListener("click", (e) => { e.preventDefault(); download("/api/cbom", "cbom.json"); });
  $("#report-link").addEventListener("click", (e) => { e.preventDefault(); download(`/api/report.html?z=${$("#z").value}`, "aegisq-report.html"); });
  $("#rescan").addEventListener("click", (e) => runJob({ kind: "scan" }, e.currentTarget));
  wireRun();
  if (token) start(); else signOut("");
});
