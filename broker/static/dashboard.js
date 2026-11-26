// Broker dashboard: polls /api/state and /api/events and draws them. Read-only.
// Every string from the broker is written with textContent (never innerHTML). The read
// token lives only in the `token` variable: not in the URL, not in storage.
"use strict";

const POLL_MS = 1500;
const FEED_ROWS = 200;
const BANDS = [[0.8, "0.80"], [0.6, "0.60"], [0.4, "0.40"]];  // Active / Suspicious / Restricted edges
const DEFENCE_KINDS = ["quarantine", "release", "revoke", "restore"];
const SVG_NS = "http://www.w3.org/2000/svg";

let token = "";
let timer = null;
let seenFeed = new Set();       // feed rows already shown, so only new rows are highlighted
let lastAgents = new Map();     // agent -> row signature, so only changed rows are highlighted
let lastState = null;

const $ = (id) => document.getElementById(id);

// --- small DOM helpers ---------------------------------------------------------------------

function cell(text, cls) {
  const td = document.createElement("td");
  td.textContent = text === null || text === undefined ? "" : String(text);
  if (cls) td.className = cls;
  return td;
}

function decisionCell(label, cls) {
  const td = document.createElement("td");
  td.className = cls;
  const mark = document.createElement("span");
  mark.className = "mark";
  td.append(mark, document.createTextNode(label));
  return td;
}

function yesNo(value) {
  return cell(value ? "yes" : "no", value ? "word yes" : "word");
}

function fill(tbodyId, emptyId, rows) {
  $(tbodyId).replaceChildren(...rows);
  $(emptyId).hidden = rows.length > 0;
}

function svg(tag, attrs, text) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
}

const clock = (iso) => (typeof iso === "string" ? iso.slice(11, 19) : "");   // HH:MM:SS (UTC)

// HH:MM:SS plus the milliseconds in their own span, which CSS hides on narrow screens.
function timeCell(iso) {
  const td = cell(clock(iso));
  if (typeof iso === "string") {
    const ms = document.createElement("span");
    ms.className = "ms";
    ms.textContent = iso.slice(19, 23);
    td.append(ms);
  }
  return td;
}

// --- connection state ------------------------------------------------------------------------

function setConn(state, text) {
  $("conn").dataset.state = state;
  $("conn-text").textContent = text;
}

async function getJson(path) {
  const r = await fetch(path, { headers: { "X-Read-Token": token }, cache: "no-store" });
  if (r.status === 401) throw new Error("bad-token");
  if (r.status === 403) throw new Error("disabled");
  if (!r.ok) throw new Error("offline");
  return r.json();
}

async function poll() {
  timer = null;
  try {
    const [state, events] = await Promise.all([getJson("/api/state"), getJson("/api/events?limit=1000")]);
    render(state, events.events || []);
    setConn("ok", "Connected");
    $("updated").textContent = new Date().toISOString().slice(11, 19) + " UTC";
  } catch (err) {
    if (err.message === "bad-token") setConn("bad-token", "Wrong token");
    else if (err.message === "disabled") setConn("bad-token", "Read routes disabled (BROKER_READ_TOKEN not set)");
    else setConn("offline", "No connection");
  }
  schedule();
}

// Poll only while the tab is visible and a token has been entered.
function schedule() {
  if (timer === null && token && !document.hidden) timer = setTimeout(poll, POLL_MS);
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden && timer !== null) { clearTimeout(timer); timer = null; }
  else schedule();
});

// --- panels ----------------------------------------------------------------------------------

function render(state, events) {
  lastState = state;
  renderAgents(state.agents || []);
  renderCounters(state.counters || {});
  renderPending(state.pending_approvals || []);
  renderFeed(events);
  drawChart();
}

function renderAgents(agents) {
  const next = new Map();
  const rows = agents.map((a) => {
    const sig = [a.role, a.T, a.trust_state, a.quarantined, a.epoch, a.revoked].join("|");
    next.set(a.agent, sig);
    const tr = document.createElement("tr");
    if (lastAgents.size && lastAgents.get(a.agent) !== sig) tr.className = "fresh";
    tr.append(cell(a.agent), cell(a.role ?? "-"), cell(Number(a.T).toFixed(2), "num"),
      cell(a.trust_state, "word"), yesNo(a.quarantined),
      cell(a.epoch ?? "-", "num"), yesNo(a.revoked));
    return tr;
  });
  lastAgents = next;
  fill("agents", "agents-empty", rows);
}

function renderCounters(c) {
  // Rows of four: defence events, approvals, then message totals.
  const a = c.approvals || {};
  const totals = [
    ...DEFENCE_KINDS.map((k) => [k, (c.defence || {})[k]]),
    ["pending", a.pending], ["approved", a.approved], ["rejected", a.rejected], ["timeout", a.expired],
    ["messages", c.messages], ["forwarded", c.forwarded],
  ];
  $("totals").replaceChildren(...totals.map(([label, n]) => {
    const div = document.createElement("div");
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = label;
    dd.textContent = String(n ?? 0);
    div.append(dt, dd);
    return div;
  }));
  const reasons = Object.entries(c.reason_codes || {}).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  fill("reasons", "reasons-empty", reasons.map(([code, n]) => {
    const tr = document.createElement("tr");
    tr.append(cell(code), cell(n, "num"));
    return tr;
  }));
}

function renderPending(items) {
  fill("pending", "pending-empty", items.map((p) => {
    const tr = document.createElement("tr");
    tr.append(cell(clock(p.created_at)), cell(p.sender), cell(p.receiver), cell(p.action), cell(p.policy_reason));
    return tr;
  }));
}

// Decisions and the defence events that matter on screen (quarantine, release, revoke,
// restore), newest first as /api/events sends them.
function renderFeed(events) {
  const shown = events.filter((e) => e.kind === "decision" || DEFENCE_KINDS.includes(e.kind)).slice(0, FEED_ROWS);
  const first = seenFeed.size === 0;
  const keys = new Set();
  const rows = shown.map((e) => {
    const key = e.entry_hash || `${e.kind}|${e.ts}|${e.msg_id || e.agent}`;
    keys.add(key);
    const tr = document.createElement("tr");
    if (!first && !seenFeed.has(key)) tr.className = "fresh";
    if (e.kind === "decision") {
      tr.append(timeCell(e.ts), cell(e.sender), cell(e.receiver), cell(e.action),
        decisionCell(e.decision, `d-${e.decision}`), cell(e.reason_code), yesNo(e.forwarded),
        cell((e.redacted_fields || []).join(", "), "wrap"));
    } else {
      // A defence event: the agent it concerns, who did it, and the event kind.
      tr.append(timeCell(e.ts), cell(e.agent), cell(e.by ? `by ${e.by}` : ""), cell(""),
        decisionCell(e.kind, "d-event"), cell(e.reason_code ?? ""), cell(""), cell(""));
    }
    return tr;
  });
  seenFeed = keys;
  fill("feed", "feed-empty", rows);
}

// --- trust chart -------------------------------------------------------------------------------
// One step line per agent (T changes in steps, at the messages the broker scored), from the
// broker's bounded history, extended to now with the current T. Band edges are dashed.

function drawChart() {
  const el = $("chart");
  const state = lastState;
  const history = (state && state.trust_history) || {};
  const names = Object.keys(history);
  $("chart-empty").hidden = names.length > 0;
  el.hidden = names.length === 0;
  if (!names.length) { el.replaceChildren(); return; }

  const w = el.clientWidth || 800;
  const h = el.clientHeight || 300;
  const pad = { l: 44, r: 190, t: 8, b: 24 };
  el.setAttribute("viewBox", `0 0 ${w} ${h}`);

  // The right edge is now; the chart shows at least the last 10 s.
  const now = Date.now();
  const t0 = Math.min(now - 10000, ...names.map((n) => Date.parse(history[n][0][0])));
  const span = now - t0;
  const x = (t) => pad.l + ((t - t0) / span) * (w - pad.l - pad.r);
  const y = (T) => pad.t + (1 - T) * (h - pad.t - pad.b);

  const parts = [svg("line", { class: "axis", x1: pad.l, x2: pad.l, y1: y(1), y2: y(0) }),
    svg("line", { class: "axis", x1: pad.l, x2: w - pad.r, y1: y(0), y2: y(0) })];
  for (const [T, label] of [[1, "1.00"], ...BANDS, [0, "0.00"]]) {
    if (T > 0 && T < 1) parts.push(svg("line", { class: "band", x1: pad.l, x2: w - pad.r, y1: y(T), y2: y(T) }));
    parts.push(svg("text", { x: pad.l - 6, y: y(T) + 5, "text-anchor": "end" }, label));
  }
  // Three time labels along the bottom (UTC).
  for (const f of [0, 0.5, 1]) {
    const t = t0 + f * span;
    parts.push(svg("text", { x: x(t), y: h - 4, "text-anchor": f === 0 ? "start" : f === 1 ? "end" : "middle" },
      new Date(t).toISOString().slice(11, 19)));
  }

  const current = new Map(((state && state.agents) || []).map((a) => [a.agent, a]));
  const labels = [];
  for (const name of names) {
    const pts = history[name].map(([ts, T]) => [Date.parse(ts), T]);
    const nowT = current.has(name) ? Number(current.get(name).T) : pts[pts.length - 1][1];
    let d = `M${x(pts[0][0]).toFixed(1)},${y(pts[0][1]).toFixed(1)}`;
    for (const [t, T] of pts.slice(1)) d += `H${x(t).toFixed(1)}V${y(T).toFixed(1)}`;
    d += `H${x(now).toFixed(1)}V${y(nowT).toFixed(1)}`;
    const moved = pts.some(([, T]) => T < 0.995) || nowT < 0.995;
    parts.push(svg("path", { class: moved ? "line moved" : "line", d }));
    labels.push({ name, T: nowT, y: y(nowT), moved });
  }
  // Labels at the right end, pushed apart so agents with the same T stay readable.
  labels.sort((a, b) => a.y - b.y);
  let prev = -Infinity;
  for (const l of labels) {
    const ly = Math.max(l.y, prev + 17);
    prev = ly;
    parts.push(svg("text", { class: l.moved ? "agent moved" : "agent", x: x(now) + 8, y: ly + 5 },
      `${l.name} ${l.T.toFixed(2)}`));
  }
  el.replaceChildren(...parts);
}

window.addEventListener("resize", drawChart);

// --- start -------------------------------------------------------------------------------------

$("addr").textContent = location.host;
$("token-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  token = $("token").value.trim();
  $("token").value = "";                       // the token stays in memory only
  seenFeed = new Set();
  lastAgents = new Map();
  if (timer !== null) { clearTimeout(timer); timer = null; }
  if (token) { setConn("none", "Connecting"); poll(); }
  else setConn("none", "Not connected");
});
