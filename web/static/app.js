"use strict";

const live = document.querySelector("#live-region");
const connection = document.querySelector("#connection");
const connectionText = document.querySelector("#connection-text");
const refreshError = document.querySelector("#refresh-error");
const chartData = new WeakMap();
const requests = new WeakMap();
const STORAGE_KEY = "monitorozo.view";
const TIMELINE_PAGE = 20;
const SVG = "http://www.w3.org/2000/svg";
let busy = false;
let queued = false;
let timer;
let streamOnline = false;
let timelineExpanded = false;

// --- Selected machine, detail tab and timeline filter --------------------

const state = {selected: "", tab: "ov", filter: "all"};

function loadState() {
  const root = live.querySelector(".ov");
  state.selected = root?.dataset.selected || "";
  state.tab = root?.dataset.tab || "ov";
  state.filter = root?.dataset.filter || "all";
  const query = new URLSearchParams(location.search);
  if (query.has("agent") || query.has("tab") || query.has("tl")) return;
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    if (saved && typeof saved === "object") {
      for (const key of ["selected", "tab", "filter"]) if (typeof saved[key] === "string" && saved[key]) state[key] = saved[key];
    }
  } catch (error) { /* storage unavailable: keep the server-side state */ }
}

function stateQuery() {
  const query = new URLSearchParams();
  if (state.selected) query.set("agent", state.selected);
  if (state.tab !== "ov") query.set("tab", state.tab);
  if (state.filter !== "all") query.set("tl", state.filter);
  return query.toString();
}

function saveState() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch (error) { /* ignore */ }
  try {
    const query = stateQuery();
    history.replaceState(null, "", query ? `/?${query}${location.hash}` : `/${location.hash}`);
  } catch (error) { /* ignore */ }
}

function applyState() {
  const nodes = [...live.querySelectorAll(".node")];
  if (!nodes.some(node => node.dataset.agent === state.selected)) {
    state.selected = live.querySelector(".ov")?.dataset.selected || nodes[0]?.dataset.agent || "";
  }
  if (!["ov", "ep", "sec", "al"].includes(state.tab)) state.tab = "ov";
  const filters = [...live.querySelectorAll(".filters [data-filter]")];
  if (!filters.some(link => link.dataset.filter === state.filter)) state.filter = "all";
  nodes.forEach(node => node.classList.toggle("sel", node.dataset.agent === state.selected));
  live.querySelectorAll(".side").forEach(panel => {
    panel.hidden = panel.dataset.agent !== state.selected;
    panel.querySelectorAll(".stabs a").forEach(link => {
      const on = link.dataset.tab === state.tab;
      link.classList.toggle("on", on);
      if (on) link.setAttribute("aria-current", "true"); else link.removeAttribute("aria-current");
    });
    panel.querySelectorAll(".pane").forEach(pane => { pane.hidden = pane.dataset.pane !== state.tab; });
  });
  filters.forEach(link => {
    const on = link.dataset.filter === state.filter;
    link.classList.toggle("on", on);
    if (on) link.setAttribute("aria-current", "true"); else link.removeAttribute("aria-current");
  });
  applyTimeline();
  saveState();
  drawLinks();
  live.querySelectorAll(".side:not([hidden]) .chart").forEach(loadChart);
}

function matches(event) {
  if (state.filter === "all") return true;
  if (state.filter === "open" || state.filter === "done") return event.dataset.state === state.filter;
  return state.filter === `agent:${event.dataset.agent}`;
}

function applyTimeline() {
  let shown = 0, matching = 0;
  live.querySelectorAll(".tl-day").forEach(day => {
    let visible = 0;
    day.querySelectorAll(".ev").forEach(event => {
      const match = matches(event);
      if (match) matching++;
      const show = match && (timelineExpanded || shown < TIMELINE_PAGE);
      if (show) { shown++; visible++; }
      event.hidden = !show;
    });
    day.hidden = visible === 0;
  });
  const empty = live.querySelector(".tl-empty");
  if (empty) empty.hidden = matching > 0;
  const more = live.querySelector(".tl-more");
  if (more) {
    more.hidden = matching <= shown;
    more.textContent = `Továbbiak (${matching - shown})`;
  }
}

// --- Hub-to-machine connection lines -------------------------------------

function drawLinks() {
  live.querySelectorAll(".map").forEach(map => {
    const svg = map.querySelector(".links");
    const hub = map.querySelector(".hub");
    if (!svg || !hub) return;
    svg.replaceChildren();
    if (getComputedStyle(svg).display === "none") return;
    const box = map.getBoundingClientRect();
    const from = hub.getBoundingClientRect();
    svg.setAttribute("width", String(box.width));
    svg.setAttribute("height", String(box.height));
    const nodes = [...map.querySelectorAll(".node")];
    const firstRow = nodes.length ? nodes[0].getBoundingClientRect().top : 0;
    nodes.forEach(node => {
      const rect = node.getBoundingClientRect();
      if (Math.abs(rect.top - firstRow) > 2) return;
      const x1 = from.left + from.width / 2 - box.left, y1 = from.bottom - box.top;
      const x2 = rect.left + rect.width / 2 - box.left, y2 = rect.top - box.top;
      const d = `M${x1} ${y1} C ${x1} ${y1 + 26}, ${x2} ${y2 - 26}, ${x2} ${y2}`;
      const rail = document.createElementNS(SVG, "path");
      rail.setAttribute("class", "rail");
      rail.setAttribute("d", d);
      const flow = document.createElementNS(SVG, "path");
      flow.setAttribute("class", node.dataset.online === "1" ? "flow" : "flow bad");
      flow.setAttribute("d", d);
      svg.append(rail, flow);
    });
  });
}

// --- Data refresh --------------------------------------------------------

async function request(url, options = {}) {
  const response = await fetch(url, {cache: "no-store", signal: AbortSignal.timeout(35000), ...options});
  if (response.redirected && new URL(response.url).pathname === "/login") {
    events.close();
    location.assign("/login");
    throw new Error("A munkamenet lejárt.");
  }
  if (!response.ok) throw new Error((await response.text()).slice(0, 600));
  return response;
}

function detailKey(element) {
  return `${element.closest("[data-agent]")?.dataset.agent || "global"}:${element.dataset.detail}`;
}

function clockNow() {
  return new Date().toLocaleTimeString("hu-HU", {hour: "2-digit", minute: "2-digit"});
}

function setConnection(kind) {
  connection.className = `live${kind === "ok" ? "" : ` ${kind}`}`;
  if (kind === "failed") connectionText.textContent = "Frissítési hiba";
  else connectionText.textContent = `${kind === "ok" ? "Élő" : "Időzített"} · frissítve ${clockNow()}`;
}

async function refresh() {
  if (document.hidden) return;
  if (busy) { queued = true; return; }
  busy = true;
  try {
    const query = stateQuery();
    const response = await request(`/api/v1/dashboard${query ? `?${query}` : ""}`);
    const html = await response.text();
    // Keep local UI choices and unsaved name edits independent of live telemetry.
    const open = new Set([...live.querySelectorAll("details[open][data-detail]")].map(detailKey));
    const ranges = new Map([...live.querySelectorAll(".side")].map(panel => [panel.dataset.agent, panel.querySelector(".history-range")?.value]));
    const renaming = new Map([...live.querySelectorAll("details.rename[open]")].map(detail => [detail.id, [...detail.querySelectorAll("input:not([type=hidden])")].map(input => input.value)]));
    const focus = document.activeElement;
    const focusName = focus?.closest?.(".rename-form") ? focus.name : "";
    const focusID = focus?.closest?.("details.rename")?.id;
    const scrollers = new Map([...live.querySelectorAll(".side:not([hidden]) .pane:not([hidden])")].map(pane => [pane.closest(".side").dataset.agent, pane.scrollTop]));
    live.querySelectorAll(".chart").forEach(chart => requests.get(chart)?.abort());
    live.innerHTML = html;
    live.querySelectorAll("details[data-detail]").forEach(detail => { detail.open = open.has(detailKey(detail)); });
    live.querySelectorAll(".side").forEach(panel => {
      const select = panel.querySelector(".history-range");
      if (select && ranges.get(panel.dataset.agent)) select.value = ranges.get(panel.dataset.agent);
    });
    live.querySelectorAll("details.rename").forEach(detail => {
      const values = renaming.get(detail.id);
      detail.open = Boolean(values);
      if (values) detail.querySelectorAll("input:not([type=hidden])").forEach((input, index) => { input.value = values[index] ?? input.value; });
      if (detail.id === focusID && focusName) detail.querySelector(`input[name="${focusName}"]`)?.focus({preventScroll: true});
    });
    applyState();
    live.querySelectorAll(".side:not([hidden]) .pane:not([hidden])").forEach(pane => { pane.scrollTop = scrollers.get(pane.closest(".side").dataset.agent) || 0; });
    refreshError.hidden = true;
    setConnection(streamOnline ? "ok" : "degraded");
  } catch (error) {
    refreshError.textContent = "A frissítés sikertelen. Az utolsó betöltött adatok láthatók; automatikusan újrapróbáljuk.";
    refreshError.hidden = false;
    setConnection("failed");
  } finally {
    busy = false;
    if (queued) { queued = false; scheduleRefresh(); }
  }
}

function scheduleRefresh() {
  // A continuous stream must not postpone refreshing indefinitely.
  if (!timer) timer = setTimeout(() => { timer = null; refresh(); }, 750);
}

// --- Longer history chart (canvas, /api/v1/history) -----------------------

function drawChart(container, points) {
  const canvas = container.querySelector("canvas");
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (!width || !height) return;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  const empty = container.querySelector(".chart-empty");
  empty.textContent = "Nincs adat a kiválasztott időszakban.";
  empty.hidden = points.length > 0;
  if (!points.length) return;
  const left = 34, right = width - 6, top = 8, bottom = height - 22;
  context.font = "10px system-ui";
  [0, 25, 50, 75, 100].forEach(value => {
    const y = bottom - (bottom - top) * value / 100;
    context.strokeStyle = "#f1eee7";
    context.fillStyle = "#8b9199";
    context.beginPath(); context.moveTo(left, y); context.lineTo(right, y); context.stroke();
    context.fillText(`${value}%`, 0, y + 3);
  });
  const start = Date.parse(points[0].timestamp), end = Date.parse(points.at(-1).timestamp);
  for (const [field, color] of [["memory_percent", "#6a5cff"], ["cpu_percent", "#1fa36b"]]) {
    context.strokeStyle = color; context.fillStyle = color; context.lineWidth = 1.6;
    context.beginPath();
    points.forEach((point, index) => {
      const x = start === end ? (left + right) / 2 : left + (right - left) * (Date.parse(point.timestamp) - start) / (end - start);
      const y = bottom - (bottom - top) * Math.max(0, Math.min(100, point[field])) / 100;
      if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
      if (points.length === 1) { context.arc(x, y, 3, 0, Math.PI * 2); context.fill(); }
    });
    context.stroke();
  }
  const format = value => new Date(value).toLocaleString("hu-HU", {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"});
  context.fillStyle = "#8b9199";
  context.fillText(format(start), left, height - 4);
  const label = format(end);
  if (width > 270) context.fillText(label, right - context.measureText(label).width, height - 4);
}

async function loadChart(container) {
  if (!container.closest("details")?.open || container.closest("[hidden]")) return;
  requests.get(container)?.abort();
  const controller = new AbortController();
  requests.set(container, controller);
  const range = container.closest(".side").querySelector(".history-range").value;
  try {
    const response = await request(`/api/v1/history?agent_id=${encodeURIComponent(container.dataset.agent)}&range=${encodeURIComponent(range)}`, {signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)])});
    const payload = await response.json();
    if (controller.signal.aborted || !container.isConnected) return;
    const points = (payload.points || []).filter(p => Number.isFinite(Date.parse(p.timestamp)) && Number.isFinite(p.cpu_percent) && Number.isFinite(p.memory_percent)).sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    chartData.set(container, points);
    drawChart(container, points);
  } catch (error) {
    if (controller.signal.aborted || !container.isConnected) return;
    chartData.delete(container);
    const canvas = container.querySelector("canvas");
    canvas.getContext("2d").clearRect(0, 0, canvas.width, canvas.height);
    const empty = container.querySelector(".chart-empty");
    empty.textContent = "Az előzmények nem érhetők el. Próbáld újra a frissítést.";
    empty.hidden = false;
  }
}

// --- Interaction ---------------------------------------------------------

function selectAgent(agent, tab) {
  state.selected = agent;
  if (tab) state.tab = tab;
  applyState();
  const panel = live.querySelector(`.side:not([hidden])`);
  if (panel && window.matchMedia("(max-width: 1150px)").matches) {
    const top = panel.getBoundingClientRect().top;
    if (top > window.innerHeight * 0.6 || top < 0) panel.scrollIntoView({behavior: "smooth", block: "start"});
  }
}

function openRename(agent) {
  selectAgent(agent);
  const detail = live.querySelector(`.side[data-agent="${CSS.escape(agent)}"] details.rename`);
  if (!detail) return;
  detail.open = true;
  const input = detail.querySelector("input[name=display_name]");
  input?.focus({preventScroll: true});
  detail.closest(".side").scrollIntoView({behavior: "smooth", block: "nearest"});
}

live.addEventListener("click", event => {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const target = event.target;
  const rename = target.closest("[data-rename]");
  if (rename) { event.preventDefault(); openRename(rename.dataset.rename); return; }
  const cancel = target.closest(".rename-cancel");
  if (cancel) { event.preventDefault(); cancel.closest("details").open = false; return; }
  const tab = target.closest(".stabs a[data-tab]");
  if (tab) { event.preventDefault(); state.tab = tab.dataset.tab; applyState(); return; }
  const filter = target.closest(".filters a[data-filter]");
  if (filter) { event.preventDefault(); state.filter = filter.dataset.filter; timelineExpanded = false; applyState(); return; }
  if (target.closest(".tl-more")) { timelineExpanded = true; applyTimeline(); return; }
  const node = target.closest(".node");
  if (node && !target.closest("form, input, button, summary")) { event.preventDefault(); selectAgent(node.dataset.agent); }
});

live.addEventListener("toggle", event => {
  const chart = event.target.querySelector?.(":scope > .chart");
  if (chart) loadChart(chart);
}, true);

live.addEventListener("change", event => {
  if (event.target.matches(".history-range")) loadChart(event.target.closest(".side").querySelector(".chart"));
});

live.addEventListener("submit", async event => {
  const form = event.target;
  if (!form.matches(".ack-form, .rename-form")) return;
  event.preventDefault();
  const button = form.querySelector("button[type=submit], button");
  button.disabled = true;
  const result = form.querySelector(".form-result");
  try {
    const headers = form.matches(".rename-form") ? {Accept: "application/json"} : {};
    const response = await request(form.action, {method: "POST", body: new URLSearchParams(new FormData(form)), headers});
    if (form.matches(".rename-form")) {
      if (result) { result.className = "form-result"; result.textContent = (await response.json()).message; }
      form.closest("details").open = false;
    }
    await refresh();
  } catch (error) {
    if (result) { result.className = "form-result error"; result.textContent = error.message || "A mentés sikertelen."; }
    else { refreshError.textContent = error.message; refreshError.hidden = false; }
    button.disabled = false;
  }
});

document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => {
  document.querySelectorAll("[data-view]").forEach(tab => tab.removeAttribute("aria-current"));
  button.setAttribute("aria-current", "page");
  document.querySelector("#overview").hidden = button.dataset.view !== "overview";
  document.querySelector("#settings").hidden = button.dataset.view !== "settings";
  if (button.dataset.view === "overview") refresh();
}));

document.querySelector("#notification-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const result = document.querySelector("#email-result");
  const body = new URLSearchParams(new FormData(form));
  const url = event.submitter?.getAttribute("formaction") || form.action;
  form.querySelectorAll("button").forEach(button => { button.disabled = true; });
  result.className = "";
  result.textContent = url.endsWith("/test") ? "Tesztlevél küldése…" : "Mentés…";
  try {
    const response = await request(url, {method: "POST", body});
    result.textContent = (await response.json()).message;
  } catch (error) { result.className = "error"; result.textContent = error.message || "A kérés sikertelen."; }
  finally { form.querySelectorAll("button").forEach(button => { button.disabled = false; }); }
});

let resizeFrame = 0;
window.addEventListener("resize", () => {
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(() => {
    drawLinks();
    live.querySelectorAll(".chart").forEach(chart => { if (chartData.has(chart)) drawChart(chart, chartData.get(chart)); });
  });
});
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
window.addEventListener("online", refresh);
const events = new EventSource("/api/v1/events");
events.addEventListener("report", scheduleRefresh);
events.addEventListener("open", () => { streamOnline = true; refresh(); });
events.addEventListener("error", () => { streamOnline = false; setConnection("degraded"); connectionText.textContent = "Újracsatlakozás…"; scheduleRefresh(); });
// Covers offline transitions, missed SSE messages and alerts changed by another session.
setInterval(refresh, 15000);
if (document.fonts?.ready) document.fonts.ready.then(drawLinks).catch(() => {});

loadState();
applyState();
const renaming = live.querySelector("details.rename[open] input[name=display_name]");
if (renaming) renaming.focus({preventScroll: true});
