"use strict";

const live = document.querySelector("#live-region");
const connection = document.querySelector("#connection");
const refreshError = document.querySelector("#refresh-error");
const chartData = new WeakMap();
const requests = new WeakMap();
let busy = false;
let queued = false;
let timer;
let streamOnline = false;

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
  return `${element.closest(".server")?.dataset.agent || "global"}:${element.dataset.detail}`;
}

async function refresh() {
  if (document.hidden) return;
  if (busy) { queued = true; return; }
  busy = true;
  document.querySelector("#refresh").disabled = true;
  try {
    const response = await request("/api/v1/dashboard");
    const html = await response.text();
    // Keep local UI choices and unsaved settings independent of live telemetry.
    const open = new Set([...live.querySelectorAll("details[open]")].map(detailKey));
    const ranges = new Map([...live.querySelectorAll(".server")].map(server => [server.dataset.agent, server.querySelector(".history-range")?.value]));
    const focus = document.activeElement;
    const focusAgent = focus.closest?.(".server")?.dataset.agent;
    const focusDetail = focus.closest?.("details")?.dataset.detail;
    live.querySelectorAll(".chart").forEach(chart => requests.get(chart)?.abort());
    live.innerHTML = html;
    live.querySelectorAll("details").forEach(detail => { detail.open = open.has(detailKey(detail)); });
    live.querySelectorAll(".server").forEach(server => {
      const select = server.querySelector(".history-range");
      if (select && ranges.get(server.dataset.agent)) select.value = ranges.get(server.dataset.agent);
      if (server.dataset.agent === focusAgent) {
        if (focus.matches("select")) select?.focus({preventScroll: true});
        else if (focus.matches("summary")) [...server.querySelectorAll("details")].find(d => d.dataset.detail === focusDetail)?.querySelector("summary").focus({preventScroll: true});
      }
    });
    initCharts();
    refreshError.hidden = true;
    connection.textContent = streamOnline ? "Élő kapcsolat" : "Időzített frissítés";
    connection.className = `connection${streamOnline ? "" : " degraded"}`;
  } catch (error) {
    refreshError.textContent = "A frissítés sikertelen. Az utolsó betöltött adatok láthatók; automatikusan újrapróbáljuk.";
    refreshError.hidden = false;
    connection.textContent = "Frissítési hiba";
    connection.className = "connection failed";
  } finally {
    busy = false;
    document.querySelector("#refresh").disabled = false;
    if (queued) { queued = false; scheduleRefresh(); }
  }
}

function scheduleRefresh() {
  // A continuous stream must not postpone refreshing indefinitely.
  if (!timer) timer = setTimeout(() => { timer = null; refresh(); }, 750);
}

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
  const left = 34, right = width - 10, top = 10, bottom = height - 25;
  context.font = "10px system-ui";
  [0, 25, 50, 75, 100].forEach(value => {
    const y = bottom - (bottom - top) * value / 100;
    context.strokeStyle = "#e3eae5";
    context.fillStyle = "#66716c";
    context.beginPath(); context.moveTo(left, y); context.lineTo(right, y); context.stroke();
    context.fillText(`${value}%`, 0, y + 3);
  });
  const start = Date.parse(points[0].timestamp), end = Date.parse(points.at(-1).timestamp);
  for (const [field, color] of [["cpu_percent", "#15745c"], ["memory_percent", "#397ab3"]]) {
    context.strokeStyle = color; context.fillStyle = color; context.lineWidth = 2;
    context.beginPath();
    points.forEach((point, index) => {
      const x = start === end ? (left + right) / 2 : left + (right - left) * (Date.parse(point.timestamp) - start) / (end - start);
      const y = bottom - (bottom - top) * Math.max(0, Math.min(100, point[field])) / 100;
      if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
      if (points.length === 1) { context.arc(x, y, 3, 0, Math.PI * 2); context.fill(); }
    });
    context.stroke();
  }
  const format = value => new Date(value).toLocaleString("hu-HU", {month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"});
  context.fillStyle = "#66716c";
  context.fillText(format(start), left, height - 4);
  const label = format(end);
  if (width > 270) context.fillText(label, right - context.measureText(label).width, height - 4);
}

async function loadChart(container) {
  if (!container.closest("details").open) return;
  requests.get(container)?.abort();
  const controller = new AbortController();
  requests.set(container, controller);
  const range = container.closest(".server").querySelector(".history-range").value;
  try {
    const response = await request(`/api/v1/history?agent_id=${encodeURIComponent(container.dataset.agent)}&range=${encodeURIComponent(range)}`, {signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)])});
    const payload = await response.json();
    if (controller.signal.aborted || !container.isConnected) return;
    const points = (payload.points || []).filter(p => Number.isFinite(Date.parse(p.timestamp)) && Number.isFinite(p.cpu_percent) && Number.isFinite(p.memory_percent)).sort((a,b) => Date.parse(a.timestamp)-Date.parse(b.timestamp));
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

function initCharts() {
  live.querySelectorAll(".chart").forEach(container => {
    container.closest("details").addEventListener("toggle", () => loadChart(container));
    container.closest(".server").querySelector(".history-range").addEventListener("change", () => loadChart(container));
    loadChart(container);
  });
}

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

live.addEventListener("submit", async event => {
  if (!event.target.matches(".ack-form")) return;
  event.preventDefault();
  const form = event.target;
  form.querySelector("button").disabled = true;
  try { await request(form.action, {method:"POST", body:new URLSearchParams(new FormData(form))}); await refresh(); }
  catch (error) { refreshError.textContent = error.message; refreshError.hidden = false; form.querySelector("button").disabled = false; }
});

document.querySelector("#refresh").addEventListener("click", refresh);
window.addEventListener("resize", () => live.querySelectorAll(".chart").forEach(chart => { if (chartData.has(chart)) drawChart(chart, chartData.get(chart)); }));
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
window.addEventListener("online", refresh);
const events = new EventSource("/api/v1/events");
events.addEventListener("report", scheduleRefresh);
events.addEventListener("open", () => { streamOnline = true; refresh(); });
events.addEventListener("error", () => { streamOnline = false; connection.className = "connection degraded"; connection.textContent = "Újracsatlakozás…"; scheduleRefresh(); });
// Covers offline transitions, missed SSE messages and alerts changed by another session.
setInterval(refresh, 15000);
initCharts();
