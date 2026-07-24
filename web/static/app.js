const charts = document.querySelectorAll(".chart");

function drawChart(container, points) {
  const canvas = container.querySelector("canvas");
  const empty = container.querySelector(".chart-empty");
  if (!points.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  context.clearRect(0, 0, width, height);
  const padding = {left: 30, right: 8, top: 8, bottom: 20};
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  context.strokeStyle = "#334155";
  context.fillStyle = "#94a3b8";
  context.font = "10px system-ui";
  context.lineWidth = 1;
  [0, 25, 50, 75, 100].forEach(value => {
    const y = padding.top + plotHeight * (1 - value / 100);
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();
    context.fillText(`${value}%`, 1, y + 3);
  });
  const drawLine = (field, color) => {
    context.strokeStyle = color;
    context.lineWidth = 2;
    context.beginPath();
    points.forEach((point, index) => {
      const x = padding.left + plotWidth * (index / Math.max(points.length - 1, 1));
      const y = padding.top + plotHeight * (1 - Math.max(0, Math.min(100, point[field])) / 100);
      if (index === 0) context.moveTo(x, y);
      else context.lineTo(x, y);
    });
    context.stroke();
  };
  drawLine("cpu_percent", "#38bdf8");
  drawLine("memory_percent", "#a78bfa");
  const compact = width < 300;
  const firstDate = new Date(points[0].timestamp);
  const lastDate = new Date(points[points.length - 1].timestamp);
  const first = compact ? firstDate.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) : firstDate.toLocaleString();
  const last = compact ? lastDate.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) : lastDate.toLocaleString();
  context.fillStyle = "#94a3b8";
  context.fillText(first, padding.left, height - 3);
  const lastWidth = context.measureText(last).width;
  context.fillText(last, width - padding.right - lastWidth, height - 3);
}

async function loadChart(container) {
  const range = container.closest(".card").querySelector(".history-range").value;
  const agent = container.dataset.agent;
  try {
    const response = await fetch(`/api/v1/history?agent_id=${encodeURIComponent(agent)}&range=${encodeURIComponent(range)}`, {
      headers: {"Accept": "application/json"},
      cache: "no-store"
    });
    if (!response.ok) throw new Error(`history request failed: ${response.status}`);
    const payload = await response.json();
    drawChart(container, payload.points || []);
  } catch (error) {
    container.querySelector(".chart-empty").textContent = "History unavailable.";
    container.querySelector(".chart-empty").hidden = false;
  }
}

charts.forEach(container => {
  loadChart(container);
  container.closest(".card").querySelector(".history-range").addEventListener("change", () => loadChart(container));
});

let reloadTimer;
const events = new EventSource("/api/v1/events");
events.addEventListener("report", () => {
  clearTimeout(reloadTimer);
  reloadTimer = setTimeout(() => location.reload(), 750);
});
