"use strict";

const $ = (id) => document.getElementById(id);
const REASONS = {
  rule1: "1 — поисковый бот без DNS",
  rule3: "3 — невозможный UA",
  rule5: "5 — равномерные интервалы",
  rule6: "6 — подсеть в окне",
  "model:autoencoder": "автоэнкодер",
  "model:iforest": "Isolation Forest",
};

let analysis = null;
let sortKey = "ae";
let sortDesc = true;

// ---------------------------------------------------------------- API

async function checkHealth() {
  try {
    const r = await fetch("/api/health");
    const h = await r.json();
    $("health").textContent = `API ${h.version} · модели: ${h.models.join(", ") || "нет"}`;
  } catch (e) {
    $("health").textContent = "API недоступен";
  }
}

async function analyze(ev) {
  ev.preventDefault();
  const file = $("file").files[0];
  if (!file) return;
  const params = new URLSearchParams({
    decision_model: $("decision_model").value,
    dns_offline: $("dns_offline").checked,
    cv_threshold: $("cv_threshold").value,
    subnet_window: $("subnet_window").value,
    subnet_threshold: $("subnet_threshold").value,
    min_requests: $("min_requests").value,
  });
  const body = new FormData();
  body.append("file", file);
  $("submit").disabled = true;
  $("status").textContent = `Загрузка и анализ ${file.name} (${(file.size / 1e6).toFixed(1)} МБ)…`;
  try {
    const r = await fetch(`/api/analyze?${params}`, { method: "POST", body });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(typeof err.detail === "string" ? err.detail : r.statusText);
    }
    analysis = await r.json();
    $("status").textContent = "";
    history.replaceState(null, "", `#id=${analysis.id}`);
    render();
    loadHistory();
  } catch (e) {
    $("status").textContent = "Ошибка: " + e.message;
  } finally {
    $("submit").disabled = false;
  }
}

async function loadHistory() {
  try {
    const items = await fetch("/api/analyses?limit=20").then((r) => r.json());
    $("history").innerHTML = items.length
      ? items.map((a) => `<tr>
          <td>${a.created_at.replace("T", " ").slice(0, 19)}</td>
          <td>${escapeHtml(a.filename)}</td>
          <td>${a.decision_model || "—"}</td>
          <td class="num">${a.lines}</td>
          <td class="num">${a.unique_ips}</td>
          <td class="num">${a.suspicious_ips}</td>
          <td><a href="#" data-open="${a.id}">открыть</a> · <a href="#" data-del="${a.id}">удалить</a></td>
        </tr>`).join("")
      : '<tr><td colspan="7" class="muted">Пока нет сохранённых анализов</td></tr>';
  } catch (e) {
    $("history").innerHTML = '<tr><td colspan="7" class="muted">История недоступна</td></tr>';
  }
}

async function openAnalysis(id) {
  const r = await fetch(`/api/analyses/${id}`);
  if (!r.ok) return false;
  analysis = await r.json();
  if (analysis.decision_model) $("decision_model").value = analysis.decision_model;
  history.replaceState(null, "", `#id=${id}`);   // ссылку на результат можно переслать
  render();
  return true;
}

async function onHistoryClick(ev) {
  const open = ev.target.dataset.open, del = ev.target.dataset.del;
  if (!open && !del) return;
  ev.preventDefault();
  if (open) {
    if (await openAnalysis(open)) $("results").scrollIntoView({ behavior: "smooth" });
  } else if (confirm("Удалить анализ из истории?")) {
    await fetch(`/api/analyses/${del}`, { method: "DELETE" });
    if (analysis && analysis.id === del) $("results").hidden = true;
    loadHistory();
  }
}

// ---------------------------------------------------------------- отрисовка

function render() {
  const s = analysis.summary;
  $("results").hidden = false;
  $("download").href = `/api/analyses/${analysis.id}/download`;
  const stats = [
    ["Строк", s.lines],
    ["Уникальных IP", s.unique_ips],
    ["Заявленных поисковиков", s.claimed_search_bots],
    ["Подтверждено DNS", s.verified_search_bots_excluded],
    ["Подозрительных IP", s.suspicious_ips],
    ["Время, с", s.seconds_total],
  ];
  $("stats").innerHTML = stats
    .map(([k, v]) => `<div class="stat"><span class="muted">${k}</span><b>${v}</b></div>`)
    .join("");
  renderReasons(s.by_reason);
  renderScores();
  renderTable();
}

function barChart(items, width = 420) {
  const rowH = 24;
  const max = Math.max(1, ...items.map((i) => i.value));
  const labelW = 170;
  const h = items.length * rowH + 4;
  const bars = items.map((it, i) => {
    const w = ((width - labelW - 50) * it.value) / max;
    const y = i * rowH + 2;
    return `<text x="0" y="${y + 15}">${it.label}</text>
      <rect class="bar ${it.cls || ""}" x="${labelW}" y="${y + 3}" width="${w}" height="16" rx="2"></rect>
      <text x="${labelW + w + 6}" y="${y + 15}">${it.value}</text>`;
  });
  return `<svg viewBox="0 0 ${width} ${h}" width="100%" role="img">${bars.join("")}</svg>`;
}

function renderReasons(byReason) {
  const items = Object.entries(byReason)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ label: REASONS[k] || k, value: v, cls: k.startsWith("model") ? "bot" : "" }));
  $("chart-reasons").innerHTML = items.length ? barChart(items) : '<p class="muted">Ботов не найдено</p>';
}

function renderScores() {
  const model = $("decision_model").value;
  const thr = analysis.thresholds[model];
  const scores = analysis.ips.map((i) => i.scores[model]).filter((v) => v !== undefined);
  if (!scores.length || thr === undefined) {
    $("chart-scores").innerHTML = '<p class="muted">Модель не применялась</p>';
    return;
  }
  // логарифмическая шкала: оценки различаются на порядки
  const logs = scores.map((v) => Math.log10(Math.max(v, 1e-6)));
  const lo = Math.min(...logs), hi = Math.max(...logs);
  const nb = 30, step = (hi - lo) / nb || 1;
  const bins = new Array(nb).fill(0);
  logs.forEach((v) => bins[Math.min(nb - 1, Math.floor((v - lo) / step))]++);
  const W = 420, H = 180, pad = 24;
  const maxB = Math.max(...bins);
  const bw = (W - pad) / nb;
  const lthr = Math.log10(thr);
  const rects = bins.map((b, i) => {
    const h = maxB ? ((H - pad) * Math.sqrt(b)) / Math.sqrt(maxB) : 0;
    const cls = lo + i * step >= lthr ? "bar bot" : "bar";
    return `<rect class="${cls}" x="${pad + i * bw}" y="${H - pad - h}" width="${bw - 1}" height="${h}"></rect>`;
  });
  const xt = pad + ((lthr - lo) / (hi - lo || 1)) * (W - pad);
  // по флагу из API: оценки в ответе округлены, сравнение с порогом могло бы врать
  const above = analysis.ips.filter((i) => i.anomalous[model]).length;
  $("chart-scores").innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img">
      ${rects.join("")}
      <line class="thr" x1="${xt}" x2="${xt}" y1="0" y2="${H - pad}"></line>
      <text x="${Math.min(xt + 4, W - 120)}" y="12">порог ${thr.toFixed(3)}</text>
      <text x="${pad}" y="${H - 6}">10^${lo.toFixed(1)}</text>
      <text x="${W - 50}" y="${H - 6}">10^${hi.toFixed(1)}</text>
    </svg>
    <p class="muted">${scores.length} IP оценено, выше порога: ${above} (шкала высот — корень)</p>`;
}

function filtered() {
  const q = $("filter-ip").value.trim();
  const kind = $("filter-kind").value;
  const rule = $("filter-rule").value;
  return analysis.ips.filter((i) => {
    if (q && !i.ip.includes(q)) return false;
    if (kind === "bots" && !i.is_bot) return false;
    if (kind === "model" && !i.reason.startsWith("model")) return false;
    if (rule && !i.rules.includes(Number(rule))) return false;
    return true;
  });
}

function sortValue(i) {
  switch (sortKey) {
    case "ip": return i.ip;
    case "requests": return i.requests;
    case "ae": return i.scores.autoencoder ?? -1;
    case "if": return i.scores.iforest ?? -1;
  }
}

function fmtScore(i, name) {
  const v = i.scores[name];
  if (v === undefined) return "—";
  return `<span class="${i.anomalous[name] ? "hi" : ""}">${v.toFixed(3)}</span>`;
}

function escapeHtml(s) {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function renderTable() {
  const rows = filtered().sort((a, b) => {
    const x = sortValue(a), y = sortValue(b);
    return (x < y ? -1 : x > y ? 1 : 0) * (sortDesc ? -1 : 1);
  });
  const limit = 500;
  $("rows").innerHTML = rows.slice(0, limit).map((i) => {
    const tag = !i.is_bot ? '<span class="tag human">человек</span>'
      : i.reason.startsWith("model") ? '<span class="tag model">бот (модель)</span>'
      : '<span class="tag bot">бот</span>';
    return `<tr>
      <td>${i.ip}</td>
      <td class="num">${i.requests}</td>
      <td>${i.rules.join(", ") || "—"}</td>
      <td class="num">${fmtScore(i, "autoencoder")}</td>
      <td class="num">${fmtScore(i, "iforest")}</td>
      <td>${tag}</td>
      <td class="desc">${escapeHtml(i.description || i.top_features.join(", "))}</td>
    </tr>`;
  }).join("");
  $("table-info").textContent = rows.length > limit
    ? `Показано ${limit} из ${rows.length}` : `Строк: ${rows.length}`;
}

// ---------------------------------------------------------------- события

$("form").addEventListener("submit", analyze);
$("file").addEventListener("change", () => {
  const f = $("file").files[0];
  $("file-name").textContent = f ? f.name : "Выберите журнал Apache (combined)";
});
["filter-ip", "filter-kind", "filter-rule"].forEach((id) => $(id).addEventListener("input", renderTable));
$("decision_model").addEventListener("change", () => analysis && renderScores());
$("history").addEventListener("click", onHistoryClick);
document.querySelectorAll("th[data-sort]").forEach((th) =>
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    sortDesc = key === sortKey ? !sortDesc : true;
    sortKey = key;
    renderTable();
  })
);
checkHealth();
loadHistory();
const linked = location.hash.match(/^#id=(\w+)$/);
if (linked) openAnalysis(linked[1]);
