import { h, clear, debounce } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, download, qs } from "../lib/api.js";
import { card, pageHead, kpiCard, rangeControl, loading, errorState, toast, segmented, badge } from "../lib/ui.js";
import { timeSeries, hbars, COLORS, CATEGORY_COLORS } from "../lib/charts.js";
import { dataTable } from "../lib/table.js";
import { int, dateTime, ago, RANGE_LABELS } from "../lib/fmt.js";
import { sevBadge, statusBadge, healthRow, COMPONENT_NAMES, ipLink } from "./shared.js";

const LEVELS = ["LOW", "GUARDED", "ELEVATED", "HIGH", "CRITICAL"];

export default async function commandCenter(ctx) {
  let chart = null, timer = null, data = null;
  const range = rangeControl(() => load(), { key: "cc-range" });
  const updated = h("span", { class: "faint small" });

  const kpis = h("div", { class: "grid g-6" }, Array.from({ length: 6 }, () => h("div", { class: "card kpi" }, loading(3))));
  const threat = h("section", { class: "card", "aria-labelledby": "tl-title" }, h("div", { class: "card-body" }, loading(4)));
  const traffic = card({ title: "Traffic overview", sub: "Requests per interval by verdict. Toggle series in the legend.", body: loading(5) });
  const dist = card({ title: "Attack distribution", sub: "Flagged requests by primary attack category", body: loading(5) });
  const sources = card({ title: "Top attack sources", sub: "Select a source to see all of its traffic", body: loading(5) });
  const health = card({ title: "System health", sub: "Live checks; cloud services report their real state", body: loading(6),
    actions: [h("a", { class: "btn sm ghost", href: "#/health" }, "Details")] });

  // Recent incidents with filters, search, sort and pagination.
  const incFilter = { severity: "", status: "new,investigating", q: "" };
  const incTable = dataTable({
    caption: "Recent security incidents",
    columns: [
      { label: "Incident", render: (r) => h("a", { href: `#/investigate/incident/${r.id}`, class: "mono" }, r.ref) },
      { label: "Severity", sort: "severity", render: (r) => sevBadge(r.severity) },
      { label: "Type", render: (r) => r.category_label },
      { label: "Source IP", render: (r) => (r.client_ip ? ipLink(r.client_ip) : r.username || "—") },
      { label: "Endpoint", cls: "trunc", render: (r) => r.endpoint || "—" },
      { label: "Detected", sort: "last_seen", render: (r) => h("span", { class: "num", title: r.last_seen_at }, dateTime(r.last_seen_at)) },
      { label: "Status", sort: "status", render: (r) => statusBadge(r.status) },
      { label: "Assigned", render: (r) => r.assigned_to || h("span", { class: "faint" }, "Unassigned") },
    ],
    sort: "last_seen",
    fetch: ({ page, sort, order }) => api(`/api/incidents${qs({ page, page_size: 8, sort, order, ...incFilter })}`),
    onRow: (r) => ctx.navigate(`investigate/incident/${r.id}`),
    emptyTitle: "No incidents match", emptyText: "Change the filters, or run the simulation lab and tools/traffic.py to generate activity.",
  });
  const incSearch = h("input", { class: "input grow", type: "search", placeholder: "Search ID, IP, user, endpoint", "aria-label": "Search incidents",
    oninput: debounce((e) => { incFilter.q = e.target.value.trim(); incTable.reload(); }) });
  const incSev = h("select", { class: "select", "aria-label": "Severity filter", onchange: (e) => { incFilter.severity = e.target.value; incTable.reload(); } },
    [["", "All severities"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["informational", "Info"]]
      .map(([v, t]) => h("option", { value: v }, t)));
  const incStatus = segmented([{ value: "new,investigating", label: "Open" }, { value: "", label: "All" },
    { value: "resolved,false_positive", label: "Closed" }], incFilter.status, (v) => { incFilter.status = v; incTable.reload(); }, "Status");
  const incidents = h("section", { class: "card" },
    h("div", { class: "card-head" }, h("div", {}, h("h2", {}, "Recent security incidents"), h("p", { class: "sub" }, "Newest activity first")),
      h("a", { class: "btn sm ghost", href: "#/incidents" }, "All incidents")),
    h("div", { class: "filters" }, incStatus, incSev, incSearch),
    incTable.el);

  const exportBtn = ctx.can("reports:export") ? h("button", { class: "btn", type: "button", onclick: async () => {
    try { toast(`Downloaded ${await download(`/api/export/summary.md?hours=${range.get()}`, "summary.md")}`); }
    catch (err) { toast(err.message, "err"); }
  } }, icon("download"), "Export summary") : null;

  const el = h("div", { class: "page" },
    pageHead("Security Command Center", "Real-time overview of traffic, detections, incidents and the health of every layer.",
      [updated, range.el, exportBtn]),
    kpis,
    h("div", { class: "grid g-1-2 mt" }, threat, traffic),
    h("div", { class: "grid g-2 mt" }, dist, sources),
    h("div", { class: "grid g-2-1 mt" }, incidents, health));

  async function load() {
    try {
      data = await api(`/api/soc/overview?hours=${range.get()}`);
      render();
    } catch (err) {
      clear(kpis, h("div", { class: "card", style: { "grid-column": "1 / -1" } }, errorState(err.message, load)));
    }
  }

  function render() {
    updated.textContent = `Updated ${dateTime(data.generated_at)}`;
    clear(kpis, data.kpis.map((k) => kpiCard(k, data.hours)));
    renderThreat(data.threat);

    const series = [
      { key: "normal", label: "Passed", color: COLORS.normal },
      { key: "suspicious", label: "Suspicious", color: COLORS.suspicious },
      { key: "blocked", label: "Blocked (app)", color: COLORS.blocked },
    ];
    if (data.waf_connected) series.push({ key: "waf_blocked", label: "Blocked (AWS WAF)", color: COLORS.waf_blocked });
    if (chart && chart.hours === data.hours) chart.update(data.timeline);
    else {
      chart?.destroy();
      chart = timeSeries({ series, data: data.timeline, hours: data.hours, kind: "bars", height: 250 });
      chart.hours = data.hours;
      clear(traffic.body, chart.el);
    }

    const total = data.distribution.reduce((a, d) => a + d.count, 0);
    clear(dist.body, total ? hbars(data.distribution.map((d, i) => ({
      label: d.label, value: d.count, color: CATEGORY_COLORS[i % CATEGORY_COLORS.length],
      sub: `${int(d.count)} (${d.pct}%)`,
    }))) : h("p", { class: "muted small" }, `No attacks detected in the ${RANGE_LABELS[data.hours].toLowerCase()}.`));

    clear(sources.body, data.sources.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
      h("thead", {}, h("tr", {}, ["Source IP", "Requests", "Blocked", "Suspicious", "Most targeted", "Last activity"].map((t) => h("th", { scope: "col" }, t)))),
      h("tbody", {}, data.sources.map((s) => h("tr", { class: "clickable", tabindex: "0",
        onclick: () => ctx.navigate(`traffic/ip/${encodeURIComponent(s.client_ip)}`),
        onkeydown: (e) => { if (e.key === "Enter") ctx.navigate(`traffic/ip/${encodeURIComponent(s.client_ip)}`); } },
      h("td", { class: "num" }, s.client_ip), h("td", { class: "num" }, int(s.requests)),
      h("td", { class: "num" }, h("span", { style: { color: s.blocked ? "#fca5a5" : null } }, int(s.blocked))),
      h("td", { class: "num" }, int(s.suspicious)), h("td", { class: "trunc mono" }, s.top_endpoint),
      h("td", { class: "nowrap" }, ago(s.last_seen)))))))
      : h("p", { class: "muted small" }, "No source sent flagged traffic in this period."));

    clear(health.body, h("ul", { class: "health-list" },
      Object.entries(data.health).map(([k, c]) => healthRow(COMPONENT_NAMES[k] || k, c))));
  }

  function renderThreat(t) {
    const idx = LEVELS.indexOf(t.level);
    clear(threat, h("div", { class: "threat" },
      h("div", { style: { display: "flex", "justify-content": "space-between", "align-items": "center" } },
        h("h2", { id: "tl-title" }, "Threat level"), h("span", { class: "faint tiny" }, "Last hour + open work")),
      h("div", { class: "threat-level" }, h("span", { class: `lvl lvl-${t.level}` }, t.level),
        h("span", { class: "score" }, `score ${t.score} / 100`)),
      h("div", {}, h("div", { class: "threat-scale", "aria-hidden": "true" },
        LEVELS.map((l, i) => h("div", { class: i <= idx ? `bg-${t.level}` : "" }))),
      h("div", { class: "threat-scale-labels", style: { "margin-top": "4px" } }, LEVELS.map((l) => h("span", { class: l === t.level ? "on" : "" }, l)))),
      h("p", { class: "small" }, t.guidance),
      h("div", {}, h("div", { class: "section-title" }, "Why this level"),
        t.reasons.length ? h("ul", { class: "reasons" }, t.reasons.map((r) =>
          h("li", {}, h("span", {}, `${r.signal}: `, h("b", {}, int(r.value))), h("b", {}, `+${r.points}`))))
          : h("p", { class: "muted small" }, "No risk signals: no open incidents and no hostile traffic in the last hour."))));
  }

  load();
  incTable.load();
  timer = setInterval(() => { if (!document.hidden) { load(); incTable.refresh(); } }, 20000);

  return { el, destroy() { clearInterval(timer); chart?.destroy(); } };
}
