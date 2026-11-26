import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, download } from "../lib/api.js";
import { card, pageHead, rangeControl, loading, errorState, toast } from "../lib/ui.js";
import { timeSeries, hbars, donut, COLORS, CATEGORY_COLORS } from "../lib/charts.js";
import { int } from "../lib/fmt.js";

export default async function analytics(ctx) {
  const charts = [];
  const range = rangeControl(() => load(), { key: "an-range" });
  const trend = card({ title: "Attack trends over time", sub: "Flagged requests per interval, by attack category", body: loading(5) });
  const cats = card({ title: "Attack categories", body: loading(5) });
  const traffic = card({ title: "Blocked versus allowed traffic", sub: "Everything the application inspected", body: loading(5) });
  const sev = card({ title: "Incident severity", sub: "Incidents opened in this period", body: loading(4) });
  const ips = card({ title: "Top source IPs", sub: "Ranked by flagged requests", body: loading(5) });
  const endpoints = card({ title: "Most targeted endpoints", body: loading(5) });
  const rules = card({ title: "Detection rule performance", sub: "How often each rule matched, and how often the request ended up blocked", body: loading(6) });
  const dlp = card({ title: "Sensitive data access activity", sub: "Searches, masked views and reveals", body: loading(5) });

  const exp = (path, name) => async () => {
    try { toast(`Downloaded ${await download(`${path}?hours=${range.get()}`, name)}`); } catch (err) { toast(err.message, "err"); }
  };
  const exports = ctx.can("reports:export") ? [
    h("button", { class: "btn", type: "button", onclick: exp("/api/export/requests.csv", "requests.csv") }, icon("download"), "Requests CSV"),
    h("button", { class: "btn", type: "button", onclick: exp("/api/export/incidents.csv", "incidents.csv") }, icon("download"), "Incidents CSV"),
    h("button", { class: "btn", type: "button", onclick: exp("/api/export/summary.md", "summary.md") }, icon("file"), "Activity summary"),
  ] : null;

  const el = h("div", { class: "page" },
    pageHead("Threat Analytics", "Trends and breakdowns computed by the database for the selected period.", [range.el, exports]),
    trend,
    h("div", { class: "grid g-2 mt" }, cats, traffic),
    h("div", { class: "grid g-3 mt" }, sev, ips, endpoints),
    h("div", { class: "grid g-2 mt" }, rules, dlp));

  async function load() {
    charts.splice(0).forEach((c) => c.destroy());
    let d;
    try { d = await api(`/api/analytics?hours=${range.get()}`); } catch (err) {
      clear(trend.body, errorState(err.message, load));
      return;
    }
    const catSeries = d.attack_trend.categories.map((c, i) => ({ key: c.key, label: c.label, color: CATEGORY_COLORS[i % CATEGORY_COLORS.length] }));
    if (catSeries.length) {
      const t = timeSeries({ series: catSeries, data: d.attack_trend.series, hours: d.hours, kind: "bars", height: 240 });
      charts.push(t);
      clear(trend.body, t.el);
    } else clear(trend.body, h("p", { class: "muted small" }, "No attacks in this period."));

    clear(cats.body, hbars(d.categories.map((c, i) => ({ label: c.label, value: c.count, color: CATEGORY_COLORS[i % CATEGORY_COLORS.length] }))));

    const tr = timeSeries({ series: [
      { key: "normal", label: "Allowed", color: COLORS.normal },
      { key: "suspicious", label: "Suspicious", color: COLORS.suspicious },
      { key: "blocked", label: "Blocked", color: COLORS.blocked },
    ], data: d.traffic, hours: d.hours, kind: "area", height: 220 });
    charts.push(tr);
    clear(traffic.body, tr.el);

    clear(sev.body, donut(d.severity.map((s) => ({ label: s.severity === "informational" ? "Info" : s.severity[0].toUpperCase() + s.severity.slice(1),
      value: s.count, color: COLORS[s.severity] })), { centerLabel: "incidents" }));

    clear(ips.body, hbars(d.top_ips.map((r) => ({
      label: r.client_ip, value: r.requests, sub: `${int(r.blocked)} blocked, ${int(r.suspicious)} suspicious of ${int(r.requests)}`,
      parts: [{ value: r.blocked, color: COLORS.blocked }, { value: r.suspicious, color: COLORS.suspicious },
        { value: r.requests - r.blocked - r.suspicious, color: COLORS.normal }],
      onClick: () => ctx.navigate(`traffic/ip/${encodeURIComponent(r.client_ip)}`),
    }))));
    clear(endpoints.body, hbars(d.top_endpoints.map((r) => ({
      label: r.path, value: r.requests, sub: `${int(r.flagged)} flagged of ${int(r.requests)}`,
      parts: [{ value: r.blocked, color: COLORS.blocked }, { value: r.flagged - r.blocked, color: COLORS.suspicious },
        { value: r.requests - r.flagged, color: COLORS.normal }],
    }))));

    clear(rules.body, d.rules.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
      h("thead", {}, h("tr", {}, ["Rule", "Weight", "Matches", "In blocked", "Block share"].map((t) => h("th", { scope: "col" }, t)))),
      h("tbody", {}, d.rules.map((r) => h("tr", { class: "clickable", tabindex: "0", onclick: () => ctx.navigate(`detection/${r.rule_id}`) },
        h("td", {}, h("span", { class: "chip" }, r.rule_id), " ", r.rule),
        h("td", { class: "num" }, `+${r.weight}`), h("td", { class: "num" }, int(r.matches)),
        h("td", { class: "num" }, int(r.in_blocked)),
        h("td", { class: "num" }, `${Math.round((r.in_blocked / r.matches) * 100)}%`))))))
      : h("p", { class: "muted small" }, "No rule matched in this period."));

    const dl = timeSeries({ series: [
      { key: "search", label: "Searches", color: "#38bdf8" },
      { key: "masked_view", label: "Masked views", color: "#818cf8" },
      { key: "reveal", label: "Reveals", color: "#f97316" },
      { key: "reveal_denied", label: "Denied reveals", color: "#ef4444" },
    ], data: d.dlp, hours: d.hours, kind: "bars", height: 200 });
    charts.push(dl);
    clear(dlp.body, dl.el);
  }

  load();
  return { el, destroy() { charts.forEach((c) => c.destroy()); } };
}
