import { h, clear, debounce } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, qs, download } from "../lib/api.js";
import { pageHead, toast, segmented } from "../lib/ui.js";
import { dataTable } from "../lib/table.js";
import { dateTime, int } from "../lib/fmt.js";
import { sevBadge, statusBadge, ipLink } from "./shared.js";

export default async function incidents(ctx) {
  const f = { status: "", severity: "", category: "", q: "", from: "", to: "" };
  const counts = h("span", { class: "faint small" });

  const table = dataTable({
    caption: "Security incidents",
    columns: [
      { label: "Incident", render: (r) => h("a", { href: `#/investigate/incident/${r.id}`, class: "mono" }, r.ref) },
      { label: "Severity", sort: "severity", render: (r) => sevBadge(r.severity) },
      { label: "Category", render: (r) => r.category_label },
      { label: "Summary", cls: "trunc", render: (r) => h("span", { title: r.summary }, r.summary) },
      { label: "Source", render: (r) => (r.client_ip ? ipLink(r.client_ip) : r.username || "—") },
      { label: "Seen", sort: "occurrences", cls: "r", render: (r) => h("span", { class: "num" }, `${int(r.occurrences)}×`) },
      { label: "Opened", sort: "ts", render: (r) => h("span", { class: "nowrap" }, dateTime(r.ts)) },
      { label: "Last activity", sort: "last_seen", render: (r) => h("span", { class: "nowrap" }, dateTime(r.last_seen_at)) },
      { label: "Status", sort: "status", render: (r) => statusBadge(r.status) },
      { label: "Assigned", render: (r) => r.assigned_to || h("span", { class: "faint" }, "—") },
    ],
    sort: "last_seen",
    fetch: async ({ page, sort, order }) => {
      const params = { page, page_size: 20, sort, order, status: f.status, severity: f.severity, category: f.category, q: f.q,
        from: f.from ? new Date(f.from).toISOString() : "", to: f.to ? new Date(f.to + "T23:59:59").toISOString() : "" };
      const d = await api(`/api/incidents${qs(params)}`);
      const c = d.status_counts;
      counts.textContent = `${int(c.new || 0)} new, ${int(c.investigating || 0)} investigating, ${int(c.resolved || 0)} resolved, ${int(c.false_positive || 0)} false positive`;
      if (catSel.options.length === 1) {
        Object.entries(d.categories).forEach(([k, v]) => catSel.append(h("option", { value: k }, v)));
      }
      return d;
    },
    onRow: (r) => ctx.navigate(`investigate/incident/${r.id}`),
    emptyTitle: "No incidents match these filters",
    emptyText: "Incidents are opened automatically by repeated or critical injections, brute-force sign-ins, bulk data access and unauthorized actions.",
  });

  const catSel = h("select", { class: "select", "aria-label": "Category", onchange: (e) => { f.category = e.target.value; table.reload(); } },
    h("option", { value: "" }, "All categories"));
  const sevSel = h("select", { class: "select", "aria-label": "Severity", onchange: (e) => { f.severity = e.target.value; table.reload(); } },
    [["", "All severities"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["informational", "Informational"],
      ["critical,high", "Critical and high"]].map(([v, t]) => h("option", { value: v }, t)));
  const from = h("input", { class: "input", type: "date", "aria-label": "Opened from", onchange: (e) => { f.from = e.target.value; table.reload(); } });
  const to = h("input", { class: "input", type: "date", "aria-label": "Opened until", onchange: (e) => { f.to = e.target.value; table.reload(); } });
  const search = h("input", { class: "input grow", type: "search", placeholder: "Search INC-ID, IP, user, endpoint, assignee", "aria-label": "Search incidents",
    oninput: debounce((e) => { f.q = e.target.value.trim(); table.reload(); }) });

  const el = h("div", { class: "page" },
    pageHead("Security Incidents", "Every incident the platform opened, with its workflow state. Repeated activity from the same source updates the open incident instead of opening a new one.",
      [counts, ctx.can("reports:export") ? h("button", { class: "btn", type: "button", onclick: async () => {
        try { toast(`Downloaded ${await download("/api/export/incidents.csv?hours=720", "incidents.csv")}`); } catch (err) { toast(err.message, "err"); }
      } }, icon("download"), "Export CSV (30 days)") : null]),
    h("section", { class: "card" },
      h("div", { class: "filters" },
        segmented([{ value: "", label: "All" }, { value: "new", label: "New" }, { value: "investigating", label: "Investigating" },
          { value: "resolved", label: "Resolved" }, { value: "false_positive", label: "False positive" }], "",
        (v) => { f.status = v; table.reload(); }, "Status"),
        sevSel, catSel, h("label", { class: "small muted" }, "From ", from), h("label", { class: "small muted" }, "to ", to), search),
      table.el));

  table.load();
  const timer = setInterval(() => { if (!document.hidden) table.refresh(); }, 30000);
  return { el, destroy() { clearInterval(timer); } };
}
