import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, qs } from "../lib/api.js";
import { card, pageHead, loading, errorState, toast, badge, formModal, rangeControl, segmented } from "../lib/ui.js";
import { timeSeries, hbars } from "../lib/charts.js";
import { dataTable } from "../lib/table.js";
import { int, dateTime, label } from "../lib/fmt.js";

const TYPE_LABEL = { search: "Search (masked)", masked_view: "Record view (masked)", reveal: "Full reveal",
  reveal_denied: "Reveal denied", sample: "Masking demo (masked)" };

export default async function dlpPage(ctx) {
  const range = rangeControl(() => loadOverview(), { key: "dlp-range" });
  let chart = null;
  const kpis = h("div", { class: "grid g-5" }, loading(2));
  const categories = card({ title: "Sensitive data categories", sub: "How often each protected field was part of a response", body: loading(5) });
  const activity = card({ title: "Access activity", body: loading(4) });
  const controls = card({ title: "Security controls", body: loading(4) });
  const demo = card({ title: "Masking demonstration", sub: "Real records as every non-admin user sees them. Revealing needs administrator rights and a reason, and is audited.", body: loading(4) });
  const users = card({ title: "Who accessed sensitive data", body: loading(4) });

  const af = { access_type: "", authorized: "" };
  const access = dataTable({
    caption: "Sensitive data access audit",
    columns: [
      { label: "Time", render: (r) => h("span", { class: "nowrap num" }, dateTime(r.ts)) },
      { label: "User", render: (r) => `${r.username} (${r.role})` },
      { label: "Record", render: (r) => (r.customer_id ? `customer ${r.customer_id}` : r.row_count ? `${r.row_count} rows` : "—") },
      { label: "Fields", render: (r) => r.fields.map((f) => h("span", { class: "chip", style: { "margin-right": "4px" } }, f)) },
      { label: "Access", render: (r) => TYPE_LABEL[r.access_type] || r.access_type },
      { label: "Authorization", render: (r) => (r.authorized ? badge("success", "Authorized") : badge("denied", "Denied")) },
      { label: "Source", render: (r) => h("span", { class: "num" }, r.client_ip || "—") },
    ],
    fetch: ({ page }) => api(`/api/dlp/access${qs({ page, page_size: 12, ...af })}`),
    emptyTitle: "No sensitive data access recorded",
    emptyText: "Searches and record views on the customer records desk appear here.",
  });

  const el = h("div", { class: "page" },
    pageHead("Data Protection Center", "Data leak prevention: what sensitive customer data left the API, in what form, and for whom. Values are never logged, only field names.",
      [range.el, h("a", { class: "btn", href: "/records" }, icon("records"), "Customer records desk")]),
    kpis,
    h("div", { class: "grid g-2 mt" }, categories, activity),
    h("div", { class: "mt" }, demo),
    h("div", { class: "grid g-2-1 mt" },
      h("section", { class: "card" },
        h("div", { class: "card-head" }, h("div", {}, h("h2", {}, "Access audit"), h("p", { class: "sub" }, "Every search, view and reveal of customer records"))),
        h("div", { class: "filters" },
          segmented([{ value: "", label: "All" }, { value: "reveal", label: "Reveals" }, { value: "reveal_denied", label: "Denied" },
            { value: "masked_view", label: "Views" }, { value: "search", label: "Searches" }], "",
          (v) => { af.access_type = v; access.reload(); }, "Access type")),
        access.el),
      h("div", { class: "stack" }, controls, users)));

  async function loadOverview() {
    let d;
    try { d = await api(`/api/dlp/overview?hours=${range.get()}`); } catch (err) { clear(kpis, errorState(err.message, loadOverview)); return; }
    const k = d.kpis;
    const kc = (l, v, sub) => h("section", { class: "card kpi" }, h("div", { class: "kpi-top" }, l), h("div", { class: "kpi-value num" }, int(v)),
      h("div", { class: "kpi-foot" }, sub));
    clear(kpis,
      kc("Customer records", k.customers, "in the protected database"),
      kc("Records accessed", k.records_accessed, "distinct records opened"),
      kc("Masked responses", k.masked_responses, "rows and views sent masked"),
      kc("Authorized reveals", k.reveals, "full details shown to admins"),
      h("section", { class: "card kpi" }, h("div", { class: "kpi-top" }, "Unauthorized reveal attempts"),
        h("div", { class: "kpi-value num", style: { color: k.denied ? "var(--crit)" : null } }, int(k.denied)),
        h("div", { class: "kpi-foot" }, k.denied ? "each opened an incident" : "none in this period")));
    clear(categories.body, hbars(d.categories.map((c) => ({ label: c.label, value: c.accesses,
      sub: `${int(c.accesses)} accesses, ${int(c.revealed)} unmasked`,
      parts: [{ value: c.revealed, color: "#f97316" }, { value: c.accesses - c.revealed, color: "#38bdf8" }] }))));
    chart?.destroy();
    chart = timeSeries({ series: [
      { key: "search", label: "Searches", color: "#38bdf8" }, { key: "masked_view", label: "Masked views", color: "#818cf8" },
      { key: "reveal", label: "Reveals", color: "#f97316" }, { key: "reveal_denied", label: "Denied", color: "#ef4444" },
    ], data: d.timeline, hours: d.hours, height: 200 });
    clear(activity.body, chart.el);
    clear(controls.body, h("ul", { class: "health-list" }, d.controls.map((c) =>
      h("li", {}, h("i", { class: "sev-dot healthy" }), h("strong", { class: "small" }, c.name), badge("enforced", "Enforced"),
        h("span", { class: "d" }, c.detail)))));
    clear(users.body, d.users.length ? h("ul", { class: "health-list" }, d.users.map((u) =>
      h("li", {}, h("i", { class: `sev-dot ${u.denied ? "critical" : "low"}` }), h("span", {}, `${u.username} (${u.role})`),
        h("span", { class: "num small" }, `${int(u.events)} events`),
        h("span", { class: "d" }, `${int(u.reveals)} reveals, ${int(u.denied)} denied, last ${dateTime(u.last_access)}`))))
      : h("p", { class: "muted small" }, "No access in this period."));
  }

  async function loadDemo() {
    let d;
    try { d = await api("/api/dlp/sample"); } catch (err) { clear(demo.body, errorState(err.message, loadDemo)); return; }
    const tbody = h("tbody");
    const row = (c) => {
      const tr = h("tr", {},
        h("td", {}, c.full_name), h("td", { class: "mono" }, c.email), h("td", { class: "mono" }, c.phone),
        h("td", { class: "mono" }, c.pan), h("td", { class: "mono" }, c.account_no),
        h("td", {}, c.masked ? badge("enforced", "Masked") : badge("high", "Revealed")),
        h("td", { class: "r" }, d.can_reveal ? (c.masked
          ? h("button", { class: "btn sm", type: "button", onclick: () => reveal(c, tr) }, icon("eye"), "Reveal")
          : h("button", { class: "btn sm ghost", type: "button", onclick: () => tr.replaceWith(row({ ...c._masked, _masked: c._masked })) }, icon("eyeOff"), "Mask"))
          : h("span", { class: "faint tiny" }, "Admin only")));
      return tr;
    };
    function reveal(c, tr) {
      formModal({
        title: `Reveal ${c.full_name}?`,
        description: "Full email, phone, PAN and account number will be shown once. Your name, the record and the reason are written to the audit log.",
        fields: [{ name: "reason", label: "Business reason", type: "textarea", required: true, maxlength: 300,
          placeholder: "e.g. Customer called to verify account ownership" }],
        submitLabel: "Reveal details",
        onSubmit: async (v) => {
          const full = await api("/api/dlp/reveal", { method: "POST", body: { customer_id: c.id, reason: v.reason } });
          tr.replaceWith(row({ ...full, _masked: c }));
          toast("Revealed and recorded in the audit log. It re-masks after 30 seconds.", "info");
          setTimeout(() => { if (document.contains(tbody)) loadDemo(); }, 30000);
          access.reload();
        },
      });
    }
    d.items.forEach((c) => tbody.append(row(c)));
    clear(demo.body, h("div", { class: "table-wrap" }, h("table", { class: "data" },
      h("caption", { class: "sr-only" }, "Masking demonstration"),
      h("thead", {}, h("tr", {}, ["Customer name", "Email", "Phone", "PAN", "Account number", "State", ""].map((t) => h("th", { scope: "col" }, t)))),
      tbody)),
    !d.can_reveal ? h("p", { class: "muted small", style: { "margin-top": "10px" } }, "Your role sees masked values only. A reveal attempt through the API is refused, logged and raised as an incident.") : null);
  }

  loadOverview();
  loadDemo();
  access.load();
  return { el, destroy() { chart?.destroy(); } };
}
