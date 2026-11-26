import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, qs } from "../lib/api.js";
import { card, pageHead, loading, errorState, toast, badge, segmented, switchControl, emptyState, pager } from "../lib/ui.js";
import { dateTime, ago, int } from "../lib/fmt.js";
import { sevBadge } from "./shared.js";

const DELIVERY = { sent: "Emailed via SNS", logged: "Logged (SNS not configured)", failed: "SNS delivery failed",
  suppressed: "Within cooldown, not re-sent", none: "In-app only" };

export default async function alertsPage(ctx) {
  const f = { status: "open", category: "", unread: false, page: 1 };
  const canManage = ctx.can("alerts:manage");
  const list = h("div", { class: "card-body flush" }, loading(5));
  const catSel = h("select", { class: "select", "aria-label": "Category", onchange: (e) => { f.category = e.target.value; f.page = 1; load(); } },
    h("option", { value: "" }, "All categories"));
  let catsLoaded = false;

  async function load() {
    let d;
    try { d = await api(`/api/alerts${qs({ page: f.page, page_size: 15, status: f.status, category: f.category, unread: f.unread || "" })}`); }
    catch (err) { clear(list, errorState(err.message, load)); return; }
    if (!catsLoaded) { catsLoaded = true; Object.entries(d.categories).forEach(([k, v]) => catSel.append(h("option", { value: k }, v))); }
    clear(list, d.items.length ? [h("ul", { class: "health-list", style: { padding: "0 16px" } }, d.items.map(row)),
      d.pages > 1 ? pager(d, (p) => { f.page = p; load(); }) : null]
      : emptyState("No alerts here", f.status === "open" ? "Nothing needs attention. Alerts come from incidents, health checks and CloudWatch alarms." : "Change the filters to see more."));
  }

  async function act(a, action) {
    try {
      await api(`/api/alerts/${a.id}`, { method: "POST", body: { action } });
      toast({ read: "Marked as read.", acknowledge: "Alert acknowledged.", resolve: "Alert resolved." }[action]);
      load();
    } catch (err) { toast(err.message, "err"); }
  }

  function row(a) {
    return h("li", { style: { "grid-template-columns": "10px 1fr auto", "align-items": "start", padding: "14px 0" } },
      h("i", { class: `sev-dot ${a.severity}`, style: { "margin-top": "6px" } }),
      h("div", { class: "stack", style: { gap: "4px" } },
        h("div", { style: { display: "flex", gap: "8px", "align-items": "center", "flex-wrap": "wrap" } },
          h("strong", {}, a.title), sevBadge(a.severity), badge(a.status), !a.is_read ? badge("new", "Unread") : null),
        h("p", { class: "small muted" }, a.description),
        h("p", { class: "tiny faint" },
          `${a.category_label}. First ${dateTime(a.ts)}, last ${ago(a.last_seen_at)}${a.occurrences > 1 ? `, ${int(a.occurrences)} occurrences` : ""}. ${DELIVERY[a.delivery] || a.delivery}.`,
          a.acknowledged_by ? ` Acknowledged by ${a.acknowledged_by}.` : "", a.resolved_by ? ` Resolved by ${a.resolved_by}.` : "",
          a.incident_id ? [" ", h("a", { href: `#/investigate/incident/${a.incident_id}` }, `Open ${a.incident_ref}`)] : null)),
      h("div", { class: "page-actions", style: { "justify-content": "flex-end" } },
        !a.is_read ? h("button", { class: "btn sm ghost", type: "button", onclick: () => act(a, "read") }, "Mark read") : null,
        canManage && a.status === "open" ? h("button", { class: "btn sm", type: "button", onclick: () => act(a, "acknowledge") }, "Acknowledge") : null,
        canManage && a.status !== "resolved" ? h("button", { class: "btn sm", type: "button", onclick: () => act(a, "resolve") }, icon("check"), "Resolve") : null));
  }

  const cw = card({ title: "CloudWatch alarms", sub: "Read live from CloudWatch when deployed", body: loading(3) });
  api("/api/infra").then((d) => {
    const c = d.services.find((s) => s.key === "cloudwatch");
    clear(cw.body, c.alarms?.length ? h("ul", { class: "health-list" }, c.alarms.map((a) => h("li", {},
      h("i", { class: `sev-dot ${a.state === "ALARM" ? "critical" : a.state === "OK" ? "healthy" : "informational"}` }),
      h("span", {}, a.name), badge(a.state === "ALARM" ? "critical" : a.state === "OK" ? "healthy" : "informational", a.state))))
      : h("p", { class: "muted small" }, c.reason || c.error || "No alarms found."));
  }).catch((err) => clear(cw.body, errorState(err.message)));

  const policy = card({ title: "Flood control", body: h("ul", { class: "stack small muted", style: { gap: "8px", margin: 0, "padding-left": "18px" } },
    h("li", {}, "Alerts with the same source and type are merged into one open alert; its occurrence count rises instead of new alerts appearing."),
    h("li", {}, "SNS sends at most one email per source and type per cooldown period. Change the cooldown under Security policies."),
    h("li", {}, "CloudWatch alarms notify SNS themselves; the console records them here without sending a second email."),
    h("li", {}, "Medium, high and critical alerts are emailed; low and informational stay in the console.")) });

  const el = h("div", { class: "page" },
    pageHead("Monitoring & Alerts", "The notification center: alerts raised by incidents, health checks, CloudWatch alarms and delivery failures.",
      [h("button", { class: "btn", type: "button", onclick: async () => { await api("/api/alerts/read-all", { method: "POST" }); toast("All alerts marked as read."); load(); } }, icon("check"), "Mark all read")]),
    h("div", { class: "grid g-2-1" },
      h("section", { class: "card" },
        h("div", { class: "filters" },
          segmented([{ value: "open", label: "Open" }, { value: "acknowledged", label: "Acknowledged" }, { value: "resolved", label: "Resolved" }, { value: "", label: "All" }],
            f.status, (v) => { f.status = v; f.page = 1; load(); }, "Status"),
          catSel, switchControl("Unread only", false, (v) => { f.unread = v; f.page = 1; load(); })),
        list),
      h("div", { class: "stack" }, cw, policy)));

  load();
  const timer = setInterval(() => { if (!document.hidden) load(); }, 30000);
  return { el, destroy() { clearInterval(timer); } };
}
