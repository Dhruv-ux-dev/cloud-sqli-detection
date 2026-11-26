import { h, clear, debounce } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, qs } from "../lib/api.js";
import { pageHead, badge, drawer, toast } from "../lib/ui.js";
import { dataTable } from "../lib/table.js";
import { dateTime, fullDateTime } from "../lib/fmt.js";

export default async function auditPage(ctx) {
  const f = { action: "", result: "", actor: "", q: "" };
  const scope = h("span", { class: "faint small" });
  let actionsLoaded = false;

  const actionSel = h("select", { class: "select", "aria-label": "Action", onchange: (e) => { f.action = e.target.value; table.reload(); } },
    h("option", { value: "" }, "All actions"));
  const table = dataTable({
    caption: "Audit log",
    columns: [
      { label: "Event", render: (r) => h("span", { class: "mono" }, r.ref) },
      { label: "Time", render: (r) => h("span", { class: "nowrap num" }, dateTime(r.ts)) },
      { label: "User", render: (r) => (r.actor ? `${r.actor}${r.actor_role ? ` (${r.actor_role})` : ""}` : h("span", { class: "faint" }, "system")) },
      { label: "Action", render: (r) => h("span", { class: "chip" }, r.action) },
      { label: "Resource", cls: "trunc mono", render: (r) => r.resource || "—" },
      { label: "Source IP", render: (r) => h("span", { class: "num" }, r.client_ip || "—") },
      { label: "Result", render: (r) => badge(r.result) },
    ],
    fetch: async ({ page }) => {
      const d = await api(`/api/audit${qs({ page, page_size: 20, ...f })}`);
      scope.textContent = d.scope === "all" ? "Showing all audit records" : "Your role sees operational records (incidents, alerts, blocklist, detection, exports, data access)";
      if (!actionsLoaded) {
        actionsLoaded = true;
        const groups = [...new Set(d.actions.map((a) => a.split(".")[0]))];
        groups.forEach((g) => actionSel.append(h("option", { value: g + "." }, `${g}.*`)));
        d.actions.forEach((a) => actionSel.append(h("option", { value: a }, a)));
      }
      return d;
    },
    onRow: (r) => openEvent(r),
    emptyTitle: "No audit records match",
  });

  function openEvent(r) {
    drawer({ title: `${r.ref}: ${r.action}`, subtitle: fullDateTime(r.ts), body: h("div", { class: "stack" },
      h("dl", { class: "kv" },
        h("dt", {}, "User"), h("dd", {}, r.actor || "system"), h("dt", {}, "Role"), h("dd", {}, r.actor_role || "—"),
        h("dt", {}, "Action"), h("dd", { class: "mono" }, r.action), h("dt", {}, "Resource"), h("dd", { class: "mono" }, r.resource || "—"),
        h("dt", {}, "Source IP"), h("dd", {}, r.client_ip || "—"), h("dt", {}, "Result"), h("dd", {}, badge(r.result))),
      h("div", {}, h("div", { class: "section-title" }, "Detail"), h("pre", { class: "payload" }, JSON.stringify(r.detail, null, 2))),
      h("p", { class: "faint small" }, "Audit records are append-only: the database rejects updates and deletes, and no API changes them.")) });
  }

  const el = h("div", { class: "page" },
    pageHead("Audit Logs", "Append-only history of security-sensitive actions: sign-ins, role and policy changes, reveals of customer data, incident updates, blocklist changes and exports.", [scope]),
    h("div", { class: "banner info", role: "note" }, icon("lock"),
      h("div", {}, "Credentials, tokens and customer values are never written here; records hold user names, resource identifiers and field names only.")),
    h("section", { class: "card mt" },
      h("div", { class: "filters" }, actionSel,
        h("select", { class: "select", "aria-label": "Result", onchange: (e) => { f.result = e.target.value; table.reload(); } },
          [["", "All results"], ["success", "Success"], ["failure", "Failure"], ["denied", "Denied"]].map(([v, t]) => h("option", { value: v }, t))),
        h("input", { class: "input", type: "search", placeholder: "Exact user name", "aria-label": "User",
          oninput: debounce((e) => { f.actor = e.target.value.trim(); table.reload(); }) }),
        h("input", { class: "input grow", type: "search", placeholder: "Search resource, action, IP", "aria-label": "Search audit log",
          oninput: debounce((e) => { f.q = e.target.value.trim(); table.reload(); }) })),
      table.el));

  table.load();
  if (ctx.params[0]) {
    api(`/api/audit/${Number(ctx.params[0])}`).then(openEvent).catch((err) => toast(err.message, "err"));
  }
  return { el };
}
