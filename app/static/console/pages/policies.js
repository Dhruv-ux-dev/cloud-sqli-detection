import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, qs } from "../lib/api.js";
import { card, pageHead, loading, errorState, toast, badge, formModal } from "../lib/ui.js";
import { dateTime, int } from "../lib/fmt.js";

export default async function policies(ctx) {
  const el = h("div", { class: "page" }, loading(6));
  const canBlock = ctx.can("blocklist:manage");

  async function load() {
    let d, bl, history = { items: [] };
    try {
      [d, bl] = await Promise.all([api("/api/policies"), api("/api/blocklist")]);
      if (ctx.can("audit:view")) history = await api(`/api/audit${qs({ action: "policy.", page_size: 8 })}`).catch(() => ({ items: [] }));
    } catch (err) { clear(el, errorState(err.message, load)); return; }

    const inputs = {};
    const err = h("p", { class: "form-error", role: "alert", hidden: true });
    const form = h("form", { class: "stack", novalidate: true, onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      const values = {};
      for (const p of d.items) {
        const v = Number(inputs[p.key].value);
        if (!Number.isInteger(v) || v < p.min || v > p.max) {
          err.textContent = `${p.label} must be a whole number between ${p.min} and ${p.max}.`;
          err.hidden = false; inputs[p.key].focus(); return;
        }
        if (v !== p.value) values[p.key] = v;
      }
      if (!Object.keys(values).length) { toast("No values changed.", "info"); return; }
      formModal({ title: "Apply policy changes?", description: `${Object.keys(values).length} value(s) change for all new traffic immediately.`,
        fields: [{ name: "reason", label: "Reason (recorded in the audit log)", type: "textarea", required: true, maxlength: 300 }],
        submitLabel: "Apply changes",
        onSubmit: async (v) => { await api("/api/policies", { method: "PUT", body: { values, reason: v.reason } }); toast("Policy updated."); load(); } });
    } },
    h("div", { class: "table-wrap" }, h("table", { class: "data" },
      h("thead", {}, h("tr", {}, ["Policy", "Value", "Default", "Allowed range", "Last change"].map((t) => h("th", { scope: "col" }, t)))),
      h("tbody", {}, d.items.map((p) => {
        inputs[p.key] = h("input", { class: "input num", type: "number", id: `pol-${p.key}`, value: p.value, min: p.min, max: p.max, step: 1,
          disabled: d.can_manage ? null : true, style: { width: "120px" } });
        return h("tr", {},
          h("td", {}, h("label", { for: `pol-${p.key}`, style: { "font-weight": "600" } }, p.label), h("p", { class: "faint tiny", style: { "max-width": "52ch" } }, p.description)),
          h("td", { class: "nowrap" }, inputs[p.key], h("span", { class: "faint small" }, ` ${p.unit}`)),
          h("td", { class: "num" }, int(p.default)),
          h("td", { class: "num nowrap faint" }, `${int(p.min)}–${int(p.max)}`),
          h("td", { class: "small" }, p.updated_by ? `${p.updated_by}, ${dateTime(p.updated_at)}` : h("span", { class: "faint" }, "default")));
      })))),
    err,
    d.can_manage ? h("div", {}, h("button", { class: "btn primary", type: "submit" }, "Save policy changes"))
      : h("p", { class: "muted small" }, "Only administrators can change policies."));

    const blockForm = canBlock ? h("button", { class: "btn", type: "button", onclick: () => formModal({
      title: "Block an IP address", fields: [
        { name: "ip", label: "IP address", required: true, placeholder: "203.0.113.7" },
        { name: "reason", label: "Reason", type: "textarea", required: true, maxlength: 300 }],
      submitLabel: "Block address", danger: true,
      onSubmit: async (v) => { await api("/api/blocklist", { method: "POST", body: { ip: v.ip.trim(), reason: v.reason } }); toast(`${v.ip} blocked.`); load(); } }) },
    icon("ban"), "Block an IP") : null;

    clear(el,
      pageHead("Security Policies", "Thresholds behind brute-force, bulk-access, rate-limit and repeat-attack detection, plus the administrator blocklist. Detector scoring thresholds are fixed in code and explained on the SQL Injection Detection page."),
      card({ title: "Detection and response thresholds", body: form }),
      h("div", { class: "grid g-2-1 mt" },
        card({ title: "IP blocklist", sub: "Requests from these addresses are refused with 403 before inspection", actions: blockForm,
          body: bl.items.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
            h("thead", {}, h("tr", {}, ["Address", "Reason", "Added", "State", ""].map((t) => h("th", { scope: "col" }, t)))),
            h("tbody", {}, bl.items.map((b) => h("tr", {},
              h("td", { class: "num mono" }, b.ip), h("td", { class: "small" }, b.reason, b.incident_id ? [" ", h("a", { href: `#/investigate/incident/${b.incident_id}` }, `INC-${String(b.incident_id).padStart(6, "0")}`)] : null),
              h("td", { class: "small nowrap" }, `${b.created_by}, ${dateTime(b.created_at)}`),
              h("td", {}, b.active ? badge("blocked", "Blocked") : badge("informational", `Removed by ${b.removed_by}`)),
              h("td", { class: "r" }, b.active && canBlock ? h("button", { class: "btn sm", type: "button", onclick: () => formModal({
                title: `Unblock ${b.ip}?`, description: "Requests from this address will be inspected normally again.", submitLabel: "Unblock",
                onSubmit: async () => { await api(`/api/blocklist/${encodeURIComponent(b.ip)}`, { method: "DELETE" }); toast(`${b.ip} unblocked.`); load(); } }) }, "Unblock") : null))))))
            : h("p", { class: "muted small" }, "No addresses blocked. Block a source from an incident investigation or with the button above.") }),
        card({ title: "Recent policy changes", body: history.items.length ? h("ul", { class: "health-list" }, history.items.map((a) => h("li", {},
          h("i", { class: "sev-dot low" }), h("span", { class: "small" }, `${a.actor}: ${Object.keys(a.detail.changes || {}).join(", ")}`),
          h("span", { class: "faint tiny" }, dateTime(a.ts)), h("span", { class: "d" }, a.detail.reason || ""))))
          : h("p", { class: "muted small" }, "No changes recorded.") })));
  }
  load();
  return { el };
}
