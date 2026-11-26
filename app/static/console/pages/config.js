import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api } from "../lib/api.js";
import { card, pageHead, loading, errorState, badge } from "../lib/ui.js";
import { label } from "../lib/fmt.js";

function kv(obj) {
  return h("dl", { class: "kv" }, Object.entries(obj).flatMap(([k, v]) => [
    h("dt", {}, label(k)),
    h("dd", { class: typeof v === "string" && v.includes(":") ? "mono small" : "small" },
      v === null || v === undefined || v === "" ? h("span", { class: "faint" }, "not set")
        : typeof v === "boolean" ? (v ? "yes" : "no") : Array.isArray(v) ? (v.length ? v.join(", ") : h("span", { class: "faint" }, "none"))
          : typeof v === "object" ? kv(v) : String(v)),
  ]));
}

export default async function config(ctx) {
  const el = h("div", { class: "page" }, loading(6));
  async function load() {
    let c;
    try { c = await api("/api/admin/config"); } catch (err) { clear(el, errorState(err.message, load)); return; }
    clear(el,
      pageHead("Configuration", "Runtime configuration of this instance. Secrets are never displayed: only whether they are set. Change values through environment variables or Terraform, then restart."),
      h("div", { class: "grid g-2" },
        card({ title: "Runtime", body: h("div", { class: "stack" },
          h("div", { style: { display: "flex", gap: "8px", "flex-wrap": "wrap" } }, h("span", { class: `env ${c.environment}` }, c.environment.toUpperCase()),
            badge("low", `WAF_MODE=${c.waf_mode}`),
            c.vulnerable_demo.active ? badge("critical", "Unsafe demo endpoint ON") : badge("healthy", "Unsafe demo endpoint off")),
          kv({ trust_proxy: c.trust_proxy, cookie_secure: c.cookie_secure, search_row_limit: c.search_row_limit,
            vulnerable_demo_requested: c.vulnerable_demo.requested, vulnerable_demo_active: c.vulnerable_demo.active })) }),
        card({ title: "Secrets", sub: "Presence only", body: h("ul", { class: "health-list" }, Object.entries(c.secrets).map(([k, v]) =>
          h("li", {}, h("i", { class: `sev-dot ${v === "set" ? "healthy" : v === "missing" ? "critical" : "informational"}` }), h("span", { class: "mono small" }, k), h("span", { class: "small muted" }, v)))) }),
        card({ title: "Database", body: kv(c.database) }),
        card({ title: "Session security", body: kv(c.session) }),
        card({ title: "AWS integration", sub: "Identifiers are partly masked", cls: "", body: kv(c.aws) })),
      h("div", { class: "banner info mt" }, icon("info"), h("div", {}, "WAF_MODE=off and the unsafe demo endpoint are refused when APP_ENV=production, whatever the other settings say.")));
  }
  load();
  return { el };
}
