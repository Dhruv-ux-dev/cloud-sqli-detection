import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api } from "../lib/api.js";
import { card, pageHead, loading, errorState, badge } from "../lib/ui.js";
import { dateTime, num, label } from "../lib/fmt.js";
import { COMPONENT_NAMES } from "./shared.js";

const WHAT = {
  api: "The FastAPI process answering this page.",
  database: "A query through the runtime connection pool, with its latency.",
  detector: "Self-test: a known injection must be blocked and a known-good name must pass.",
  dlp: "Self-test: every masking rule must hide the original value.",
  waf: "Reads the Web ACL definition and its metrics from AWS WAF.",
  cloudwatch: "Lists this deployment's alarms and the last log ingestion time.",
  sns: "Reads the topic's subscription counts.",
};

export default async function health(ctx) {
  const el = h("div", { class: "page" }, loading(6));
  async function load() {
    let d;
    try { d = await api("/api/health/components"); } catch (err) { clear(el, errorState(err.message, load)); return; }
    clear(el,
      pageHead("System Health", `Live checks of each component. Mode: ${d.mode === "local" ? "local (AWS services not connected)" : "AWS"}.`,
        [h("button", { class: "btn", type: "button", onclick: load }, icon("refresh"), "Run checks again")]),
      h("div", { class: "grid g-3" }, Object.entries(d.components).map(([k, c]) => card({ title: COMPONENT_NAMES[k] || k,
        body: h("div", { class: "stack", style: { gap: "10px" } },
          h("div", { style: { display: "flex", gap: "8px", "align-items": "center" } },
            badge(c.status, label(c.status)), h("span", { class: "faint small" }, `checked ${dateTime(c.checked_at)}`)),
          h("p", { class: "small muted" }, WHAT[k]),
          c.detail ? h("p", { class: "small" }, c.detail) : null,
          c.reason ? h("p", { class: "small" }, c.reason) : null,
          c.error ? h("p", { class: "form-error" }, c.error) : null,
          c.metrics ? h("div", { class: "svc-metrics" }, Object.entries(c.metrics).map(([mk, mv]) =>
            h("div", {}, h("span", {}, label(mk)), h("b", {}, mv === null || mv === undefined ? "—" : typeof mv === "number" ? num(mv, 1) : String(mv))))) : null) }))));
  }
  load();
  const t = setInterval(() => { if (!document.hidden) load(); }, 60000);
  return { el, destroy() { clearInterval(t); } };
}
