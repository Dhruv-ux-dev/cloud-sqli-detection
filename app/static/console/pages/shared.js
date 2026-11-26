// Building blocks shared by several pages.
import { h } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api } from "../lib/api.js";
import { badge, drawer, formModal, toast, loading, errorState } from "../lib/ui.js";
import { int, fullDateTime, dateTime, VERDICT_LABEL, VERDICT_CLASS, label } from "../lib/fmt.js";

export const verdictBadge = (v, status) => badge(VERDICT_CLASS[v] || v,
  v === "blocked" && status && status !== 403 && status !== 429 ? "Not enforced" : VERDICT_LABEL[v] || label(v));
export const sevBadge = (s) => badge(s, s === "informational" ? "Info" : label(s));
export const statusBadge = (s) => badge(s, s === "false_positive" ? "False positive" : label(s));

export function scoreBar(score, thresholds) {
  const max = Math.max(score, thresholds.block * 2, 20);
  const color = score >= thresholds.block ? "#ef4444" : score >= thresholds.suspicious ? "#f59e0b" : "#22c55e";
  const pct = (v) => `${(v / max) * 100}%`;
  return h("div", { class: "stack", style: { gap: "4px" } },
    h("div", { class: "scorebar", role: "img", "aria-label": `Score ${score}; suspicious from ${thresholds.suspicious}, blocked from ${thresholds.block}` },
      h("div", { class: "seg-fill", style: { width: pct(score), background: color } }),
      h("div", { class: "mark", style: { left: pct(thresholds.suspicious) } }),
      h("div", { class: "mark", style: { left: pct(thresholds.block) } })),
    h("div", { class: "scorebar-labels" },
      h("span", { style: { left: "0", transform: "none" } }, "0"),
      h("span", { style: { left: pct(thresholds.suspicious) } }, `suspicious ${thresholds.suspicious}`),
      h("span", { style: { left: pct(thresholds.block) } }, `block ${thresholds.block}`)));
}

/** contributions: [{rule_id, rule, weight, severity, category_label, explanation, field, snippet, decoded}] */
export function explanationBlock(contributions, { score, thresholds, reason }) {
  return h("div", { class: "stack", style: { gap: "12px" } },
    h("div", { style: { display: "flex", "align-items": "baseline", gap: "10px", "flex-wrap": "wrap" } },
      h("span", { class: "kpi-value num" }, String(score)), h("span", { class: "muted small" }, "detection score")),
    scoreBar(score, thresholds),
    reason ? h("p", { class: "small" }, reason) : null,
    contributions.length ? h("div", { class: "contrib" }, contributions.map((c) => h("div", { class: "contrib-item" },
      h("div", { class: "top" }, h("span", { class: "chip" }, c.rule_id), h("strong", {}, c.rule),
        c.severity ? sevBadge(c.severity) : null, h("span", { class: "w" }, `+${c.weight}`)),
      c.category_label ? h("p", { class: "tiny faint" }, c.category_label) : null,
      h("p", {}, c.explanation),
      c.field ? h("p", { class: "tiny" }, h("span", { class: "faint" }, `Matched in ${c.field}${c.decoded ? " after decoding" : ""}: `),
        h("code", {}, c.snippet ?? "")) : null)))
      : h("p", { class: "muted small" }, "No detection rule matched this input."));
}

export function ipLink(ip) {
  return h("a", { href: `#/traffic/ip/${encodeURIComponent(ip)}`, class: "num", title: `Show traffic from ${ip}` }, ip);
}

/** Request detail drawer used by the traffic monitor, command center and search. */
export async function openRequestDrawer(id, ctx) {
  const d = drawer({ title: `Request REQ-${String(id).padStart(7, "0")}`, body: loading(6),
    footer: [h("a", { class: "btn", href: `#/investigate/request/${id}` }, icon("target"), "Open investigation")] });
  try {
    const r = await api(`/api/traffic/${id}`);
    d.body.replaceChildren(requestDetail(r, ctx));
    if (ctx.can("blocklist:manage") && r.verdict !== "normal") {
      d.panel.querySelector(".drawer-foot").prepend(blockButton(r.client_ip));
    }
  } catch (err) {
    d.body.replaceChildren(errorState(err.message));
  }
}

export function requestDetail(r, ctx) {
  return h("div", { class: "stack", style: { gap: "18px" } },
    h("div", { style: { display: "flex", gap: "8px", "align-items": "center", "flex-wrap": "wrap" } },
      verdictBadge(r.verdict, r.status), r.category_label ? badge("informational", r.category_label) : null,
      h("span", { class: "muted small" }, `Stopped by: ${r.source}`)),
    h("dl", { class: "kv" },
      h("dt", {}, "Time"), h("dd", {}, fullDateTime(r.ts)),
      h("dt", {}, "Source IP"), h("dd", {}, ipLink(r.client_ip)),
      h("dt", {}, "Request"), h("dd", {}, h("span", { class: "method" }, r.method), r.path),
      h("dt", {}, "Status"), h("dd", { class: "num" }, String(r.status)),
      h("dt", {}, "User"), h("dd", {}, r.username || "not signed in"),
      h("dt", {}, "User agent"), h("dd", { class: "small" }, r.user_agent || "—"),
      h("dt", {}, "Latency"), h("dd", { class: "num" }, r.latency_ms !== null ? `${r.latency_ms} ms` : "—")),
    h("div", {}, h("div", { class: "section-title" }, "Query parameters (sensitive values removed)"),
      h("pre", { class: "payload" }, r.query_preview || "(none)")),
    h("div", {}, h("div", { class: "section-title" }, "Input that matched"),
      h("pre", { class: "payload" }, r.sample || "(no rule matched)")),
    h("div", {}, h("div", { class: "section-title" }, "Why it got this verdict"),
      explanationBlock(r.explanation, { score: r.score, thresholds: r.thresholds, reason: r.reason })),
    r.related_incidents?.length ? h("div", {}, h("div", { class: "section-title" }, "Related incidents"),
      h("ul", { class: "health-list" }, r.related_incidents.map((i) => h("li", {}, h("i", { class: `sev-dot ${i.severity}` }),
        h("a", { href: `#/investigate/incident/${i.id}` }, `${i.ref}: ${i.summary}`), h("span", { class: "faint tiny" }, dateTime(i.ts))))))
      : null);
}

export function blockButton(ip, incidentId, onDone) {
  return h("button", { class: "btn danger", type: "button", onclick: () => formModal({
    title: `Block ${ip}?`,
    description: "Every request from this address will be refused with 403 until an administrator removes it. The change is audited.",
    fields: [{ name: "reason", label: "Reason", type: "textarea", required: true, maxlength: 300,
      value: incidentId ? `Attack source in INC-${String(incidentId).padStart(6, "0")}` : "Repeated SQL injection attempts" }],
    submitLabel: "Block address", danger: true,
    onSubmit: async (v) => {
      await api("/api/blocklist", { method: "POST", body: { ip, reason: v.reason, incident_id: incidentId || null } });
      toast(`${ip} is now blocked.`);
      onDone && onDone();
    },
  }) }, icon("ban"), "Block source IP");
}

export function healthRow(name, c) {
  const st = c.status;
  const text = { healthy: "Healthy", degraded: "Degraded", down: "Down", error: "Error", not_connected: "Not connected",
    not_configured: "Not configured" }[st] || label(st);
  return h("li", {}, h("i", { class: `sev-dot ${st}` }), h("span", {}, name), badge(st, text),
    h("span", { class: "d" }, c.detail || c.reason || c.error || (c.metrics ? Object.entries(c.metrics).filter(([, v]) => v !== null && v !== undefined)
      .slice(0, 3).map(([k, v]) => `${label(k)} ${typeof v === "number" ? int(v) : v}`).join(", ") : "")));
}

export const COMPONENT_NAMES = { api: "API", database: "Database connectivity", detector: "SQLi detection engine",
  dlp: "DLP engine", waf: "AWS WAF", cloudwatch: "CloudWatch", sns: "SNS notifications" };
