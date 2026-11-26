import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api } from "../lib/api.js";
import { card, pageHead, loading, errorState, toast, badge, drawer, formModal, segmented } from "../lib/ui.js";
import { columns, COLORS } from "../lib/charts.js";
import { int, dateTime, ago } from "../lib/fmt.js";
import { sevBadge } from "./shared.js";

export default async function detection(ctx) {
  const el = h("div", { class: "page" }, loading(8));
  let rules = [], filter = "all", sortKey = "weight", charts = [];

  async function load() {
    try {
      const [r, st] = await Promise.all([api("/api/detection/rules"), api("/api/detection/stats")]);
      rules = r.items;
      render(r, st);
      if (ctx.params[0]) {
        const rule = rules.find((x) => x.id === ctx.params[0]);
        if (rule) openRule(rule, r.can_manage);
      }
    } catch (err) { clear(el, errorState(err.message, load)); }
  }

  function render(r, st) {
    charts.forEach((c) => c.destroy?.());
    const kpi = (labelText, value, sub) => h("section", { class: "card kpi" }, h("div", { class: "kpi-top" }, labelText),
      h("div", { class: "kpi-value num" }, value), h("div", { class: "kpi-foot" }, sub));
    const engine = st.engine;
    const tableBody = h("tbody");
    const drawTable = () => {
      const rows = rules.filter((x) => filter === "all" || (filter === "enabled" ? x.enabled : !x.enabled))
        .sort((a, b) => sortKey === "weight" ? b.weight - a.weight : sortKey === "matches" ? b.matches_30d - a.matches_30d : a.id.localeCompare(b.id));
      clear(tableBody, rows.map((x) => h("tr", { class: "clickable", tabindex: "0", onclick: () => openRule(x, r.can_manage),
        onkeydown: (e) => { if (e.key === "Enter") openRule(x, r.can_manage); } },
      h("td", {}, h("span", { class: "chip" }, x.id)), h("td", {}, x.name), h("td", {}, x.category_label),
      h("td", {}, sevBadge(x.severity)), h("td", { class: "num r" }, `+${x.weight}`),
      h("td", { class: "num r" }, int(x.matches_30d)), h("td", { class: "nowrap faint" }, x.last_matched ? ago(x.last_matched) : "never"),
      h("td", {}, x.enabled ? badge("enforced", "Enabled") : badge("informational", "Disabled")))));
    };
    drawTable();
    const hist = columns(st.score_distribution.map((b) => ({ label: b.bucket, value: b.n,
      color: b.lo >= st.thresholds.block ? COLORS.blocked : b.lo >= st.thresholds.suspicious ? COLORS.suspicious : b.lo > 0 ? "#64748b" : COLORS.normal })));
    charts.push(hist);

    clear(el,
      pageHead("SQL Injection Detection", "The application's own detection engine: 16 weighted signatures applied to every request after decoding. In AWS it sits behind AWS WAF as the second layer."),
      h("div", { class: "grid g-6" },
        kpi("Detection rules", int(st.rules_total), "signatures in the engine"),
        kpi("Active rules", int(st.rules_active), "applied to every request"),
        kpi("Disabled rules", int(st.rules_disabled), st.rules_disabled ? "switched off by an administrator" : "none switched off"),
        kpi("Pattern matches", int(st.pattern_matches_30d), "rule matches, last 30 days"),
        kpi("Requests flagged", int(st.requests_flagged_30d), `of ${int(st.requests_inspected_30d)} logged, 30 days`),
        h("section", { class: "card kpi" }, h("div", { class: "kpi-top" }, "Engine health"),
          h("div", {}, badge(engine.status, engine.status === "healthy" ? "Healthy" : "Failing")),
          h("div", { class: "kpi-foot" }, h("span", { class: "tiny" }, engine.detail)))),
      h("div", { class: "grid g-2 mt" },
        card({ title: "How requests are classified", body: h("div", { class: "stack", style: { gap: "12px" } },
          h("div", { class: "grid g-3", style: { gap: "8px" } },
            [["Normal", `score 0–${st.thresholds.suspicious - 1}`, "allowed"], ["Suspicious", `score ${st.thresholds.suspicious}–${st.thresholds.block - 1}`, "suspicious"],
              ["Blocked", `score ${st.thresholds.block}+`, "blocked"]].map(([t, s, c]) =>
              h("div", { class: "contrib-item" }, badge(c, t), h("span", { class: "num small" }, s)))),
          h("ul", { class: "stack small", style: { gap: "8px", "padding-left": "18px", margin: 0, color: "var(--text-2)" } },
            st.thresholds.explanation.map((t) => h("li", {}, t))),
          h("p", { class: "small" }, h("strong", {}, "Current enforcement: "), st.enforcement)) }),
        card({ title: "Detection score distribution", sub: "Requests by score, last 30 days. Colours follow the thresholds.", body: hist })),
      h("section", { class: "card mt" },
        h("div", { class: "card-head" }, h("div", {}, h("h2", {}, "Detection rules"), h("p", { class: "sub" }, "Select a rule to inspect its pattern and history.")),
          h("div", { class: "page-actions" },
            segmented([{ value: "all", label: "All" }, { value: "enabled", label: "Enabled" }, { value: "disabled", label: "Disabled" }], filter,
              (v) => { filter = v; drawTable(); }, "Rule filter"),
            h("label", { class: "small muted", for: "rule-sort" }, "Sort"),
            h("select", { class: "select", id: "rule-sort", onchange: (e) => { sortKey = e.target.value; drawTable(); } },
              h("option", { value: "weight" }, "Weight"), h("option", { value: "matches" }, "Matches"), h("option", { value: "id" }, "Rule ID")))),
        h("div", { class: "card-body flush" }, h("div", { class: "table-wrap" }, h("table", { class: "data" },
          h("caption", { class: "sr-only" }, "Detection rules"),
          h("thead", {}, h("tr", {}, ["Rule", "Name", "Attack category", "Severity", "Weight", "Matches (30 d)", "Last match", "Status"]
            .map((t, i) => h("th", { scope: "col", class: i === 4 || i === 5 ? "r" : null }, t)))),
          tableBody)))));
  }

  function openRule(x, canManage) {
    const d = drawer({ title: `${x.id}: ${x.name}`, subtitle: `${x.category_label}, weight +${x.weight}`,
      body: h("div", { class: "stack", style: { gap: "16px" } },
        h("div", { style: { display: "flex", gap: "8px" } }, sevBadge(x.severity), x.enabled ? badge("enforced", "Enabled") : badge("informational", "Disabled")),
        h("p", {}, x.explanation),
        h("dl", { class: "kv" },
          h("dt", {}, "Applies to"), h("dd", {}, x.scope),
          h("dt", {}, "Weight"), h("dd", {}, `+${x.weight} toward the score`),
          h("dt", {}, "Matches"), h("dd", {}, `${int(x.matches_24h)} in 24 h, ${int(x.matches_30d)} in 30 days`),
          h("dt", {}, "Last match"), h("dd", {}, x.last_matched ? dateTime(x.last_matched) : "never"),
          h("dt", {}, "Last change"), h("dd", {}, x.changed_by ? `${x.enabled ? "Enabled" : "Disabled"} by ${x.changed_by}, ${dateTime(x.changed_at)}` : "Never changed")),
        h("div", {}, h("div", { class: "section-title" }, "Pattern (regular expression, case-insensitive)"), h("pre", { class: "payload" }, x.pattern)),
        h("a", { class: "btn sm", href: `#/traffic/q/${encodeURIComponent(x.id)}` }, icon("activity"), "Show requests that matched this rule")),
      footer: canManage ? [h("button", { class: `btn ${x.enabled ? "danger" : "primary"}`, type: "button", onclick: () => formModal({
        title: `${x.enabled ? "Disable" : "Enable"} ${x.id}?`,
        description: x.enabled ? "Requests will no longer gain this rule's weight. Scores and verdicts change immediately for new traffic." : "The rule will score new traffic again.",
        fields: [{ name: "reason", label: "Reason (recorded in the audit log)", type: "textarea", required: true, maxlength: 300 }],
        submitLabel: x.enabled ? "Disable rule" : "Enable rule", danger: x.enabled,
        onSubmit: async (v) => {
          await api(`/api/detection/rules/${x.id}`, { method: "PATCH", body: { enabled: !x.enabled, reason: v.reason } });
          toast(`${x.id} ${x.enabled ? "disabled" : "enabled"}.`);
          d.close();
          load();
        } }) }, x.enabled ? "Disable rule" : "Enable rule")] : [h("span", { class: "faint small" }, "Only administrators can change rules.")] });
  }

  load();
  return { el, destroy() { charts.forEach((c) => c.destroy?.()); } };
}
