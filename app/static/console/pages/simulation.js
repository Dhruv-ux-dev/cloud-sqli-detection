import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, b64, qs } from "../lib/api.js";
import { card, pageHead, loading, errorState, toast, badge, emptyState } from "../lib/ui.js";
import { dataTable } from "../lib/table.js";
import { dateTime, micros } from "../lib/fmt.js";
import { verdictBadge, explanationBlock } from "./shared.js";

export default async function simulation(ctx) {
  let presets;
  try { presets = await api("/api/simulations/presets"); } catch (err) {
    return { el: h("div", { class: "page" }, errorState(err.message)) };
  }
  let category = "union";
  const compare = new Map(); // id -> result
  const results = h("div", { class: "stack" }, emptyState("No simulation yet",
    "Pick a test case or write your own payload, choose a target and run it. The result appears here."));

  // ---------------------------------------------------------------- configuration
  const payload = h("textarea", { class: "textarea mono", id: "sim-payload", rows: 4, maxlength: 2000, spellcheck: "false",
    placeholder: "Type or pick a payload" });
  const target = h("select", { class: "select", id: "sim-target" }, presets.targets.map((t) => h("option", { value: t.key }, t.label)));
  const presetBox = h("div", { class: "preset-list" });
  const chips = h("div", { class: "cat-chips", role: "group", "aria-label": "Attack category" });
  const run = h("button", { class: "btn primary", type: "submit" }, icon("play"), "Run simulation");

  function drawChips() {
    clear(chips, presets.categories.map((c) => h("button", { type: "button", "aria-pressed": String(c.key === category),
      onclick: () => { category = c.key; drawChips(); drawPresets(); } }, c.label)));
  }
  function drawPresets() {
    const c = presets.categories.find((x) => x.key === category);
    clear(presetBox, c.payloads.map((p) => h("button", { class: "preset", type: "button",
      onclick: () => { payload.value = p; if (category === "auth_bypass") target.value = "login"; payload.focus(); } }, p)));
  }
  drawChips();
  drawPresets();

  const form = h("form", { class: "stack", style: { gap: "14px" }, onsubmit: async (e) => {
    e.preventDefault();
    if (!payload.value.trim()) { toast("Enter or pick a payload first.", "info"); payload.focus(); return; }
    run.disabled = true;
    clear(results, loading(6));
    try {
      const r = await api("/api/simulations", { method: "POST", body: {
        category: presets.categories.some((c) => c.payloads.includes(payload.value)) ? category : "custom",
        target: target.value, payload_b64: b64(payload.value) } });
      renderResult(r);
      history.reload();
    } catch (err) {
      clear(results, errorState(err.message));
    } finally { run.disabled = false; }
  } },
  h("div", { class: "field" }, h("span", { class: "label" }, "Attack category"), chips),
  h("div", { class: "field" }, h("span", { class: "label" }, "Test cases"), presetBox),
  h("div", { class: "field" }, h("label", { for: "sim-payload" }, "Payload (editable)"), payload),
  h("div", { class: "field" }, h("label", { for: "sim-target" }, "Target (safe demo endpoints only)"), target),
  h("div", {}, run));

  // ---------------------------------------------------------------- result
  function renderResult(r) {
    const hero = h("div", { class: `verdict-hero ${r.decision}` },
      h("span", { class: "big" }, { block: "BLOCKED", flag: "FLAGGED", allow: "ALLOWED" }[r.decision]),
      h("div", { class: "stack", style: { gap: "2px" } },
        h("span", { class: "small" }, `Score ${r.score}. ${r.detected_category || "No attack category"}.`),
        h("span", { class: "faint tiny" }, `Enforced by: ${r.enforced_by}`)),
      h("div", { style: { "margin-left": "auto", "text-align": "right" } },
        h("span", { class: "num small" }, micros(r.timings_us.total)), h("p", { class: "faint tiny" }, "processing time")));

    const pipe = h("div", { class: "pipeline", role: "list", "aria-label": "Request processing pipeline" },
      r.pipeline.map((st, i) => h("div", { class: `stage ${st.status}`, role: "listitem", style: { "animation-delay": `${i * 90}ms` } },
        h("span", { class: "n" }, String(i + 1)), h("strong", {}, st.stage), h("p", {}, st.detail),
        st.us ? h("span", { class: "us" }, micros(st.us)) : null)));
    requestAnimationFrame(() => pipe.querySelectorAll(".stage").forEach((s) => s.classList.add("lit")));

    clear(results,
      hero,
      card({ title: "Processing pipeline", sub: "Input → normalisation → detection → scoring → policy → decision → audit", body: pipe }),
      card({ title: "Detection result", body: h("div", { class: "stack", style: { gap: "14px" } },
        h("div", { class: "grid g-2 keep" },
          h("div", {}, h("div", { class: "section-title" }, "Payload as sent"), h("pre", { class: "payload" }, r.payload)),
          h("div", {}, h("div", { class: "section-title" }, "After normalisation"), h("pre", { class: "payload" }, r.normalised || "(empty)"))),
        explanationBlock(r.explanation, { score: r.score, thresholds: r.thresholds, reason: r.reason })) }),
      card({ title: "Recorded security event", body: h("dl", { class: "kv" },
        h("dt", {}, "Simulation"), h("dd", { class: "mono" }, `SIM-${r.id}`),
        h("dt", {}, "Audit record"), h("dd", {}, r.audit_id ? h("a", { href: `#/audit/${r.audit_id}`, class: "mono" }, `AUD-${String(r.audit_id).padStart(7, "0")}`) : "not written"),
        h("dt", {}, "Time"), h("dd", {}, dateTime(r.ts)),
        h("dt", {}, "Would the app block it?"), h("dd", {}, r.would_block ? "Yes, with 403 before any query runs" : r.verdict === "suspicious" ? "No: served and flagged" : "No"),
        h("dt", {}, "AWS WAF"), h("dd", { class: "small" }, "Not simulated. In a deployment, WAF evaluates real traffic before the app; its decisions appear on the AWS Infrastructure page.")) }));
  }

  // ---------------------------------------------------------------- history and comparison
  const compareBox = h("div");
  const history = dataTable({
    caption: "Simulation history",
    columns: [
      { label: "Compare", render: (r) => h("input", { type: "checkbox", "aria-label": `Compare SIM-${r.id}`, checked: compare.has(r.id) ? true : null,
        onchange: (e) => { if (e.target.checked) { if (compare.size >= 4) { e.target.checked = false; toast("Compare up to four runs.", "info"); return; } compare.set(r.id, r); } else compare.delete(r.id); drawCompare(); } }) },
      { label: "Run", render: (r) => h("span", { class: "mono" }, `SIM-${r.id}`) },
      { label: "When", render: (r) => h("span", { class: "nowrap" }, dateTime(r.ts)) },
      { label: "By", render: (r) => r.username },
      { label: "Target", render: (r) => r.target },
      { label: "Payload", cls: "trunc mono", render: (r) => h("span", { title: r.payload }, r.payload) },
      { label: "Detected as", render: (r) => r.detected_label || h("span", { class: "faint" }, "—") },
      { label: "Score", cls: "r", render: (r) => String(r.score) },
      { label: "Result", render: (r) => r.would_block ? badge("blocked", "Blocked") : verdictBadge(r.verdict) },
    ],
    fetch: ({ page }) => api(`/api/simulations${qs({ page, page_size: 10 })}`),
    onRow: (r) => { payload.value = r.payload; target.value = r.target; payload.scrollIntoView({ block: "center" }); payload.focus(); },
    emptyTitle: "No simulations yet",
  });

  function drawCompare() {
    const runs = [...compare.values()];
    if (runs.length < 2) { clear(compareBox, runs.length ? h("p", { class: "muted small", style: { padding: "0 16px 14px" } }, "Select one more run to compare.") : null); return; }
    const rows = [
      ["Payload", (r) => h("code", {}, r.payload)], ["Target", (r) => r.target], ["Detected as", (r) => r.detected_label || "—"],
      ["Score", (r) => h("b", { class: "num" }, String(r.score))], ["Rules", (r) => r.rule_ids.join(", ") || "none"],
      ["Result", (r) => r.would_block ? badge("blocked", "Blocked") : verdictBadge(r.verdict)], ["Detector time", (r) => micros(r.duration_us)],
    ];
    clear(compareBox, h("div", { class: "table-wrap", style: { padding: "0 0 8px" } }, h("table", { class: "data" },
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, ""), runs.map((r) => h("th", { scope: "col" }, `SIM-${r.id}`)))),
      h("tbody", {}, rows.map(([k, f]) => h("tr", {}, h("th", { scope: "row" }, k), runs.map((r) => h("td", {}, f(r)))))))));
  }

  const el = h("div", { class: "page" },
    pageHead("Attack Simulation Lab", "Run SQL injection test cases through the real detection engine and see every stage of the decision."),
    h("div", { class: "banner warn", role: "note" }, icon("alert"),
      h("div", {}, h("strong", {}, "Isolated testing only. "),
        `Payloads are evaluated by the detector inside this app: no HTTP request is sent, no SQL is executed and no customer data is touched. Run live attack traffic (tools/sqli_test.py) only against your own local or test deployment. Environment: ${presets.environment}, WAF mode: ${presets.waf_mode}.`)),
    h("div", { class: "grid g-1-2 mt", style: { "align-items": "start" } },
      card({ title: "Attack configuration", body: form }),
      h("div", { class: "stack" }, h("h2", { class: "sr-only" }, "Simulation results"), results)),
    h("section", { class: "card mt" },
      h("div", { class: "card-head" }, h("div", {}, h("h2", {}, "Simulation history"),
        h("p", { class: "sub" }, "Tick two to four runs to compare them side by side. Select a row to load it again."))),
      compareBox, history.el));

  history.load();
  return { el };
}
