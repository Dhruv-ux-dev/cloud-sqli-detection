import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, download, qs } from "../lib/api.js";
import { card, pageHead, loading, errorState, toast, badge } from "../lib/ui.js";
import { dataTable } from "../lib/table.js";
import { dateTime, fullDateTime, int, label } from "../lib/fmt.js";
import { sevBadge, statusBadge, verdictBadge, explanationBlock, requestDetail, blockButton, ipLink } from "./shared.js";

export default async function investigate(ctx) {
  const [kind, id] = ctx.params;
  if (kind === "incident" && id) return incidentView(ctx, Number(id));
  if (kind === "request" && id) return requestView(ctx, Number(id));
  return landing(ctx);
}

// ---------------------------------------------------------------- landing

function landing(ctx) {
  const incidents = dataTable({
    caption: "Open incidents",
    columns: [
      { label: "Incident", render: (r) => h("span", { class: "mono" }, r.ref) },
      { label: "Severity", sort: "severity", render: (r) => sevBadge(r.severity) },
      { label: "Summary", cls: "trunc", render: (r) => h("span", { title: r.summary }, r.summary) },
      { label: "Last activity", sort: "last_seen", render: (r) => dateTime(r.last_seen_at) },
      { label: "Status", render: (r) => statusBadge(r.status) },
    ],
    sort: "severity",
    fetch: ({ page, sort, order }) => api(`/api/incidents${qs({ page, page_size: 10, sort, order, status: "new,investigating" })}`),
    onRow: (r) => ctx.navigate(`investigate/incident/${r.id}`),
    emptyTitle: "No open incidents", emptyText: "Nothing is waiting for triage.",
  });
  const requests = dataTable({
    caption: "Recent flagged requests",
    columns: [
      { label: "Request", render: (r) => h("span", { class: "mono" }, r.ref) },
      { label: "Source", render: (r) => r.client_ip },
      { label: "Endpoint", cls: "trunc mono", render: (r) => `${r.method} ${r.path}` },
      { label: "Score", cls: "r", render: (r) => String(r.score) },
      { label: "Verdict", render: (r) => verdictBadge(r.verdict, r.status) },
    ],
    fetch: async ({ page }) => {
      const [b, s] = await Promise.all([
        api(`/api/traffic${qs({ page, page_size: 10, verdict: "blocked" })}`),
        api(`/api/traffic${qs({ page: 1, page_size: 5, verdict: "suspicious" })}`),
      ]);
      const items = [...b.items, ...(page === 1 ? s.items : [])].sort((x, y) => y.id - x.id);
      return { ...b, items };
    },
    onRow: (r) => ctx.navigate(`investigate/request/${r.id}`),
    emptyTitle: "No flagged requests yet",
  });
  incidents.load();
  requests.load();
  return { el: h("div", { class: "page" },
    pageHead("Attack Investigation", "Pick an incident or a flagged request to see the detection evidence, the event timeline and the response actions."),
    h("div", { class: "grid g-2" },
      h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Open incidents")), h("div", { class: "card-body flush" }, incidents.el)),
      h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Recent flagged requests")), h("div", { class: "card-body flush" }, requests.el)))) };
}

// ---------------------------------------------------------------- incident

async function incidentView(ctx, id) {
  const el = h("div", { class: "page" }, loading(8));
  const ref = `INC-${String(id).padStart(6, "0")}`;
  ctx.setCrumb(ref);
  let assignees = [];
  if (ctx.can("incidents:manage")) {
    try { assignees = (await api("/api/users/assignable")).items; } catch { /* optional */ }
  }

  async function load() {
    let d;
    try { d = await api(`/api/incidents/${id}`); } catch (err) { clear(el, errorState(err.message, load)); return; }
    render(d);
  }

  function render(d) {
    const e = d.explanation;
    const overview = h("section", { class: "card pad" },
      h("div", { style: { display: "flex", "justify-content": "space-between", gap: "16px", "flex-wrap": "wrap", "align-items": "flex-start" } },
        h("div", { class: "stack", style: { gap: "8px" } },
          h("div", { style: { display: "flex", gap: "8px", "align-items": "center", "flex-wrap": "wrap" } },
            h("span", { class: "mono", style: { color: "var(--accent)" } }, d.ref), sevBadge(d.severity), statusBadge(d.status),
            d.source_blocked ? badge("blocked", "Source blocked") : null),
          h("h1", {}, d.summary)),
        h("div", { class: "page-actions" },
          ctx.can("reports:export") ? h("button", { class: "btn", type: "button", onclick: async () => {
            try { toast(`Downloaded ${await download(`/api/incidents/${id}/report`, `${d.ref}.md`)}`); } catch (err) { toast(err.message, "err"); }
          } }, icon("download"), "Export report") : null,
          d.client_ip ? h("a", { class: "btn", href: `#/traffic/ip/${encodeURIComponent(d.client_ip)}` }, icon("activity"), "Related requests") : null)),
      h("dl", { class: "kv", style: { "margin-top": "16px", "grid-template-columns": "repeat(4, max-content 1fr)" } },
        h("dt", {}, "Category"), h("dd", {}, d.category_label),
        h("dt", {}, "Attack"), h("dd", {}, e?.attack || "—"),
        h("dt", {}, "Source IP"), h("dd", {}, d.client_ip ? ipLink(d.client_ip) : "—"),
        h("dt", {}, "User"), h("dd", {}, d.username || "—"),
        h("dt", {}, "Target endpoint"), h("dd", { class: "mono" }, d.endpoint || "—"),
        h("dt", {}, "Opened"), h("dd", {}, fullDateTime(d.ts)),
        h("dt", {}, "Last activity"), h("dd", {}, fullDateTime(d.last_seen_at)),
        h("dt", {}, "Occurrences"), h("dd", { class: "num" }, int(d.occurrences))));

    const details = card({ title: "Attack details", sub: e ? `Evidence from ${e.request_ref}, the highest-scoring related request` : null,
      body: e ? h("dl", { class: "kv" },
        h("dt", {}, "HTTP method"), h("dd", {}, h("span", { class: "method" }, e.method)),
        h("dt", {}, "Endpoint"), h("dd", { class: "mono" }, e.endpoint),
        h("dt", {}, "Matched input"), h("dd", {}, h("pre", { class: "payload" }, e.sample || "—")),
        h("dt", {}, "Matched patterns"), h("dd", {}, e.contributions.map((c) => h("span", { class: "chip", style: { "margin": "0 4px 4px 0" } }, c.rule_id))),
        h("dt", {}, "Detection score"), h("dd", { class: "num" }, String(e.score)),
        h("dt", {}, "Thresholds"), h("dd", {}, `suspicious at ${e.thresholds.suspicious}, blocked at ${e.thresholds.block}`),
        h("dt", {}, "Final verdict"), h("dd", {}, verdictBadge(e.verdict)),
        h("dt", {}, "Request"), h("dd", {}, h("a", { href: `#/investigate/request/${e.request_id}` }, e.request_ref)))
        : h("p", { class: "muted small" }, d.client_ip ? "No flagged requests from this source around the incident time. This incident came from account or data-access activity rather than injected input."
          : "This incident is about user activity, not a single request.") });

    const explanation = card({ title: "Detection explanation",
      body: e ? explanationBlock(e.contributions, { score: e.score, thresholds: e.thresholds, reason: e.reason })
        : h("p", { class: "muted small" }, "There is no detector evidence for this incident type. See the summary and timeline.") });

    const timeline = card({ title: "Event timeline", sub: `${d.timeline.length} events, oldest first`,
      body: h("ol", { class: "timeline" }, d.timeline.map((t) => h("li", { class: t.type },
        h("span", { class: "when" }, fullDateTime(t.ts)),
        h("strong", {}, t.title, t.ref && t.ref.startsWith("REQ") ? h("a", { href: `#/investigate/request/${Number(t.ref.slice(4))}`, style: { "margin-left": "6px", "font-weight": "400" } }, t.ref) : null),
        h("p", {}, t.detail)))) });

    const actions = actionsCard(d);
    const notes = card({ title: "Investigation notes", body: d.notes.filter((n) => n.kind === "note").length
      ? h("ul", { class: "health-list" }, d.notes.filter((n) => n.kind === "note").map((n) =>
        h("li", { style: { "grid-template-columns": "1fr" } }, h("div", {}, h("strong", { class: "small" }, n.author), h("span", { class: "faint tiny" }, ` ${fullDateTime(n.ts)}`),
          h("p", { class: "small", style: { "white-space": "pre-wrap", "margin-top": "4px" } }, n.body)))))
      : h("p", { class: "muted small" }, "No notes yet.") });

    const related = card({ title: "Related requests", sub: "Flagged requests from the same source around this incident",
      body: d.related_requests.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, ["Time", "Request", "Endpoint", "Score", "Verdict", "Rules"].map((t) => h("th", { scope: "col" }, t)))),
        h("tbody", {}, d.related_requests.map((r) => h("tr", { class: "clickable", tabindex: "0", onclick: () => ctx.navigate(`investigate/request/${r.id}`) },
          h("td", { class: "num nowrap" }, dateTime(r.ts)), h("td", { class: "mono" }, r.ref),
          h("td", { class: "trunc mono" }, `${r.method} ${r.path}`), h("td", { class: "num" }, String(r.score)),
          h("td", {}, verdictBadge(r.verdict, r.status)), h("td", { class: "trunc" }, r.rule_ids.join(", ")))))))
        : h("p", { class: "muted small" }, "None.") });

    clear(el, overview,
      h("div", { class: "grid g-2-1 mt" }, h("div", { class: "stack" }, details, explanation, related), h("div", { class: "stack" }, actions, timeline, notes)));
  }

  function actionsCard(d) {
    if (!ctx.can("incidents:manage")) {
      return card({ title: "Investigation actions", body: h("p", { class: "muted small" }, "Your role can view incidents but not change them.") });
    }
    const status = h("select", { class: "select", id: "inc-status" }, d.statuses.map((s) =>
      h("option", { value: s, selected: s === d.status ? true : null }, s === "false_positive" ? "False positive" : label(s))));
    const assignee = h("select", { class: "select", id: "inc-assign" },
      h("option", { value: "" }, "Unassigned"),
      assignees.map((a) => h("option", { value: a.username, selected: a.username === d.assigned_to ? true : null }, `${a.display_name || a.username} (${a.role})`)));
    const note = h("textarea", { class: "textarea", id: "inc-note", rows: 3, maxlength: 2000, placeholder: "What you found, what you did, what is next" });
    const save = h("button", { class: "btn primary", type: "button", onclick: async () => {
      const body = {};
      if (status.value !== d.status) body.status = status.value;
      if ((assignee.value || null) !== (d.assigned_to || null)) body.assigned_to = assignee.value;
      if (note.value.trim()) body.note = note.value.trim();
      if (!Object.keys(body).length) { toast("Change the status, the assignee or add a note first.", "info"); return; }
      save.disabled = true;
      try {
        await api(`/api/incidents/${id}`, { method: "PATCH", body });
        toast("Incident updated. The change is in the audit log.");
        load();
      } catch (err) { toast(err.message, "err"); save.disabled = false; }
    } }, "Save changes");
    const quick = (st, text) => h("button", { class: "btn sm", type: "button", disabled: d.status === st ? true : null, onclick: async () => {
      try { await api(`/api/incidents/${id}`, { method: "PATCH", body: { status: st } }); toast(`Marked as ${text.toLowerCase()}.`); load(); }
      catch (err) { toast(err.message, "err"); }
    } }, text);
    return card({ title: "Investigation actions", body: h("div", { class: "stack", style: { gap: "12px" } },
      h("div", { class: "page-actions" }, quick("investigating", "Investigating"), quick("resolved", "Resolved"), quick("false_positive", "False positive")),
      h("div", { class: "field" }, h("label", { for: "inc-status" }, "Status"), status),
      h("div", { class: "field" }, h("label", { for: "inc-assign" }, "Assigned to"), assignee),
      h("div", { class: "field" }, h("label", { for: "inc-note" }, "Add a note"), note),
      h("div", { class: "page-actions" }, save,
        d.client_ip && ctx.can("blocklist:manage") && !d.source_blocked ? blockButton(d.client_ip, d.id, load) : null),
      d.source_blocked ? h("p", { class: "small muted" }, `Source blocked by ${d.source_blocked.created_by}, ${fullDateTime(d.source_blocked.created_at)}. Manage it under Security policies.`) : null) });
  }

  load();
  return { el };
}

// ---------------------------------------------------------------- request

async function requestView(ctx, id) {
  const ref = `REQ-${String(id).padStart(7, "0")}`;
  ctx.setCrumb(ref);
  const el = h("div", { class: "page" }, loading(8));
  async function load() {
    let r;
    try { r = await api(`/api/traffic/${id}`); } catch (err) { clear(el, errorState(err.message, load)); return; }
    clear(el,
      pageHead(`${ref}: ${r.method} ${r.path}`, `From ${r.client_ip}, ${fullDateTime(r.ts)}`,
        [ctx.can("blocklist:manage") && r.verdict !== "normal" ? blockButton(r.client_ip, null, load) : null,
          h("a", { class: "btn", href: `#/traffic/ip/${encodeURIComponent(r.client_ip)}` }, icon("activity"), "All traffic from this source")]),
      h("div", { class: "grid g-2-1" },
        card({ title: "Request and detection", body: requestDetail(r, ctx) }),
        card({ title: "Source activity", sub: "Other requests from this IP within 30 minutes",
          body: r.related_requests.length ? h("ol", { class: "timeline" }, r.related_requests.map((n) => h("li", {
            class: n.verdict === "blocked" ? "blocked" : n.verdict === "suspicious" ? "attempt" : "" },
          h("span", { class: "when" }, fullDateTime(n.ts)),
          h("strong", {}, h("a", { href: `#/investigate/request/${n.id}` }, n.ref), ` ${n.method} ${n.path}`),
          h("p", {}, `Score ${n.score}, ${n.verdict}`))))
            : h("p", { class: "muted small" }, "No other requests from this source in that window.") })));
  }
  load();
  return { el };
}
