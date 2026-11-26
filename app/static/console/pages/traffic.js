import { h, clear, debounce } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api, qs } from "../lib/api.js";
import { pageHead, segmented, switchControl, badge } from "../lib/ui.js";
import { ribbon } from "../lib/charts.js";
import { dataTable } from "../lib/table.js";
import { dateTime, int } from "../lib/fmt.js";
import { verdictBadge, openRequestDrawer } from "./shared.js";

export default async function traffic(ctx) {
  // Deep link: #/traffic/ip/1.2.3.4
  const f = { verdict: "", ip: ctx.params[0] === "ip" ? ctx.params[1] || "" : "", endpoint: "",
    q: ctx.params[0] === "q" ? ctx.params[1] || "" : "" };
  let live = true, timer = null, latestId = null;
  const liveNote = h("span", { class: "faint small", "aria-live": "polite" });

  const table = dataTable({
    caption: "Incoming HTTP requests",
    columns: [
      { label: "Time", render: (r) => h("span", { class: "num nowrap", title: r.ts }, dateTime(r.ts)) },
      { label: "Source IP", render: (r) => h("button", { class: "btn sm ghost num", type: "button", title: "Filter by this IP",
        onclick: () => { f.ip = r.client_ip; ipInput.value = r.client_ip; table.reload(); } }, r.client_ip) },
      { label: "Method", render: (r) => h("span", { class: "method" }, r.method) },
      { label: "Endpoint", cls: "trunc mono", render: (r) => h("span", { title: r.path }, r.path) },
      { label: "User agent", cls: "trunc", render: (r) => h("span", { class: "faint", title: r.user_agent || "" }, r.user_agent || "—") },
      { label: "Score", cls: "r", render: (r) => h("span", { class: "num" }, String(r.score)) },
      { label: "Verdict", render: (r) => verdictBadge(r.verdict, r.status) },
      { label: "Detection reason", cls: "trunc", render: (r) => reason(r) },
    ],
    fetch: async ({ page }) => {
      const d = await api(`/api/traffic${qs({ page, page_size: 25, ...f })}`);
      latestId = d.latest_id;
      return d;
    },
    onRow: (r) => openRequestDrawer(r.id, ctx),
    emptyTitle: "No requests match these filters",
    emptyText: "Clear a filter, or browse the records desk to generate traffic.",
  });

  function reason(r) {
    if (r.source === "blocklist") return "Source on administrator blocklist";
    if (r.source === "rate-limit") return "API rate limit exceeded";
    if (!r.rule_ids.length) return h("span", { class: "faint" }, r.status >= 400 ? `HTTP ${r.status}` : "No rule matched");
    return `${r.category_label ? r.category_label + ": " : ""}${r.rule_ids.join(", ")}`;
  }

  const verdictSeg = segmented([{ value: "", label: "All" }, { value: "normal", label: "Allowed" },
    { value: "suspicious", label: "Suspicious" }, { value: "blocked", label: "Blocked" }], "", (v) => { f.verdict = v; table.reload(); }, "Verdict");
  const ipInput = h("input", { class: "input", type: "search", placeholder: "Source IP", value: f.ip, "aria-label": "Filter by source IP",
    oninput: debounce((e) => { f.ip = e.target.value.trim(); table.reload(); }) });
  const epInput = h("input", { class: "input", type: "search", placeholder: "Endpoint contains", "aria-label": "Filter by endpoint",
    oninput: debounce((e) => { f.endpoint = e.target.value.trim(); table.reload(); }) });
  const qInput = h("input", { class: "input grow", type: "search", placeholder: "Search path, user agent, matched input or rule ID",
    "aria-label": "Search request history", value: f.q, oninput: debounce((e) => { f.q = e.target.value.trim(); table.reload(); }) });

  const rib = ribbon([], { onPick: (it) => openRequestDrawer(it.id, ctx) });
  const ribbonCard = h("section", { class: "card" },
    h("div", { class: "card-head" }, h("div", {}, h("h2", {}, "Request ribbon"),
      h("p", { class: "sub" }, "Last 200 requests, oldest on the left. Height and colour show the verdict; select a tick to open it.")),
    h("div", { class: "legend" }, [["#3b5a78", "Allowed"], ["#f59e0b", "Suspicious"], ["#ef4444", "Blocked"]].map(([c, t]) =>
      h("span", { class: "chip", style: { gap: "6px", "font-family": "var(--sans)" } }, h("i", { style: { width: "8px", height: "8px", background: c, "border-radius": "2px" } }), t)))),
    h("div", { class: "card-body" }, rib));

  async function loadRibbon() {
    try {
      const d = await api("/api/traffic?page_size=100");
      const d2 = d.total > 100 ? await api("/api/traffic?page_size=100&page=2") : { items: [] };
      rib.update([...d.items, ...d2.items].reverse());
    } catch { /* table shows the error */ }
  }

  async function poll() {
    if (!live || document.hidden) return;
    try {
      const d = await api(`/api/traffic?page_size=5&since_id=${latestId ?? 0}`);
      if (d.total) {
        liveNote.textContent = `${int(d.total)} new request${d.total === 1 ? "" : "s"}`;
        latestId = d.latest_id;
        table.refresh();
        loadRibbon();
      } else liveNote.textContent = "Watching for new requests";
    } catch { liveNote.textContent = "Live updates paused: the server did not answer"; }
  }

  const el = h("div", { class: "page" },
    pageHead("Live Traffic Monitor", "Every request the application inspected, with its detection score and verdict. Requests blocked by AWS WAF never reach the app; see AWS Infrastructure for those.",
      [liveNote, switchControl("Live", live, (v) => { live = v; liveNote.textContent = v ? "Watching for new requests" : "Paused"; })]),
    ribbonCard,
    h("section", { class: "card mt" },
      h("div", { class: "filters" }, verdictSeg, ipInput, epInput, qInput,
        h("button", { class: "btn sm ghost", type: "button", onclick: () => {
          Object.assign(f, { verdict: "", ip: "", endpoint: "", q: "" });
          verdictSeg.set(""); ipInput.value = ""; epInput.value = ""; qInput.value = "";
          table.reload();
        } }, icon("x"), "Clear")),
      table.el));

  table.load();
  loadRibbon();
  timer = setInterval(poll, 5000);
  if (ctx.params[0] === "ip") ctx.setCrumb(`Source ${f.ip}`);
  if (ctx.params[0] === "q") ctx.setCrumb(`Search ${f.q}`);
  return { el, destroy() { clearInterval(timer); rib.destroy(); } };
}
