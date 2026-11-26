import { h, s, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api } from "../lib/api.js";
import { card, pageHead, loading, errorState, badge } from "../lib/ui.js";
import { int, num, dateTime, ago, label } from "../lib/fmt.js";

const STATUS_TEXT = { healthy: "Connected", degraded: "Degraded", error: "Error", down: "Down",
  not_connected: "Not connected", not_configured: "Not configured" };

export default async function infrastructure(ctx) {
  const el = h("div", { class: "page" }, loading(8));
  let timer;

  async function load() {
    let d;
    try { d = await api("/api/infra"); } catch (err) { clear(el, errorState(err.message, load)); return; }
    render(d);
  }

  function render(d) {
    const svc = Object.fromEntries(d.services.map((x) => [x.key, x]));
    const local = d.mode === "local";
    clear(el,
      pageHead("AWS Infrastructure", "The deployed architecture and the live state of every AWS service, read from AWS APIs. Nothing on this page is simulated.",
        [h("span", { class: `env ${local ? "local" : "production"}` }, local ? "LOCAL MODE" : `AWS ${d.region || ""}`),
          h("button", { class: "btn", type: "button", onclick: load }, icon("refresh"), "Recheck")]),
      local ? h("div", { class: "banner info", role: "note" }, icon("info"), h("div", {},
        h("strong", {}, "Local mode. "), "AWS WAF, the load balancer, EC2, CloudWatch and SNS are not connected to this run, so they are shown as not connected rather than with made-up figures. The database figures come from the local PostgreSQL container. Deploy with Terraform (infra/) to see live AWS data here."))
        : null,
      card({ title: "Architecture", sub: "Select a service to jump to its details. Dashed outline: not connected.", cls: "mt", body: diagram(svc) }),
      h("div", { class: "grid g-2 mt" }, d.services.map(serviceCard)),
      h("div", { class: "grid g-2 mt" },
        card({ title: "Terraform", body: h("dl", { class: "kv" },
          h("dt", {}, "Managed by Terraform"), h("dd", {}, d.terraform.managed ? "Yes" : "Not deployed"),
          h("dt", {}, "Definition"), h("dd", { class: "mono" }, d.terraform.path),
          h("dt", {}, "State"), h("dd", {}, d.terraform.detail)) }),
        card({ title: "Application metrics (last hour)", sub: "Measured by the app itself, in every mode", body: h("div", { class: "svc-metrics" },
          metric("Requests", int(d.local_metrics.requests)), metric("Blocked by app", int(d.local_metrics.blocked)),
          metric("Avg latency", d.local_metrics.avg_latency_ms !== null ? `${num(d.local_metrics.avg_latency_ms)} ms` : "—"),
          metric("Server errors", int(d.local_metrics.errors)),
          metric("Last notification", d.local_metrics.last_notification ? ago(d.local_metrics.last_notification.ts) : "none")) })));
  }

  function diagram(svc) {
    const W = 920, H = 300;
    const node = (key, x, y, w, title, sub) => {
      const st = key === "users" ? "client" : svc[key]?.status || "not_connected";
      const g = s("g", { class: `node ${st}`, transform: `translate(${x},${y})`, tabindex: "0", role: "link",
        "aria-label": `${title}: ${STATUS_TEXT[st] || st}`,
        onclick: () => document.getElementById(`svc-${key}`)?.scrollIntoView({ behavior: "smooth", block: "center" }),
        onkeydown: (e) => { if (e.key === "Enter") document.getElementById(`svc-${key}`)?.scrollIntoView({ block: "center" }); } },
      s("rect", { width: w, height: 58 }),
      s("text", { x: 14, y: 25, text: title }),
      s("text", { class: "s", x: 14, y: 43, text: sub || STATUS_TEXT[st] || st }),
      s("circle", { cx: w - 14, cy: 16, r: 4, fill: { healthy: "#22c55e", degraded: "#f59e0b", error: "#ef4444", down: "#ef4444", client: "#38bdf8" }[st] || "#64748b" }));
      return g;
    };
    const edge = (d, cls = "") => s("path", { class: `edge ${cls}`, d, "marker-end": "url(#arrow)" });
    const lbl = (x, y, t) => s("text", { class: "edge-label", x, y, text: t });
    const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Architecture: users to AWS WAF to load balancer to EC2 to RDS; logs to CloudWatch; alarms to SNS" },
      s("defs", {}, s("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" },
        s("path", { d: "M0,0 L10,5 L0,10 z", fill: "#324360" }))),
      edge("M120 70 H168"), lbl(128, 60, "HTTP"),
      edge("M318 70 H366"), lbl(322, 60, "allowed"),
      edge("M516 70 H564"),
      edge("M714 70 H762"), lbl(724, 60, "SQL"),
      edge("M243 99 V200 H366", "log"), lbl(250, 160, "WAF logs"),
      edge("M639 99 V200 H516", "log"), lbl(560, 160, "app logs"),
      edge("M837 99 V230 H516", "log"), lbl(760, 160, "DB logs"),
      edge("M441 258 H564"), lbl(470, 250, "alarms"),
      node("users", 0, 41, 120, "Users", "browser clients"),
      node("waf", 168, 41, 150, "AWS WAF", null),
      node("alb", 366, 41, 150, "Load balancer", null),
      node("ec2", 564, 41, 150, "EC2 app server", null),
      node("rds", 762, 41, 150, "RDS PostgreSQL", null),
      node("cloudwatch", 366, 200, 150, "CloudWatch", null),
      node("sns", 564, 229, 150, "SNS", null));
    return h("div", { class: "arch" }, svg);
  }

  function metric(k, v) { return h("div", {}, h("span", {}, k), h("b", {}, v ?? "—")); }

  function serviceCard(x) {
    const st = x.status;
    const metrics = Object.entries(x.metrics || {});
    const config = Object.entries(x.config || {}).filter(([k]) => k !== "rules");
    const parts = [
      h("div", { style: { display: "flex", gap: "8px", "align-items": "center", "flex-wrap": "wrap" } },
        badge(st, STATUS_TEXT[st] || label(st)), h("span", { class: "faint small" }, `Checked ${x.checked_at ? dateTime(x.checked_at) : "—"}`)),
      h("p", { class: "muted small" }, x.role),
      x.reason ? h("p", { class: "small" }, x.reason) : null,
      x.error ? h("div", { class: "banner crit" }, icon("alert"), h("div", {}, h("strong", {}, "Error: "), x.error)) : null,
      metrics.length ? h("div", { class: "svc-metrics" }, metrics.map(([k, v]) => metric(label(k).replace(/ 1h$/, " (1 h)"),
        v === null || v === undefined ? "not reported" : typeof v === "number" ? num(v, 2) : String(v)))) : null,
      x.app ? h("div", { class: "svc-metrics" }, metric("App status", label(x.app.status)), metric("App uptime", `${Math.round(x.app.uptime_s / 60)} min`),
        metric("Requests (1 h)", int(x.app.requests_1h))) : null,
      x.app_connection ? h("div", { class: "svc-metrics" }, Object.entries(x.app_connection.metrics || {}).map(([k, v]) => metric(label(k), num(v)))) : null,
      config.length ? h("dl", { class: "kv" }, config.flatMap(([k, v]) => [h("dt", {}, label(k)),
        h("dd", { class: "small" }, v === null || v === undefined ? "—" : typeof v === "boolean" ? (v ? "yes" : "no") : String(v))])) : null,
      x.config?.rules ? h("div", {}, h("div", { class: "section-title" }, "Web ACL rules"),
        h("ul", { class: "health-list" }, x.config.rules.map((r) => h("li", {}, h("i", { class: "sev-dot healthy" }), h("span", {}, `${r.priority}. ${r.name}`),
          h("span", { class: "faint tiny" }, r.type))))) : null,
      x.alarms?.length ? h("div", {}, h("div", { class: "section-title" }, "Alarms"),
        h("ul", { class: "health-list" }, x.alarms.map((a) => h("li", {}, h("i", { class: `sev-dot ${a.state === "ALARM" ? "critical" : a.state === "OK" ? "healthy" : "informational"}` }),
          h("span", {}, a.name), badge(a.state === "ALARM" ? "critical" : a.state === "OK" ? "healthy" : "informational", a.state),
          a.state === "ALARM" ? h("span", { class: "d" }, a.reason) : null)))) : null,
      x.notes?.length ? h("ul", { class: "small muted", style: { margin: 0, "padding-left": "18px" } }, x.notes.map((n) => h("li", {}, n))) : null,
      x.last_delivery?.status ? h("p", { class: "small" }, `Last SNS publish from the app: ${x.last_delivery.status} ${dateTime(x.last_delivery.ts)}${x.last_delivery.error ? ` (${x.last_delivery.error})` : ""}`) : null,
      x.last_notification ? h("p", { class: "small" }, `Last alert: “${x.last_notification.title}”, delivery ${x.last_notification.delivery}, ${dateTime(x.last_notification.ts)}`) : null,
    ];
    const c = card({ title: x.name, body: h("div", { class: "stack", style: { gap: "12px" } }, parts) });
    c.id = `svc-${x.key}`;
    return c;
  }

  load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 60000);
  return { el, destroy() { clearInterval(timer); } };
}
