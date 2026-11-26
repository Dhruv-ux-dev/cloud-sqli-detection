// Northfield console shell: navigation, top bar, global search, notifications
// and a hash router that loads one page module at a time.
import { h, clear, debounce, store } from "./lib/dom.js";
import { icon, brandMark } from "./lib/icons.js";
import { api } from "./lib/api.js";
import { dateTime, ago } from "./lib/fmt.js";
import { noAccess, closeAllLayers, toast, errorState } from "./lib/ui.js";

const NAV = [
  { group: "OVERVIEW", items: [
    { path: "command-center", label: "Security Command Center", icon: "command", perm: "dashboard:view" },
    { path: "traffic", label: "Live Traffic Monitor", icon: "activity", perm: "traffic:view" },
    { path: "analytics", label: "Threat Analytics", icon: "chart", perm: "analytics:view" },
  ] },
  { group: "SECURITY OPERATIONS", items: [
    { path: "investigate", label: "Attack Investigation", icon: "target", perm: "incidents:view" },
    { path: "simulation", label: "Attack Simulation Lab", icon: "flask", perm: "simulation:run" },
    { path: "detection", label: "SQL Injection Detection", icon: "scan", perm: "detection:view" },
    { path: "dlp", label: "Data Protection Center", icon: "lock", perm: "dlp:view" },
    { path: "incidents", label: "Security Incidents", icon: "siren", perm: "incidents:view", badge: "incidents" },
    { path: "audit", label: "Audit Logs", icon: "scroll", perm: "audit:view" },
  ] },
  { group: "INFRASTRUCTURE", items: [
    { path: "infrastructure", label: "AWS Infrastructure", icon: "cloud", perm: "infra:view" },
    { path: "alerts", label: "Monitoring & Alerts", icon: "bell", perm: "alerts:view", badge: "alerts" },
    { path: "health", label: "System Health", icon: "pulse", perm: "dashboard:view" },
  ] },
  { group: "ADMINISTRATION", items: [
    { path: "users", label: "Users & Roles", icon: "users", perm: "users:manage" },
    { path: "policies", label: "Security Policies", icon: "sliders", perm: "policy:view" },
    { path: "config", label: "Configuration", icon: "cog", perm: "config:view" },
  ] },
];
const ROUTES = Object.fromEntries(NAV.flatMap((g) => g.items.map((i) => [i.path, { ...i, group: g.group }])));

const ctx = { me: null, can: (p) => ctx.me?.permissions.includes(p), navigate: (path) => { location.hash = "#/" + path; } };
let current = null; // { destroy }
const badges = { incidents: 0, alerts: 0 };
const els = {};

// ---------------------------------------------------------------- boot

async function boot() {
  try {
    ctx.me = await api("/api/me");
  } catch (err) {
    clear(document.getElementById("app"), errorState(err.message, () => location.reload()));
    return;
  }
  buildShell();
  window.addEventListener("hashchange", route);
  route();
  pollBadges();
  pollHealth();
  setInterval(() => { if (!document.hidden) pollBadges(); }, 30000);
  setInterval(() => { if (!document.hidden) pollHealth(); }, 60000);
}

// ---------------------------------------------------------------- shell

function buildShell() {
  const shell = h("div", { class: `shell${store.get("collapsed", false) ? " collapsed" : ""}` });
  els.shell = shell;

  // sidebar
  els.navLinks = {};
  const nav = h("nav", { class: "nav", "aria-label": "Main" });
  for (const g of NAV) {
    const items = g.items.filter((i) => ctx.can(i.perm));
    if (!items.length) continue;
    nav.append(h("div", { class: "nav-group" }, h("div", { class: "nav-heading" }, g.group), items.map((i) => {
      const a = h("a", { href: `#/${i.path}`, "data-label": i.label }, icon(i.icon), h("span", {}, i.label));
      if (i.badge) {
        a.append(h("span", { class: "count", hidden: true }), h("i", { class: "dot-badge", hidden: true }));
      }
      a.addEventListener("mouseenter", () => showNavTip(a));
      a.addEventListener("mouseleave", hideNavTip);
      a.addEventListener("focus", () => showNavTip(a));
      a.addEventListener("blur", hideNavTip);
      a.addEventListener("click", () => shell.classList.remove("mobile-open"));
      els.navLinks[i.path] = a;
      return a;
    })));
  }
  const me = ctx.me;
  const initials = (me.display_name || me.username).split(/\s+/).map((p) => p[0]).slice(0, 2).join("");
  const sidebar = h("aside", { class: "sidebar", "aria-label": "Sidebar" },
    h("a", { class: "brand", href: "#/command-center", "aria-label": "Northfield home" }, brandMark(),
      h("div", { class: "brand-text" }, h("strong", {}, "NORTHFIELD"), h("span", {}, "Cloud Security Platform"))),
    nav,
    h("div", { class: "sidebar-foot" },
      h("button", { class: "collapse-btn", type: "button", "aria-label": "Collapse sidebar", onclick: toggleCollapse },
        icon("chevronLeft"), h("span", {}, "Collapse")),
      h("div", { class: "profile" }, h("span", { class: "avatar", "aria-hidden": "true" }, initials),
        h("div", { class: "profile-text" }, h("strong", {}, me.display_name || me.username), h("span", {}, me.role_label)))));

  // top bar
  els.crumbs = h("div", { class: "crumbs" });
  els.status = h("button", { class: "status-ind", type: "button", onclick: () => ctx.navigate("health"),
    "aria-label": "System status" }, h("i", { class: "sev-dot" }), h("span", {}, "Checking"));
  els.bell = h("button", { class: "icon-btn", type: "button", "aria-label": "Notifications", "aria-haspopup": "true",
    onclick: (e) => { e.stopPropagation(); toggleNotifications(); } }, icon("bell"),
  h("span", { class: "badge-count", hidden: true }));
  const userBtn = h("button", { class: "icon-btn", type: "button", "aria-label": "Account menu", "aria-haspopup": "true",
    onclick: (e) => { e.stopPropagation(); toggleUserMenu(); } }, h("span", { class: "avatar", style: { width: "28px", height: "28px" } }, initials));
  const topbar = h("header", { class: "topbar" },
    h("button", { class: "icon-btn menu-btn", type: "button", "aria-label": "Open navigation",
      onclick: () => shell.classList.toggle("mobile-open") }, icon("menu")),
    els.crumbs,
    h("div", { class: "top-right" },
      buildSearch(),
      h("span", { class: `env ${me.environment}`, title: `Environment: ${me.environment}` }, me.environment.toUpperCase()),
      els.status, els.bell, userBtn));

  els.content = h("main", { id: "content", tabindex: "-1" });
  shell.append(sidebar, h("div", { class: "main" }, topbar, els.content));
  clear(document.getElementById("app"), shell);
  document.addEventListener("click", closePopovers);
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); els.searchInput.focus(); }
    if (e.key === "Escape") closePopovers();
  });
}

function toggleCollapse() {
  const on = !els.shell.classList.contains("collapsed");
  els.shell.classList.toggle("collapsed", on);
  store.set("collapsed", on);
  hideNavTip();
}

let navTip;
function showNavTip(a) {
  if (!els.shell.classList.contains("collapsed") || window.innerWidth <= 860) return;
  hideNavTip();
  const r = a.getBoundingClientRect();
  navTip = h("div", { class: "nav-tip", role: "tooltip" }, a.dataset.label);
  document.body.append(navTip);
  navTip.style.left = `${r.right + 10}px`;
  navTip.style.top = `${r.top + r.height / 2 - navTip.offsetHeight / 2}px`;
}
function hideNavTip() { navTip?.remove(); navTip = null; }

// ---------------------------------------------------------------- search

function buildSearch() {
  const input = h("input", { type: "search", placeholder: "Search incidents, IPs, endpoints, rules", "aria-label": "Global search",
    autocomplete: "off", spellcheck: "false", "aria-expanded": "false", "aria-controls": "search-results" });
  els.searchInput = input;
  const results = h("div", { class: "search-results", id: "search-results", role: "listbox", hidden: true });
  let links = [], active = -1;
  const setActive = (i) => {
    links.forEach((l) => l.classList.remove("active"));
    active = i;
    if (links[i]) { links[i].classList.add("active"); links[i].scrollIntoView({ block: "nearest" }); }
  };
  const run = debounce(async () => {
    const q = input.value.trim();
    if (q.length < 2) { results.hidden = true; input.setAttribute("aria-expanded", "false"); return; }
    try {
      const data = await api(`/api/search?q=${encodeURIComponent(q)}`);
      const r = data.results;
      const groups = [
        ["INCIDENTS", r.incidents, (x) => [`#/investigate/incident/${x.id}`, x.ref, x.title]],
        ["REQUESTS", r.requests, (x) => [`#/investigate/request/${x.id}`, x.ref, `${x.title} from ${x.client_ip}`]],
        ["DETECTION RULES", r.rules, (x) => [`#/detection/${x.id}`, x.id, x.title]],
        ["ALERTS", r.alerts, (x) => ["#/alerts", `ALERT-${x.id}`, x.title]],
        ["AUDIT EVENTS", r.audit, (x) => [`#/audit/${x.id}`, x.ref, x.title]],
      ];
      clear(results);
      links = [];
      for (const [title, rows, map] of groups) {
        if (!rows.length) continue;
        results.append(h("h4", {}, title));
        for (const row of rows) {
          const [href, ref, text] = map(row);
          const a = h("a", { href, role: "option", onclick: () => { results.hidden = true; input.value = ""; } },
            h("span", { class: "ref" }, ref), h("span", { class: "t" }, text), h("span", { class: "faint tiny" }, row.ts ? ago(row.ts) : ""));
          links.push(a);
          results.append(a);
        }
      }
      if (!links.length) results.append(h("p", { class: "empty" }, `No incidents, requests, rules or audit events match “${q}”.`));
      results.hidden = false;
      input.setAttribute("aria-expanded", "true");
      setActive(-1);
    } catch (err) {
      clear(results, h("p", { class: "empty" }, err.message));
      results.hidden = false;
    }
  }, 220);
  input.addEventListener("input", run);
  input.addEventListener("keydown", (e) => {
    if (results.hidden) return;
    if (e.key === "ArrowDown") { e.preventDefault(); setActive(Math.min(links.length - 1, active + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive(Math.max(0, active - 1)); }
    else if (e.key === "Enter" && links[active]) { e.preventDefault(); links[active].click(); location.hash = links[active].getAttribute("href"); }
    else if (e.key === "Escape") { results.hidden = true; input.blur(); }
  });
  input.addEventListener("focus", () => { if (input.value.trim().length >= 2) run(); });
  const wrap = h("div", { class: "search", onclick: (e) => e.stopPropagation() }, icon("search"), input, h("kbd", {}, "Ctrl K"), results);
  els.searchResults = results;
  return wrap;
}

// ---------------------------------------------------------------- popovers

function closePopovers() {
  els.pop?.remove();
  els.pop = null;
  if (els.searchResults) els.searchResults.hidden = true;
}

async function toggleNotifications() {
  if (els.pop?.dataset.kind === "notif") { closePopovers(); return; }
  closePopovers();
  const body = h("div", { class: "popover-body" }, h("p", { class: "muted small", style: { padding: "14px" } }, "Loading"));
  const pop = h("div", { class: "popover", role: "dialog", "aria-label": "Notifications", dataset: { kind: "notif" },
    onclick: (e) => e.stopPropagation() },
  h("div", { class: "popover-head" }, h("h2", {}, "Notifications"),
    h("button", { class: "btn sm ghost", type: "button", onclick: async () => {
      await api("/api/alerts/read-all", { method: "POST" });
      pollBadges();
      closePopovers();
      toast("All notifications marked as read.");
    } }, "Mark all read")),
  body,
  h("div", { class: "popover-foot" }, h("a", { href: "#/alerts", onclick: closePopovers }, "Open Monitoring & Alerts")));
  els.pop = pop;
  els.shell.querySelector(".main").append(pop);
  try {
    const data = await api("/api/alerts?page_size=8&status=open");
    clear(body, data.items.length ? data.items.map((a) => h("div", { class: `notif${a.is_read ? "" : " unread"}`, tabindex: "0",
      onclick: () => { closePopovers(); location.hash = a.incident_id ? `#/investigate/incident/${a.incident_id}` : "#/alerts"; api(`/api/alerts/${a.id}`, { method: "POST", body: { action: "read" } }).then(pollBadges).catch(() => {}); } },
    h("i", { class: `sev-dot ${a.severity}` }),
    h("div", {}, h("strong", {}, a.title), h("p", {}, a.description),
      h("span", { class: "faint tiny" }, `${ago(a.last_seen_at)}${a.occurrences > 1 ? `, ${a.occurrences} times` : ""}`))))
      : h("p", { class: "muted small", style: { padding: "16px 14px" } }, "No open alerts. New alerts from incidents, health checks and CloudWatch appear here."));
  } catch (err) {
    clear(body, h("p", { class: "form-error", style: { padding: "14px" } }, err.message));
  }
}

function toggleUserMenu() {
  if (els.pop?.dataset.kind === "user") { closePopovers(); return; }
  closePopovers();
  const me = ctx.me;
  const pop = h("div", { class: "popover user-menu", role: "menu", dataset: { kind: "user" }, style: { width: "260px" },
    onclick: (e) => e.stopPropagation() },
  h("div", { class: "popover-head" }, h("div", {}, h("strong", {}, me.display_name || me.username),
    h("p", { class: "muted small" }, `${me.username}, ${me.role_label}`))),
  h("div", { style: { padding: "6px 0" } },
    h("a", { class: "menu-item", href: "/records", role: "menuitem" }, icon("records"), "Customer records desk"),
    ctx.can("users:manage") ? h("a", { class: "menu-item", href: "#/users", role: "menuitem", onclick: closePopovers }, icon("users"), "Users & roles") : null,
    h("button", { class: "menu-item", type: "button", role: "menuitem", onclick: signOut }, icon("logout"), "Sign out")));
  els.pop = pop;
  els.shell.querySelector(".main").append(pop);
}

async function signOut() {
  try { await api("/api/logout", { method: "POST" }); } finally { location.assign("/"); }
}

// ---------------------------------------------------------------- polling

async function pollBadges() {
  try {
    const [alerts, incidents] = await Promise.all([
      api("/api/alerts?page_size=5&unread=true"),
      api("/api/incidents?status=new&page_size=5"),
    ]);
    badges.alerts = alerts.unread;
    badges.incidents = incidents.total;
  } catch { return; }
  const bc = els.bell.querySelector(".badge-count");
  bc.hidden = !badges.alerts;
  bc.textContent = badges.alerts > 99 ? "99+" : String(badges.alerts);
  els.bell.setAttribute("aria-label", `Notifications, ${badges.alerts} unread`);
  for (const [path, key] of [["alerts", "alerts"], ["incidents", "incidents"]]) {
    const a = els.navLinks[path];
    if (!a) continue;
    const c = a.querySelector(".count"), dot = a.querySelector(".dot-badge");
    c.hidden = !badges[key];
    dot.hidden = !badges[key];
    c.textContent = badges[key] > 99 ? "99+" : String(badges[key]);
  }
}

async function pollHealth() {
  try {
    const data = await api("/api/health/components");
    const comps = Object.values(data.components);
    const core = ["api", "database", "detector", "dlp"].map((k) => data.components[k]);
    const down = core.some((c) => c.status === "down");
    const degraded = comps.some((c) => ["degraded", "error"].includes(c.status));
    const cls = down ? "down" : degraded ? "degraded" : "healthy";
    const text = down ? "Core service down" : degraded ? "Degraded" : data.mode === "local" ? "Operational (local)" : "All systems operational";
    clear(els.status, h("i", { class: `sev-dot ${cls}` }), h("span", {}, text));
    els.status.title = text;
  } catch {
    clear(els.status, h("i", { class: "sev-dot down" }), h("span", {}, "Unreachable"));
  }
}

// ---------------------------------------------------------------- router

async function route() {
  const raw = location.hash.replace(/^#\/?/, "") || "command-center";
  const [path, ...params] = raw.split("/").map(decodeURIComponent);
  const r = ROUTES[path];
  closeAllLayers();
  closePopovers();
  hideNavTip();
  if (current?.destroy) { try { current.destroy(); } catch { /* ignore */ } }
  current = null;

  for (const [p, a] of Object.entries(els.navLinks)) { if (p === path) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); }

  if (!r) { location.replace("#/command-center"); return; }
  clear(els.crumbs, h("span", { class: "section" }, r.group.charAt(0) + r.group.slice(1).toLowerCase()), icon("chevronRight", { class: "section" }), h("strong", {}, r.label));
  document.title = `${r.label} | Northfield`;
  if (!ctx.can(r.perm)) { clear(els.content, noAccess()); return; }

  clear(els.content, h("div", { class: "page" }, h("p", { class: "muted" }, "Loading")));
  try {
    const mod = await import(`./pages/${path}.js`);
    const page = await mod.default({ ...ctx, params, setCrumb: (extra) => {
      clear(els.crumbs, h("span", { class: "section" }, r.group.charAt(0) + r.group.slice(1).toLowerCase()),
        icon("chevronRight", { class: "section" }), h("a", { href: `#/${path}` }, r.label),
        extra ? [icon("chevronRight"), h("strong", {}, extra)] : null);
    } });
    current = page;
    clear(els.content, page.el);
    els.content.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  } catch (err) {
    console.error(err);
    clear(els.content, h("div", { class: "page" }, errorState(err.message || "This page failed to load.", route)));
  }
}

export { ctx, dateTime };
boot();
