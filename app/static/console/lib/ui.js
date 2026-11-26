// Reusable UI components.
import { h, clear, store } from "./dom.js";
import { icon } from "./icons.js";
import { int, RANGE_SHORT, RANGE_LABELS, label as labelize } from "./fmt.js";
import { sparkline } from "./charts.js";

// ---------------------------------------------------------------- toast

let toastBox;
export function toast(message, kind = "ok", ms = 4200) {
  if (!toastBox) {
    toastBox = h("div", { class: "toasts", role: "status", "aria-live": "polite" });
    document.body.append(toastBox);
  }
  const close = () => t.remove();
  const t = h("div", { class: `toast ${kind}` },
    icon(kind === "err" ? "alert" : kind === "ok" ? "check" : "info", { width: 16, height: 16 }),
    h("div", {}, message),
    h("button", { type: "button", "aria-label": "Dismiss", onclick: close }, "✕"));
  toastBox.append(t);
  setTimeout(close, ms);
}

// ---------------------------------------------------------------- overlays

let openLayers = [];

function trapFocus(container, e) {
  if (e.key !== "Tab") return;
  const f = [...container.querySelectorAll('a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])')]
    .filter((el) => el.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}

function layer(panel, { onClose } = {}) {
  const previous = document.activeElement;
  const overlay = h("div", { class: "overlay" });
  const close = () => {
    overlay.remove();
    panel.remove();
    document.removeEventListener("keydown", onKey);
    openLayers = openLayers.filter((l) => l !== api);
    if (previous && previous.focus) previous.focus();
    onClose && onClose();
  };
  const onKey = (e) => {
    if (openLayers[openLayers.length - 1] !== api) return;
    if (e.key === "Escape") { e.preventDefault(); close(); }
    trapFocus(panel, e);
  };
  overlay.addEventListener("click", close);
  document.addEventListener("keydown", onKey);
  document.body.append(overlay, panel);
  const api = { close, panel };
  openLayers.push(api);
  requestAnimationFrame(() => {
    const focusable = panel.querySelector("[autofocus], input, select, textarea, button");
    (focusable || panel).focus();
  });
  return api;
}

export function closeAllLayers() {
  [...openLayers].reverse().forEach((l) => l.close());
}

export function drawer({ title, subtitle, body, footer, onClose }) {
  const titleId = "dr-" + Math.random().toString(36).slice(2);
  const panel = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId, tabindex: "-1" });
  const head = h("div", { class: "drawer-head" },
    h("div", {}, h("h2", { id: titleId }, title), subtitle ? h("p", { class: "muted small", style: { "margin-top": "4px" } }, subtitle) : null),
    h("button", { class: "icon-btn", type: "button", "aria-label": "Close panel", onclick: () => l.close() }, icon("x")));
  const bodyEl = h("div", { class: "drawer-body" }, body);
  panel.append(head, bodyEl);
  if (footer) panel.append(h("div", { class: "drawer-foot" }, footer));
  const l = layer(panel, { onClose });
  return { ...l, body: bodyEl };
}

/** Modal form. `fields`: [{name,label,type,value,options,required,min,max,placeholder,help}] */
export function formModal({ title, description, fields = [], submitLabel = "Save", danger = false, onSubmit }) {
  const titleId = "md-" + Math.random().toString(36).slice(2);
  const err = h("p", { class: "form-error", role: "alert", hidden: true });
  const inputs = {};
  const form = h("form", { novalidate: true });
  const body = h("div", { class: "modal-body" });
  for (const f of fields) {
    const id = `${titleId}-${f.name}`;
    let input;
    if (f.type === "select") {
      input = h("select", { id, class: "select", name: f.name }, (f.options || []).map((o) =>
        h("option", { value: o.value, selected: String(o.value) === String(f.value) ? true : null }, o.label)));
    } else if (f.type === "textarea") {
      input = h("textarea", { id, class: "textarea", name: f.name, rows: f.rows || 3, placeholder: f.placeholder || null,
        maxlength: f.maxlength || null }, f.value || "");
    } else {
      input = h("input", { id, class: "input", name: f.name, type: f.type || "text", value: f.value ?? "",
        placeholder: f.placeholder || null, min: f.min ?? null, max: f.max ?? null, autocomplete: f.autocomplete || "off",
        maxlength: f.maxlength || null });
    }
    if (f.required) input.required = true;
    inputs[f.name] = input;
    body.append(h("div", { class: "field" }, h("label", { for: id }, f.label), input,
      f.help ? h("p", { class: "faint small" }, f.help) : null));
  }
  body.append(err);
  const submit = h("button", { class: `btn ${danger ? "danger" : "primary"}`, type: "submit" }, submitLabel);
  const panel = h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId, tabindex: "-1" });
  form.append(
    h("div", { class: "modal-head" }, h("h2", { id: titleId }, title), description ? h("p", {}, description) : null),
    body,
    h("div", { class: "modal-foot" }, h("button", { class: "btn ghost", type: "button", onclick: () => l.close() }, "Cancel"), submit));
  panel.append(form);
  const l = layer(panel);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.hidden = true;
    for (const f of fields) {
      if (f.required && !String(inputs[f.name].value).trim()) {
        err.textContent = `${f.label} is required.`;
        err.hidden = false;
        inputs[f.name].focus();
        return;
      }
    }
    const values = Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, el.value]));
    submit.disabled = true;
    try {
      await onSubmit(values);
      l.close();
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
      submit.disabled = false;
    }
  });
  return l;
}

export function confirmModal({ title, description, confirmLabel = "Confirm", danger = false, onConfirm }) {
  return formModal({ title, description, submitLabel: confirmLabel, danger, onSubmit: onConfirm });
}

// ---------------------------------------------------------------- tooltip

let tipEl;
export function hint(text) {
  const btn = h("button", { type: "button", class: "hint-btn", "aria-label": text }, icon("info"));
  const show = () => {
    tipEl?.remove();
    tipEl = h("div", { class: "tooltip", role: "tooltip" }, text);
    document.body.append(tipEl);
    const r = btn.getBoundingClientRect();
    const w = tipEl.offsetWidth;
    tipEl.style.left = `${Math.max(8, Math.min(window.innerWidth - w - 8, r.left + r.width / 2 - w / 2))}px`;
    tipEl.style.top = `${r.bottom + 8}px`;
  };
  const hide = () => { tipEl?.remove(); tipEl = null; };
  btn.addEventListener("mouseenter", show);
  btn.addEventListener("focus", show);
  btn.addEventListener("mouseleave", hide);
  btn.addEventListener("blur", hide);
  return btn;
}

// ---------------------------------------------------------------- small pieces

export const badge = (cls, text) => h("span", { class: `badge ${cls}` }, text ?? labelize(cls));

export function card({ title, sub, actions, body, cls = "" }) {
  const c = h("section", { class: `card ${cls}` });
  if (title) {
    c.append(h("div", { class: "card-head" },
      h("div", {}, h("h2", {}, title), sub ? h("p", { class: "sub" }, sub) : null),
      actions ? h("div", { class: "page-actions" }, actions) : null));
  }
  const b = h("div", { class: "card-body" }, body);
  c.append(b);
  c.body = b;
  return c;
}

export function pageHead(title, description, actions) {
  return h("div", { class: "page-head" },
    h("div", {}, h("h1", {}, title), description ? h("p", {}, description) : null),
    actions ? h("div", { class: "page-actions" }, actions) : null);
}

export function loading(rows = 3) {
  return h("div", { class: "stack", "aria-busy": "true", "aria-label": "Loading" },
    Array.from({ length: rows }, (_, i) => h("div", { class: "skeleton", style: { width: `${92 - i * 14}%` } })));
}

export function emptyState(title, text, action) {
  return h("div", { class: "state" }, icon("inbox"), h("strong", {}, title), text ? h("p", {}, text) : null, action || null);
}

export function errorState(message, retry) {
  return h("div", { class: "state error", role: "alert" }, icon("alert"), h("strong", {}, "Could not load this"),
    h("p", {}, message), retry ? h("button", { class: "btn sm", type: "button", onclick: retry }, icon("refresh"), "Try again") : null);
}

export function noAccess() {
  return h("div", { class: "page" }, h("div", { class: "card" },
    h("div", { class: "state" }, icon("lock"), h("strong", {}, "Your role cannot open this page"),
      h("p", {}, "Ask an administrator if you need access."), h("a", { class: "btn sm", href: "#/command-center" }, "Go to the command center"))));
}

export function segmented(options, value, onChange, labelText = "Options") {
  const wrap = h("div", { class: "seg", role: "group", "aria-label": labelText });
  const render = (v) => {
    clear(wrap, options.map((o) => h("button", { type: "button", "aria-pressed": String(o.value === v),
      onclick: () => { render(o.value); onChange(o.value); } }, o.label)));
  };
  render(value);
  wrap.set = render;
  return wrap;
}

export function rangeControl(onChange, { ranges = [1, 6, 24, 168, 720], key = "range" } = {}) {
  let current = store.get(key, 24);
  if (!ranges.includes(current)) current = 24;
  const seg = segmented(ranges.map((r) => ({ value: r, label: RANGE_SHORT[r] })), current, (v) => {
    current = v;
    store.set(key, v);
    seg.title = RANGE_LABELS[v];
    onChange(v);
  }, "Time range");
  seg.title = RANGE_LABELS[current];
  return { el: seg, get: () => current };
}

export function switchControl(labelText, checked, onChange) {
  const input = h("input", { type: "checkbox", checked: checked ? true : null, onchange: (e) => onChange(e.target.checked) });
  return h("label", { class: "switch" }, input, h("span", { class: "track", "aria-hidden": "true" }), labelText);
}

const KPI_ICONS = { total: ["activity", "accent"], blocked: ["ban", "crit"], suspicious: ["alert", "warn"],
  successful: ["check", "ok"], incidents: ["siren", "crit"], dlp: ["lock", "info"] };

export function kpiCard(k, rangeHours) {
  const [ic, tone] = KPI_ICONS[k.key] || ["activity", "accent"];
  let delta;
  const prevText = `prev ${RANGE_SHORT[rangeHours]}`;
  if (k.key === "incidents") {
    delta = h("span", { class: "delta neutral" }, `${int(k.opened)} opened (prev ${int(k.opened_previous)})`);
  } else if (k.change_pct !== null && k.change_pct !== undefined) {
    const up = k.change_pct > 0;
    const flat = k.change_pct === 0;
    const cls = flat || !k.good_direction ? "neutral" : (up ? (k.good_direction === "down" ? "up-bad" : "up-good")
      : (k.good_direction === "down" ? "down-good" : "down-bad"));
    delta = h("span", {}, h("span", { class: `delta ${cls}` }, flat ? null : icon(up ? "up" : "down"), `${Math.abs(k.change_pct)}%`),
      ` vs ${prevText}`);
  } else {
    delta = h("span", {}, `No data in ${prevText}`);
  }
  const color = { crit: "#ef4444", warn: "#f59e0b", ok: "#22c55e", accent: "#38bdf8", info: "#818cf8" }[tone];
  return h("section", { class: "card kpi", "aria-label": k.label },
    h("div", { class: "kpi-top" },
      h("span", { class: "kpi-label" }, k.label, hint(k.hint)),
      h("span", { class: `ico ${tone}` }, icon(ic))),
    h("div", { class: "kpi-value num" }, int(k.value)),
    h("div", { class: "kpi-foot" },
      delta,
      sparkline(k.spark, color)));
}

export function pager(state, onPage) {
  const { page, pages, total, page_size } = state;
  const from = total ? (page - 1) * page_size + 1 : 0;
  const to = Math.min(total, page * page_size);
  return h("div", { class: "table-foot" },
    h("span", { class: "num" }, total ? `${int(from)}–${int(to)} of ${int(total)}` : "No results"),
    h("div", { class: "pager" },
      h("button", { class: "btn sm", type: "button", disabled: page <= 1 ? true : null, "aria-label": "Previous page",
        onclick: () => onPage(page - 1) }, icon("chevronLeft")),
      h("span", { class: "num small" }, `Page ${page} of ${pages}`),
      h("button", { class: "btn sm", type: "button", disabled: page >= pages ? true : null, "aria-label": "Next page",
        onclick: () => onPage(page + 1) }, icon("chevronRight"))));
}
