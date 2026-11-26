// Hand-drawn SVG charts: no chart library, so the console works offline.
import { h, s, clear } from "./dom.js";
import { int, bucketLabel } from "./fmt.js";

export const COLORS = {
  normal: "#3b5a78", successful: "#22c55e", suspicious: "#f59e0b", blocked: "#ef4444", waf_blocked: "#b91c1c",
  accent: "#38bdf8", info: "#818cf8", high: "#f97316", critical: "#ef4444", medium: "#f59e0b",
  low: "#38bdf8", informational: "#64748b",
};
export const CATEGORY_COLORS = ["#38bdf8", "#f59e0b", "#ef4444", "#818cf8", "#22c55e", "#f97316", "#e879f9", "#2dd4bf",
  "#facc15", "#94a3b8", "#fb7185"];

function niceMax(v) {
  if (v <= 4) return 4;
  const mag = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * mag >= v) return m * mag;
  return 10 * mag;
}

// ---------------------------------------------------------------- sparkline

export function sparkline(values = [], color = COLORS.accent) {
  const w = 84, hgt = 26;
  const svg = s("svg", { class: "spark", viewBox: `0 0 ${w} ${hgt}`, preserveAspectRatio: "none", "aria-hidden": "true" });
  if (!values.length || values.every((v) => !v)) {
    svg.append(s("line", { x1: 0, x2: w, y1: hgt - 2, y2: hgt - 2, stroke: "#263449", "stroke-width": 1.5 }));
    return svg;
  }
  const max = Math.max(...values, 1);
  const step = values.length > 1 ? w / (values.length - 1) : w;
  const pts = values.map((v, i) => [i * step, hgt - 2 - (v / max) * (hgt - 4)]);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join("");
  svg.append(
    s("path", { d: `${d}L${w},${hgt}L0,${hgt}Z`, fill: color, opacity: 0.12 }),
    s("path", { d, fill: "none", stroke: color, "stroke-width": 1.5, "stroke-linejoin": "round" }));
  return svg;
}

// ---------------------------------------------------------------- time series

/**
 * Stacked bar or area time series with hover tooltip and legend toggles.
 * opts: { series:[{key,label,color}], data:[{t,...}], hours, kind:"bars"|"area", height, stacked }
 * Returns { el, update(data), destroy() }.
 */
export function timeSeries(opts) {
  const { series, hours, kind = "bars", height = 240, stacked = true } = opts;
  let data = opts.data || [];
  const hidden = new Set(opts.hidden || []);
  const wrap = h("div", { class: "chart" });
  const legend = h("div", { class: "legend", role: "group", "aria-label": "Series" });
  const plot = h("div", { style: { position: "relative" } });
  const tip = h("div", { class: "chart-tip", hidden: true });
  plot.append(tip);
  wrap.append(legend, plot);

  const drawLegend = () => clear(legend, series.map((sr) => h("button", {
    type: "button", "aria-pressed": String(!hidden.has(sr.key)),
    onclick: () => { hidden.has(sr.key) ? hidden.delete(sr.key) : hidden.add(sr.key); drawLegend(); draw(); },
  }, h("i", { style: { background: sr.color } }), sr.label)));

  let svg;
  function draw() {
    svg?.remove();
    const w = Math.max(plot.clientWidth || wrap.clientWidth || 600, 260);
    const m = { l: 40, r: 8, t: 12, b: 24 };
    const iw = w - m.l - m.r, ih = height - m.t - m.b;
    const active = series.filter((sr) => !hidden.has(sr.key));
    const totals = data.map((d) => stacked ? active.reduce((a, sr) => a + (d[sr.key] || 0), 0)
      : Math.max(0, ...active.map((sr) => d[sr.key] || 0)));
    const max = niceMax(Math.max(0, ...totals));
    const y = (v) => m.t + ih - (v / max) * ih;
    const n = Math.max(data.length, 1);
    const slot = iw / n;
    svg = s("svg", { viewBox: `0 0 ${w} ${height}`, height, role: "img",
      "aria-label": `Chart of ${active.map((a) => a.label).join(", ")} over time` });
    const grid = s("g", { class: "grid" }), axis = s("g", { class: "axis" });
    for (let g = 0; g <= 4; g++) {
      const v = (max / 4) * g;
      grid.append(s("line", { x1: m.l, x2: w - m.r, y1: y(v) + 0.5, y2: y(v) + 0.5 }));
      axis.append(s("text", { x: m.l - 8, y: y(v) + 4, "text-anchor": "end", text: int(v) }));
    }
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 80))));
    data.forEach((d, i) => {
      if (i % every === 0) axis.append(s("text", { x: m.l + i * slot + slot / 2, y: height - 6, "text-anchor": "middle",
        text: bucketLabel(d.t, hours) }));
    });
    svg.append(grid, axis);

    const body = s("g");
    if (kind === "bars") {
      const bw = Math.max(1.5, slot * 0.68);
      data.forEach((d, i) => {
        let acc = 0;
        const x = m.l + i * slot + (slot - bw) / 2;
        for (const sr of active) {
          const v = d[sr.key] || 0;
          if (!v) continue;
          const top = stacked ? y(acc + v) : y(v);
          const bottom = stacked ? y(acc) : y(0);
          body.append(s("rect", { x: x.toFixed(2), y: top.toFixed(2), width: bw.toFixed(2),
            height: Math.max(1, bottom - top).toFixed(2), fill: sr.color, rx: Math.min(2, bw / 3) }));
          if (stacked) acc += v;
        }
      });
    } else {
      const xs = (i) => m.l + i * slot + slot / 2;
      const base = data.map(() => 0);
      for (const sr of active) {
        const top = data.map((d, i) => (stacked ? base[i] : 0) + (d[sr.key] || 0));
        const line = top.map((v, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
        const under = stacked
          ? base.map((v, i) => [xs(i), y(v)]).reverse().map(([px, py]) => `L${px.toFixed(1)},${py.toFixed(1)}`).join("")
          : `L${xs(data.length - 1).toFixed(1)},${y(0)}L${xs(0).toFixed(1)},${y(0)}`;
        body.append(s("path", { d: line + under + "Z", fill: sr.color, opacity: 0.18 }),
          s("path", { d: line, fill: "none", stroke: sr.color, "stroke-width": 1.75, "stroke-linejoin": "round" }));
        if (stacked) top.forEach((v, i) => (base[i] = v));
      }
    }
    svg.append(body);
    const hover = s("line", { class: "hover-line", y1: m.t, y2: m.t + ih, visibility: "hidden" });
    svg.append(hover);
    const capture = s("rect", { x: m.l, y: m.t, width: iw, height: ih, fill: "transparent" });
    svg.append(capture);
    capture.addEventListener("mousemove", (e) => {
      const r = svg.getBoundingClientRect();
      const px = ((e.clientX - r.left) / r.width) * w;
      const i = Math.min(data.length - 1, Math.max(0, Math.floor((px - m.l) / slot)));
      const d = data[i];
      if (!d) return;
      const cx = m.l + i * slot + slot / 2;
      hover.setAttribute("x1", cx); hover.setAttribute("x2", cx); hover.setAttribute("visibility", "visible");
      clear(tip, h("div", { class: "t" }, bucketLabel(d.t, hours)),
        active.map((sr) => h("div", { class: "row" }, h("span", {}, h("i", { style: { background: sr.color } }), sr.label),
          h("b", { class: "num" }, int(d[sr.key] || 0)))));
      tip.hidden = false;
      const left = ((cx / w) * r.width) + 12;
      tip.style.left = `${Math.min(left, r.width - tip.offsetWidth - 4)}px`;
      tip.style.top = "8px";
    });
    capture.addEventListener("mouseleave", () => { tip.hidden = true; hover.setAttribute("visibility", "hidden"); });
    plot.prepend(svg);
  }

  const ro = new ResizeObserver(() => draw());
  drawLegend();
  requestAnimationFrame(() => { draw(); ro.observe(plot); });
  return {
    el: wrap,
    update(next) { data = next; draw(); },
    destroy() { ro.disconnect(); },
  };
}

// ---------------------------------------------------------------- horizontal bars

/** items: [{label, value, sub, color, onClick}] */
export function hbars(items, { max, emptyText = "No data in this period." } = {}) {
  if (!items.length || items.every((i) => !i.value)) {
    return h("p", { class: "muted small" }, emptyText);
  }
  const top = max ?? Math.max(...items.map((i) => i.value), 1);
  return h("ul", { class: "hbars" }, items.map((it) => {
    const inner = [
      h("div", { class: "row" }, h("span", {}, it.label), h("span", {}, it.sub ?? int(it.value))),
      h("div", { class: "track" }, (it.parts || [{ value: it.value, color: it.color }]).map((p) =>
        h("div", { class: "fill", style: { width: `${(p.value / top) * 100}%`, background: p.color || COLORS.accent } }))),
    ];
    return h("li", {}, it.onClick ? h("button", { type: "button", class: "row-link", onclick: it.onClick }, inner) : inner);
  }));
}

// ---------------------------------------------------------------- donut

export function donut(items, { size = 140, centerLabel = "total" } = {}) {
  const total = items.reduce((a, i) => a + i.value, 0);
  const r = size / 2 - 10, c = size / 2, circ = 2 * Math.PI * r;
  const svg = s("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}`, role: "img",
    "aria-label": items.map((i) => `${i.label}: ${i.value}`).join(", ") });
  svg.append(s("circle", { cx: c, cy: c, r, fill: "none", stroke: "#1f2b40", "stroke-width": 14 }));
  let offset = 0;
  if (total) {
    for (const it of items) {
      if (!it.value) continue;
      const len = (it.value / total) * circ;
      svg.append(s("circle", { cx: c, cy: c, r, fill: "none", stroke: it.color, "stroke-width": 14,
        "stroke-dasharray": `${Math.max(0, len - 1.5)} ${circ}`, "stroke-dashoffset": -offset,
        transform: `rotate(-90 ${c} ${c})` }));
      offset += len;
    }
  }
  svg.append(s("text", { x: c, y: c - 2, "text-anchor": "middle", fill: "#f8fafc", "font-size": 20, "font-weight": 700,
    "font-family": "Archivo, sans-serif", text: int(total) }),
    s("text", { x: c, y: c + 16, "text-anchor": "middle", fill: "#94a3b8", "font-size": 11,
      "font-family": "Archivo, sans-serif", text: centerLabel }));
  return h("div", { class: "donut-wrap" }, svg,
    h("ul", { class: "donut-legend" }, items.map((it) => h("li", {}, h("i", { style: { background: it.color } }),
      it.label, h("b", {}, int(it.value), total ? h("span", { class: "faint" }, ` ${Math.round((it.value / total) * 100)}%`) : null)))));
}

// ---------------------------------------------------------------- column chart (histogram)

export function columns(items, { height = 180, color = COLORS.accent } = {}) {
  const wrap = h("div", { class: "chart" });
  const draw = () => {
    const w = Math.max(wrap.clientWidth || 400, 240);
    const m = { l: 36, r: 6, t: 10, b: 26 };
    const iw = w - m.l - m.r, ih = height - m.t - m.b;
    const max = niceMax(Math.max(1, ...items.map((i) => i.value)));
    const slot = iw / Math.max(items.length, 1);
    const svg = s("svg", { viewBox: `0 0 ${w} ${height}`, height, role: "img",
      "aria-label": items.map((i) => `${i.label}: ${i.value}`).join(", ") });
    const grid = s("g", { class: "grid" }), axis = s("g", { class: "axis" });
    for (let g = 0; g <= 4; g++) {
      const v = (max / 4) * g, yy = m.t + ih - (v / max) * ih;
      grid.append(s("line", { x1: m.l, x2: w - m.r, y1: yy + 0.5, y2: yy + 0.5 }));
      axis.append(s("text", { x: m.l - 8, y: yy + 4, "text-anchor": "end", text: int(v) }));
    }
    svg.append(grid, axis);
    items.forEach((it, i) => {
      const bh = (it.value / max) * ih, bw = slot * 0.62, x = m.l + i * slot + (slot - bw) / 2;
      const rect = s("rect", { x, y: m.t + ih - bh, width: bw, height: Math.max(bh, it.value ? 1 : 0), rx: 2, fill: it.color || color });
      rect.append(s("title", { text: `${it.label}: ${int(it.value)}` }));
      svg.append(rect, s("text", { x: x + bw / 2, y: height - 8, "text-anchor": "middle", fill: "#64748b", "font-size": 11,
        "font-family": "Archivo, sans-serif", text: it.label }));
      if (it.value) svg.append(s("text", { x: x + bw / 2, y: m.t + ih - bh - 4, "text-anchor": "middle", fill: "#94a3b8",
        "font-size": 10, "font-family": "Archivo, sans-serif", text: int(it.value) }));
    });
    clear(wrap, svg);
  };
  const ro = new ResizeObserver(draw);
  requestAnimationFrame(() => { draw(); ro.observe(wrap); });
  wrap.destroy = () => ro.disconnect();
  return wrap;
}

// ---------------------------------------------------------------- request ribbon

/** Every request as one tick: grey passed, amber suspicious, red blocked. */
export function ribbon(items, { onPick } = {}) {
  const wrap = h("figure", { class: "ribbon", style: { margin: 0, position: "relative" } });
  const tip = h("div", { class: "chart-tip", hidden: true });
  let svg;
  const draw = () => {
    const w = Math.max(wrap.clientWidth || 600, 200), hgt = 72, pad = 6;
    svg = s("svg", { viewBox: `0 0 ${w} ${hgt}`, preserveAspectRatio: "none", role: "img",
      "aria-label": `Last ${items.length} requests by verdict` });
    if (!items.length) {
      svg.append(s("text", { x: w / 2, y: hgt / 2 + 4, "text-anchor": "middle", fill: "#64748b", "font-size": 12,
        "font-family": "Archivo, sans-serif", text: "No requests yet" }));
    }
    const step = Math.min(6, (w - pad * 2) / Math.max(items.length, 1));
    const tick = Math.max(1, step * 0.6);
    const x0 = w - pad - items.length * step;
    const scale = { normal: 0.32, suspicious: 0.62, blocked: 1 };
    const full = hgt - pad * 2;
    items.forEach((it, i) => {
      const bh = Math.max(3, full * scale[it.verdict]);
      svg.append(s("rect", { class: `t-${it.verdict}`, x: (x0 + i * step).toFixed(2), y: (hgt - pad - bh).toFixed(2),
        width: tick.toFixed(2), height: bh.toFixed(2), rx: Math.min(1, tick / 2), "data-i": i }));
    });
    svg.addEventListener("mousemove", (e) => {
      const r = svg.getBoundingClientRect();
      const px = ((e.clientX - r.left) / r.width) * w;
      const i = Math.floor((px - x0) / step);
      svg.querySelectorAll(".t-hover").forEach((n) => n.classList.remove("t-hover"));
      const it = items[i];
      if (!it) { tip.hidden = true; return; }
      svg.querySelector(`rect[data-i="${i}"]`)?.classList.add("t-hover");
      clear(tip, h("div", { class: "t" }, new Date(it.ts).toLocaleTimeString("en-GB")),
        h("div", {}, `${it.method} ${it.path}`), h("div", { class: "muted" }, `${it.client_ip}, score ${it.score}`));
      tip.hidden = false;
      tip.style.left = `${Math.min(Math.max(0, e.clientX - r.left - 80), r.width - 180)}px`;
      tip.style.top = "-62px";
    });
    svg.addEventListener("mouseleave", () => { tip.hidden = true; });
    svg.addEventListener("click", (e) => {
      const r = svg.getBoundingClientRect();
      const i = Math.floor((((e.clientX - r.left) / r.width) * w - x0) / step);
      if (items[i] && onPick) onPick(items[i]);
    });
    clear(wrap, svg, tip);
  };
  const ro = new ResizeObserver(draw);
  requestAnimationFrame(() => { draw(); ro.observe(wrap); });
  wrap.update = (next) => { items = next; draw(); };
  wrap.destroy = () => ro.disconnect();
  return wrap;
}
