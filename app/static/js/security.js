(() => {
  const SVG = "http://www.w3.org/2000/svg";
  const RANGE_LABEL = { 1: "hour", 6: "6 hours", 24: "24 hours", 168: "7 days" };
  const KIND_LABEL = {
    repeated_injection: "Repeated injection attempts",
    brute_force: "Repeated failed sign-ins",
    bulk_access: "Bulk record access",
    pii_reveal: "Unmasked record viewed",
  };
  const ALERT_LABEL = {
    sent: ["Alert emailed through SNS", "alert-sent"],
    logged: ["Alert logged (SNS not configured)", ""],
    suppressed: ["Alert held back: one was sent for this source in the last few minutes", ""],
    failed: ["Alert could not be sent. Check the SNS topic", "alert-failed"],
    none: ["No alert for this severity", ""],
  };

  let hours = 24;
  let data = null;
  let timer = null;

  const $ = (id) => document.getElementById(id);
  const plural = (n, one, many) => `${fmt.int(n)} ${n === 1 ? one : many}`;

  function svg(tag, attrs = {}) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  }

  api("/api/me").then((u) => { $("who").textContent = `${u.username} (${u.role})`; });

  async function load() {
    try {
      data = await api(`/api/admin/overview?hours=${hours}`);
      render();
    } catch (err) {
      $("updated").textContent = `Could not refresh: ${err.message}`;
    }
  }

  function render() {
    renderHead();
    renderRibbon();
    renderTimeline();
    renderIncidents();
    renderFlagged();
    renderBars();
    renderWaf();
    $("updated").textContent = `Updated at ${fmt.time(data.generated_at)}.`;
  }

  function renderHead() {
    $("mode-line").textContent = {
      aws: "AWS WAF filters traffic before it reaches the app. Figures include requests WAF blocked.",
      emulated: "Local run. The app stands in for AWS WAF, so it counts the blocked requests itself.",
      off: "Filtering is off for the controlled demo. Requests are classified but not blocked.",
    }[data.mode];

    const t = data.totals;
    const tally = $("tally");
    tally.replaceChildren(
      `In the last ${RANGE_LABEL[data.hours]}, the desk received `,
      el("b", {}, fmt.int(t.total)), t.total === 1 ? " request. " : " requests. ",
      el("b", { class: "pass" }, fmt.int(t.normal)), " passed, ",
      el("b", { class: "flag" }, fmt.int(t.suspicious)), " looked suspicious and ",
      el("b", { class: "block" }, fmt.int(t.blocked)), t.blocked === 1 ? " was blocked." : " were blocked.",
    );

    let split = "";
    if (data.mode === "aws") {
      split = `Of the blocked: ${plural(t.blocked_by_waf, "request", "requests")} stopped at AWS WAF, `
        + `${fmt.int(t.blocked_by_app)} by the application filter.`;
      if (data.waf && data.waf.error) split += ` WAF figures are incomplete (${data.waf.error}).`;
    }
    $("split").textContent = split;
  }

  // ---------------------------------------------------------- ribbon

  function ribbonItems() {
    const items = data.ribbon.map((r) => ({ ...r }));
    for (const s of (data.waf && data.waf.samples) || []) {
      items.push({ t: Date.parse(s.ts) / 1000, verdict: "blocked", method: s.method, path: s.uri,
                   client_ip: s.client_ip, status: 403, waf: s.rule });
    }
    items.sort((a, b) => a.t - b.t);
    return items.slice(-480);
  }

  function renderRibbon() {
    const box = $("ribbon");
    const w = Math.max(box.clientWidth, 200);
    const h = box.clientHeight || 112;
    box.setAttribute("viewBox", `0 0 ${w} ${h}`);
    box.replaceChildren();
    const items = ribbonItems();
    box._items = items;

    const pad = 10;
    const base = h - pad;
    box.append(svg("line", { class: "guide", x1: 0, x2: w, y1: base + 0.5, y2: base + 0.5 }));

    if (!items.length) {
      const t = svg("text", { class: "none", x: w / 2, y: h / 2 + 5, "text-anchor": "middle" });
      t.textContent = "No requests in this period yet";
      box.append(t);
      $("ribbon-from").textContent = "";
      return;
    }

    const step = Math.min(7, (w - pad * 2) / items.length);
    const tick = Math.max(1, step * 0.62);
    const x0 = w - pad - items.length * step;
    const scale = { normal: 0.34, suspicious: 0.64, blocked: 1 };
    const full = h - pad * 2;
    box._geom = { x0, step };

    items.forEach((it, i) => {
      const height = Math.max(3, full * scale[it.verdict]);
      box.append(svg("rect", {
        class: `t-${it.verdict}`,
        x: (x0 + i * step).toFixed(2),
        y: (base - height).toFixed(2),
        width: tick.toFixed(2),
        height: height.toFixed(2),
        rx: Math.min(1, tick / 2),
        "data-i": i,
      }));
    });
    $("ribbon-from").textContent = fmt.dateTime(items[0].t * 1000);
  }

  function ribbonHover(e) {
    const box = $("ribbon");
    const tip = $("tip");
    if (!box._items || !box._items.length || !box._geom) return;
    const rect = box.getBoundingClientRect();
    const vbW = box.viewBox.baseVal.width;
    const x = ((e.clientX - rect.left) / rect.width) * vbW;
    const i = Math.floor((x - box._geom.x0) / box._geom.step);
    box.querySelectorAll(".t-hover").forEach((r) => r.classList.remove("t-hover"));
    if (i < 0 || i >= box._items.length) { tip.hidden = true; return; }
    const it = box._items[i];
    box.querySelector(`rect[data-i="${i}"]`)?.classList.add("t-hover");
    const verdict = { normal: "Passed", suspicious: "Suspicious", blocked: it.waf ? "Blocked by AWS WAF" : "Blocked" }[it.verdict];
    tip.replaceChildren(
      el("strong", {}, `${verdict}, ${fmt.time(it.t * 1000)}`), el("br"),
      `${it.method} ${it.path}`, el("br"),
      `from ${it.client_ip}${it.status ? `, status ${it.status}` : ""}`,
    );
    const wrap = $("ribbon-wrap").getBoundingClientRect();
    const left = Math.min(Math.max(e.clientX - wrap.left, 110), wrap.width - 110);
    tip.style.left = `${left}px`;
    tip.hidden = false;
  }

  $("ribbon").addEventListener("mousemove", ribbonHover);
  $("ribbon").addEventListener("mouseleave", () => {
    $("tip").hidden = true;
    $("ribbon").querySelectorAll(".t-hover").forEach((r) => r.classList.remove("t-hover"));
  });

  // ---------------------------------------------------------- timeline

  function niceMax(v) {
    if (v <= 4) return 4;
    const mag = 10 ** Math.floor(Math.log10(v));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * mag >= v) return m * mag;
    return 10 * mag;
  }

  function bucketLabel(t) {
    const d = new Date(t * 1000);
    const hm = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    return data.hours > 24 ? `${d.toLocaleDateString("en-GB", { weekday: "short" })} ${hm}` : hm;
  }

  function renderTimeline() {
    const box = $("timeline");
    const w = Math.max(box.clientWidth, 260);
    const h = 220;
    const m = { l: 34, r: 4, t: 8, b: 24 };
    const series = data.timeline;
    const totals = series.map((s) => s.normal + s.suspicious + s.blocked + s.waf_blocked);
    const max = niceMax(Math.max(0, ...totals));
    const iw = w - m.l - m.r;
    const ih = h - m.t - m.b;
    const slot = iw / series.length;
    const bw = Math.max(2, slot * 0.7);
    const y = (v) => m.t + ih - (v / max) * ih;

    const root = svg("svg", { viewBox: `0 0 ${w} ${h}`, role: "img",
      "aria-label": `Requests per ${data.bucket_seconds / 60} minutes, stacked by verdict` });

    for (let g = 0; g <= 4; g++) {
      const v = (max / 4) * g;
      root.append(svg("line", { class: "grid", x1: m.l, x2: w - m.r, y1: y(v) + 0.5, y2: y(v) + 0.5 }));
      const label = svg("text", { class: "axis", x: m.l - 6, y: y(v) + 4, "text-anchor": "end" });
      label.textContent = fmt.int(v);
      root.append(label);
    }

    const every = Math.ceil(series.length / Math.max(2, Math.floor(iw / 90)));
    series.forEach((s, i) => {
      const x = m.l + i * slot + (slot - bw) / 2;
      let acc = 0;
      for (const [key, value] of [["normal", s.normal], ["suspicious", s.suspicious], ["blocked", s.blocked + s.waf_blocked]]) {
        if (!value) continue;
        const top = y(acc + value);
        const r = svg("rect", { class: `b-${key}`, x: x.toFixed(2), y: top.toFixed(2), width: bw.toFixed(2),
                                height: Math.max(1, y(acc) - top).toFixed(2) });
        const title = svg("title");
        title.textContent = `${bucketLabel(s.t)}: ${value} ${key === "normal" ? "passed" : key}`;
        r.append(title);
        root.append(r);
        acc += value;
      }
      if (i % every === 0) {
        const t = svg("text", { class: "axis", x: (x + bw / 2).toFixed(2), y: h - 6, "text-anchor": "middle" });
        t.textContent = bucketLabel(s.t);
        root.append(t);
      }
    });
    box.replaceChildren(root);
  }

  // ---------------------------------------------------------- lists

  function renderIncidents() {
    const list = $("incidents");
    if (!data.incidents.length) {
      list.replaceChildren(el("li", {}, el("p", { class: "muted summary" },
        "No incidents in this period. Repeated attacks, failed sign-ins or bulk reading will show here.")));
      return;
    }
    list.replaceChildren(...data.incidents.map((i) => {
      const [alertText, alertClass] = ALERT_LABEL[i.alert] || [i.alert, ""];
      return el("li", { class: i.severity },
        el("p", { class: "what" }, KIND_LABEL[i.kind] || i.kind),
        el("p", { class: "summary" }, i.summary),
        el("p", { class: "meta" }, fmt.dateTime(i.ts), ". ", el("span", { class: alertClass }, alertText), "."),
      );
    }));
  }

  function renderFlagged() {
    const body = $("flagged").querySelector("tbody");
    if (!data.flagged.length) {
      body.replaceChildren(el("tr", { class: "empty-row" }, el("td", { colspan: 5 },
        "Nothing flagged in this period. Run tools/sqli_test.py against this deployment to exercise the filters.")));
      return;
    }
    body.replaceChildren(...data.flagged.map((r) => {
      const tr = el("tr", { tabindex: "0", "aria-expanded": "false" },
        el("td", { class: "when" }, fmt.dateTime(r.ts)),
        el("td", { class: "ip" }, r.client_ip, r.username ? el("div", { class: "muted small" }, r.username) : null),
        el("td", { class: "req" }, el("span", { class: "m" }, r.method), r.path),
        el("td", {}, el("span", { class: `verdict ${r.verdict}` },
          r.verdict === "suspicious" ? "Suspicious" : r.status === 403 ? "Blocked" : "Not enforced")),
        el("td", {},
          el("span", { class: "payload" }, r.sample || "(no sample)"),
          el("span", { class: "rules" }, `Score ${r.score}. Rules: ${r.rule_ids.join(", ")}. Stopped by: ${r.source}.`)),
      );
      const toggle = () => {
        const open = tr.classList.toggle("open");
        tr.setAttribute("aria-expanded", String(open));
      };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      return tr;
    }));
  }

  function barList(target, rows, label, emptyText) {
    if (!rows.length) {
      target.replaceChildren(el("li", { class: "empty" }, emptyText));
      return;
    }
    const max = Math.max(...rows.map((r) => r.n));
    target.replaceChildren(...rows.map((r) => {
      const track = el("div", { class: "track" });
      if (r.blocked !== undefined) {
        track.append(el("div", { class: "fill blocked", style: `width:${(r.blocked / max) * 100}%` }));
        track.append(el("div", { class: "fill", style: `width:${((r.n - r.blocked) / max) * 100}%` }));
      } else {
        track.append(el("div", { class: "fill blocked", style: `width:${(r.n / max) * 100}%` }));
      }
      return el("li", {},
        el("div", { class: "row" }, el("span", { class: "label" }, label(r)),
          el("span", { class: "count" }, r.blocked !== undefined ? `${fmt.int(r.n)} flagged, ${fmt.int(r.blocked)} blocked` : fmt.int(r.n))),
        track);
    }));
  }

  function renderBars() {
    barList($("top-ips"), data.top_ips, (r) => r.client_ip, "No flagged sources in this period.");
    barList($("top-rules"), data.top_rules, (r) => r.description, "No rules matched in this period.");
  }

  function renderWaf() {
    const note = $("waf-note");
    const table = $("waf");
    const waf = data.waf || {};
    if (!waf.available) {
      note.textContent = data.mode === "aws"
        ? "WAF metrics are not configured. Set WAF_WEB_ACL_NAME and AWS_REGION."
        : "AWS WAF is not in front of a local run. Deploy with Terraform to see requests WAF blocks here.";
      table.hidden = true;
      return;
    }
    const samples = waf.samples || [];
    note.textContent = samples.length
      ? `${plural(waf.blocked, "request", "requests")} blocked by AWS WAF in this period. Below are WAF's own samples from the last 3 hours.`
      : `${plural(waf.blocked, "request", "requests")} blocked by AWS WAF in this period. WAF keeps samples for 3 hours, and none are left in that window.`
        + (waf.samples_error ? ` (${waf.samples_error})` : "");
    table.hidden = !samples.length;
    table.querySelector("tbody").replaceChildren(...samples.map((s) => el("tr", {},
      el("td", { class: "when" }, fmt.dateTime(s.ts)),
      el("td", { class: "ip" }, s.client_ip, s.country ? el("div", { class: "muted small" }, s.country) : null),
      el("td", { class: "req" }, el("span", { class: "m" }, s.method), s.uri),
      el("td", {}, s.rule),
    )));
  }

  // ---------------------------------------------------------- controls

  document.querySelectorAll("[data-hours]").forEach((b) => b.addEventListener("click", () => {
    hours = Number(b.dataset.hours);
    document.querySelectorAll("[data-hours]").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    load();
  }));

  function schedule() {
    clearInterval(timer);
    if ($("live").checked) timer = setInterval(() => { if (!document.hidden) load(); }, 10000);
  }
  $("live").addEventListener("change", schedule);

  let resizeFrame = 0;
  window.addEventListener("resize", () => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(() => { if (data) { renderRibbon(); renderTimeline(); } });
  });

  load();
  schedule();
})();
