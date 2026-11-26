(() => {
  const form = document.getElementById("search");
  const input = document.getElementById("q");
  const msg = document.getElementById("search-msg");
  const table = document.getElementById("results");
  const tbody = table.querySelector("tbody");
  const empty = document.getElementById("empty");
  const record = document.getElementById("record");
  let me = null;
  let selectedId = null;

  function notice(text, kind = "") {
    msg.textContent = text;
    msg.className = "notice " + kind;
    msg.hidden = !text;
  }

  api("/api/me").then((user) => {
    me = user;
    document.getElementById("who").textContent = `${user.username} (${user.role})`;
  });

  api("/api/config").then((cfg) => {
    if (cfg.vulnerable_demo) setupUnsafe();
  }).catch(() => {});

  async function search(q) {
    notice("");
    try {
      const res = await api(`/api/customers?q=${encodeURIComponent(q)}`);
      tbody.replaceChildren(...res.results.map(row));
      table.hidden = res.results.length === 0;
      empty.hidden = true;
      if (res.results.length === 0) {
        notice(`No customers match “${q}”. Check the spelling, or search by city instead.`);
      } else if (res.truncated) {
        notice(`Showing the first ${res.limit} matches. Add more of the name to narrow it down.`);
      }
    } catch (err) {
      table.hidden = true;
      notice(err.message, err.status === 403 ? "error" : err.status === 429 ? "warn" : "error");
    }
  }

  function row(c) {
    const tr = el("tr", { "data-id": c.id, "aria-selected": c.id === selectedId ? "true" : "false" },
      el("td", {}, el("button", { class: "rowlink", type: "button", onclick: () => open(c.id) }, c.full_name)),
      el("td", {}, el("span", {}, `${c.city}, ${c.branch}`)),
      el("td", {}, el("span", { class: "masked" }, c.email)),
      el("td", {}, el("span", { class: "masked" }, c.account_no)),
    );
    return tr;
  }

  async function open(id, reveal = false) {
    selectedId = id;
    for (const tr of tbody.children) tr.setAttribute("aria-selected", String(Number(tr.dataset.id) === id));
    try {
      const c = await api(`/api/customers/${id}${reveal ? "?reveal=true" : ""}`);
      render(c);
    } catch (err) {
      record.replaceChildren(el("p", { class: "notice " + (err.status === 429 ? "warn" : "error") }, err.message));
    }
  }

  function render(c) {
    const fields = [
      ["Email", c.email], ["Phone", c.phone], ["PAN", c.pan], ["Account", c.account_no],
      ["Balance", c.balance], [c.masked ? "Customer since" : "Opened on", c.opened_on],
    ];
    const parts = [
      el("h2", {}, c.full_name),
      el("p", { class: "place" }, `${c.city}, ${c.branch} branch`),
      el("dl", {}, fields.flatMap(([k, v]) => [el("dt", {}, k), el("dd", { class: c.masked ? "masked" : "" }, v)])),
    ];
    if (c.masked) {
      parts.push(el("p", { class: "state muted" }, "Identifiers are masked. Balance is shown as a range."));
      if (me && me.role === "admin") {
        parts.push(el("button", { class: "btn quiet", type: "button", onclick: () => open(c.id, true) }, "Show full details"));
      }
    } else {
      parts.push(el("p", { class: "state revealed" }, "Full details shown. This view was recorded in the security log."));
      parts.push(el("button", { class: "btn quiet", type: "button", onclick: () => open(c.id) }, "Mask again"));
    }
    record.replaceChildren(...parts);
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (q.length < 2) { notice("Type at least two characters."); return; }
    search(q);
  });

  document.querySelectorAll("[data-try]").forEach((b) =>
    b.addEventListener("click", () => { input.value = b.dataset.try; search(b.dataset.try); }));

  function setupUnsafe() {
    const section = document.getElementById("unsafe");
    const uform = document.getElementById("unsafe-form");
    const uq = document.getElementById("uq");
    const sql = document.getElementById("unsafe-sql");
    const out = document.getElementById("unsafe-out");
    section.hidden = false;

    uform.addEventListener("submit", async (e) => {
      e.preventDefault();
      out.replaceChildren();
      sql.hidden = true;
      try {
        const res = await api(`/api/demo/unsafe-search?q=${encodeURIComponent(uq.value)}`);
        sql.textContent = res.query;
        sql.hidden = false;
        if (!res.rows.length) { out.append(el("p", { class: "muted" }, "The query ran and returned no rows.")); return; }
        const cols = Object.keys(res.rows[0]);
        out.append(el("table", { class: "results" },
          el("thead", {}, el("tr", {}, cols.map((c) => el("th", { scope: "col" }, c)))),
          el("tbody", {}, res.rows.map((r) => el("tr", {}, cols.map((c) => el("td", {}, String(r[c])))))),
        ));
      } catch (err) {
        if (err.body && err.body.query) {
          sql.textContent = err.body.query;
          sql.hidden = false;
          out.append(el("p", { class: "notice error" }, `Database error: ${err.body.database_error}`));
        } else {
          out.append(el("p", { class: "notice error" }, err.message));
        }
      }
    });
  }
})();
