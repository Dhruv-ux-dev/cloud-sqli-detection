// Server-paginated, sortable data table with loading, empty and error states.
import { h, clear } from "./dom.js";
import { icon } from "./icons.js";
import { pager, loading, emptyState, errorState } from "./ui.js";

/**
 * columns: [{ key, label, render(row) -> Node|string, sort: "server-sort-key", cls, width }]
 * fetch({page, sort, order}) -> Promise<{items,total,page,pages,page_size}>
 */
export function dataTable({ columns, fetch, onRow, emptyTitle = "Nothing here yet", emptyText = "",
                            sort = null, order = "desc", rowClass, caption, selectedId }) {
  const state = { page: 1, sort, order, data: null, selected: selectedId ?? null };
  const wrap = h("div", { class: "dt" });
  const tableWrap = h("div", { class: "table-wrap" });
  const foot = h("div");
  wrap.append(tableWrap, foot);
  let seq = 0;

  function header() {
    return h("thead", {}, h("tr", {}, columns.map((c) => {
      const sorted = c.sort && state.sort === c.sort;
      const th = h("th", { scope: "col", class: c.cls || null, style: c.width ? { width: c.width } : null,
        "aria-sort": sorted ? (state.order === "asc" ? "ascending" : "descending") : null });
      if (c.sort) {
        th.append(h("button", { type: "button", onclick: () => {
          state.order = state.sort === c.sort && state.order === "desc" ? "asc" : "desc";
          state.sort = c.sort;
          state.page = 1;
          load();
        } }, c.label, icon(sorted ? (state.order === "asc" ? "up" : "down") : "sort")));
      } else th.append(c.label);
      return th;
    })));
  }

  function render(fresh = new Set()) {
    const d = state.data;
    const table = h("table", { class: "data" }, caption ? h("caption", { class: "sr-only" }, caption) : null, header());
    const body = h("tbody");
    for (const row of d.items) {
      const tr = h("tr", { class: [onRow ? "clickable" : "", rowClass ? rowClass(row) : "", fresh.has(row.id) ? "fresh" : "",
        state.selected !== null && row.id === state.selected ? "selected" : ""].join(" ").trim() || null });
      if (onRow) {
        tr.tabIndex = 0;
        tr.addEventListener("click", (e) => { if (!e.target.closest("button, a, input, select")) { state.selected = row.id; mark(); onRow(row); } });
        tr.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target === tr) { state.selected = row.id; mark(); onRow(row); } });
      }
      for (const c of columns) {
        const v = c.render ? c.render(row) : row[c.key];
        tr.append(h("td", { class: c.cls || null }, v ?? "—"));
      }
      body.append(tr);
    }
    table.append(body);
    clear(tableWrap, d.items.length ? table : emptyState(emptyTitle, emptyText));
    clear(foot, d.total > d.page_size || d.page > 1 ? pager(d, (p) => { state.page = p; load(); }) : null);
  }

  function mark() {
    tableWrap.querySelectorAll("tbody tr").forEach((tr, i) => {
      tr.classList.toggle("selected", state.data.items[i]?.id === state.selected);
    });
  }

  async function load({ silent = false } = {}) {
    const my = ++seq;
    if (!silent || !state.data) clear(tableWrap, h("div", { class: "card-body" }, loading(5)));
    try {
      const data = await fetch({ page: state.page, sort: state.sort, order: state.order });
      if (my !== seq) return;
      const before = new Set((state.data?.items || []).map((r) => r.id));
      const fresh = silent && state.data ? new Set(data.items.filter((r) => !before.has(r.id)).map((r) => r.id)) : new Set();
      state.data = data;
      render(fresh);
    } catch (err) {
      if (my !== seq) return;
      if (!silent || !state.data) clear(tableWrap, errorState(err.message, () => load()));
    }
  }

  return {
    el: wrap,
    load,
    reload: () => { state.page = 1; return load(); },
    refresh: () => load({ silent: true }),
    get data() { return state.data; },
  };
}
