import { h, clear } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { api } from "../lib/api.js";
import { card, pageHead, loading, errorState, toast, badge, formModal } from "../lib/ui.js";
import { dateTime } from "../lib/fmt.js";

const PASSWORD_HELP = "At least 12 characters with upper-case, lower-case letters and digits.";

export default async function users(ctx) {
  const el = h("div", { class: "page" }, loading(6));

  async function load() {
    let d;
    try { d = await api("/api/users"); } catch (err) { clear(el, errorState(err.message, load)); return; }
    const roleOptions = d.roles.map((r) => ({ value: r.key, label: r.label }));
    const allPerms = [...new Set(d.roles.flatMap((r) => r.permissions))].sort();
    clear(el,
      pageHead("Users & Roles", "Accounts and what each role may do. Permissions are enforced by the API; the console only hides controls a role cannot use.",
        [h("button", { class: "btn primary", type: "button", onclick: () => formModal({
          title: "Create user", fields: [
            { name: "username", label: "Username", required: true, placeholder: "e.g. priya.analyst", maxlength: 32 },
            { name: "display_name", label: "Display name", required: true, maxlength: 80 },
            { name: "role", label: "Role", type: "select", options: roleOptions, value: "viewer" },
            { name: "password", label: "Initial password", type: "password", required: true, help: PASSWORD_HELP, autocomplete: "new-password" },
          ], submitLabel: "Create user",
          onSubmit: async (v) => { await api("/api/users", { method: "POST", body: v }); toast(`Created ${v.username}.`); load(); },
        }) }, icon("plus"), "Create user")]),
      h("section", { class: "card" }, h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("caption", { class: "sr-only" }, "Users"),
        h("thead", {}, h("tr", {}, ["User", "Role", "Status", "Last sign-in", "Created", ""].map((t) => h("th", { scope: "col" }, t)))),
        h("tbody", {}, d.items.map((u) => h("tr", {},
          h("td", {}, h("strong", {}, u.display_name || u.username), h("div", { class: "faint tiny mono" }, u.username)),
          h("td", {}, u.role_label),
          h("td", {}, u.is_active ? badge("healthy", "Active") : badge("informational", "Deactivated")),
          h("td", { class: "nowrap" }, u.last_login_at ? dateTime(u.last_login_at) : h("span", { class: "faint" }, "never")),
          h("td", { class: "nowrap" }, dateTime(u.created_at)),
          h("td", { class: "r" }, h("div", { class: "page-actions", style: { "justify-content": "flex-end" } },
            h("button", { class: "btn sm", type: "button", onclick: () => formModal({
              title: `Change role for ${u.username}`, description: "Changing the role signs the user out everywhere.",
              fields: [{ name: "role", label: "Role", type: "select", options: roleOptions, value: u.role }], submitLabel: "Change role",
              onSubmit: async (v) => { await api(`/api/users/${u.id}`, { method: "PATCH", body: { role: v.role } }); toast("Role changed."); load(); },
            }) }, "Role"),
            h("button", { class: "btn sm", type: "button", onclick: () => formModal({
              title: `Reset password for ${u.username}`, description: "Existing sessions for this user end immediately.",
              fields: [{ name: "password", label: "New password", type: "password", required: true, help: PASSWORD_HELP, autocomplete: "new-password" }],
              submitLabel: "Reset password",
              onSubmit: async (v) => { await api(`/api/users/${u.id}/password`, { method: "POST", body: v }); toast("Password reset."); },
            }) }, icon("key"), "Password"),
            h("button", { class: `btn sm ${u.is_active ? "danger" : ""}`, type: "button", onclick: () => formModal({
              title: `${u.is_active ? "Deactivate" : "Activate"} ${u.username}?`,
              description: u.is_active ? "The user is signed out and cannot sign in until reactivated. Their history stays." : "The user can sign in again.",
              submitLabel: u.is_active ? "Deactivate" : "Activate", danger: u.is_active,
              onSubmit: async () => { await api(`/api/users/${u.id}`, { method: "PATCH", body: { is_active: !u.is_active } }); toast(u.is_active ? "Deactivated." : "Activated."); load(); },
            }) }, u.is_active ? "Deactivate" : "Activate"))))))))),
      card({ title: "Role permissions", sub: "Enforced on every API call", cls: "mt", body: h("div", { class: "table-wrap" }, h("table", { class: "data perm-matrix" },
        h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Permission"), d.roles.map((r) => h("th", { scope: "col" }, r.label)))),
        h("tbody", {}, allPerms.map((p) => h("tr", {}, h("td", { class: "mono" }, p),
          d.roles.map((r) => h("td", {}, r.permissions.includes(p) ? h("span", { class: "yes", "aria-label": "allowed" }, "✓") : h("span", { class: "no", "aria-label": "not allowed" }, "–")))))))) }));
  }
  load();
  return { el };
}
