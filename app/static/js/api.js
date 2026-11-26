/* Shared helpers. All page text from the server goes into the DOM through
   textContent (via el()), never innerHTML: the dashboard shows raw attack
   payloads, and they must render as text. */

class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function api(path, options = {}) {
  const init = { credentials: "same-origin", headers: {}, ...options };
  if (init.body && typeof init.body !== "string") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError("The server did not respond. Check your connection and try again.", 0, null);
  }
  const text = await res.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }

  if (res.ok) return body;

  if (res.status === 401 && !path.startsWith("/api/login")) {
    window.location.assign("/");
    throw new ApiError("Your session ended. Sign in again.", 401, body);
  }
  let message;
  if (res.status === 403 && body && body.blocked_by) {
    message = `Blocked by the ${body.blocked_by}: the input looked like SQL injection.`;
  } else if (res.status === 403 && !body) {
    // AWS WAF answers with its own page, not our JSON.
    message = "Blocked by AWS WAF: the input looked like SQL injection.";
  } else if (body && typeof body.detail === "string") {
    message = body.detail;
  } else if (body && Array.isArray(body.detail)) {
    message = "Check the input: " + body.detail.map((d) => d.msg).join("; ");
  } else if (body && body.error) {
    message = body.error;
  } else {
    message = `The server answered with status ${res.status}.`;
  }
  throw new ApiError(message, res.status, body);
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "style") {
      // CSSOM, not the style attribute: the CSP blocks inline style attributes.
      for (const decl of String(v).split(";")) {
        const [prop, ...rest] = decl.split(":");
        if (prop && rest.length) node.style.setProperty(prop.trim(), rest.join(":").trim());
      }
    }
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const fmt = {
  int: (n) => Number(n || 0).toLocaleString("en-IN"),
  time: (iso) => new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  dateTime: (iso) => {
    const d = new Date(iso);
    const today = new Date().toDateString() === d.toDateString();
    return today
      ? d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })
      : d.toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  },
};

async function signOut() {
  try { await api("/api/logout", { method: "POST" }); } finally { window.location.assign("/"); }
}

document.addEventListener("click", (e) => {
  if (e.target.closest("[data-signout]")) { e.preventDefault(); signOut(); }
});
