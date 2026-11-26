// Fetch wrapper: same-origin cookies, CSRF header on state-changing calls,
// consistent error messages, session expiry handling.

export class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

export async function api(path, { method = "GET", body, raw = false, signal } = {}) {
  const init = { method, credentials: "same-origin", headers: {}, signal };
  if (method !== "GET") init.headers["X-Northfield-CSRF"] = "1";
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (err) {
    if (err.name === "AbortError") throw err;
    throw new ApiError("The server did not respond. Check that it is running and try again.", 0, null);
  }
  if (raw && res.ok) return res;
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (res.ok) return data;

  if (res.status === 401) {
    window.location.assign("/");
    throw new ApiError("Your session ended. Sign in again.", 401, data);
  }
  let message;
  if (data && typeof data.detail === "string") message = data.detail;
  else if (data && Array.isArray(data.detail)) message = data.detail.map((d) => `${d.loc.slice(-1)[0]}: ${d.msg}`).join("; ");
  else if (data && data.error) message = data.error;
  else if (res.status === 403) message = "Blocked by AWS WAF.";
  else message = `The server answered with status ${res.status}.`;
  throw new ApiError(message, res.status, data);
}

export async function download(path, fallbackName) {
  const res = await api(path, { raw: true });
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const name = (cd.match(/filename="([^"]+)"/) || [])[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  return name;
}

export function qs(params) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)) continue;
    p.set(k, Array.isArray(v) ? v.join(",") : String(v));
  }
  const s = p.toString();
  return s ? "?" + s : "";
}

export function b64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
