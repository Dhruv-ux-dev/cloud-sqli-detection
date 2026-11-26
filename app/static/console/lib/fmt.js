export const int = (n) => (n === null || n === undefined ? "—" : Number(n).toLocaleString("en-IN"));

export function num(n, digits = 1) {
  if (n === null || n === undefined) return "—";
  return Number(n).toLocaleString("en-IN", { maximumFractionDigits: digits });
}

export function time(iso) {
  return new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function dateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  const today = new Date().toDateString() === d.toDateString();
  return today
    ? d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

export function fullDateTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function ago(iso) {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export function bucketLabel(epoch, hours) {
  const d = new Date(epoch * 1000);
  if (hours >= 720) return d.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
  const hm = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  return hours > 24 ? `${d.toLocaleDateString("en-GB", { weekday: "short" })} ${hm}` : hm;
}

export const RANGE_LABELS = { 1: "Last hour", 6: "Last 6 hours", 24: "Last 24 hours", 168: "Last 7 days", 720: "Last 30 days" };
export const RANGE_SHORT = { 1: "1h", 6: "6h", 24: "24h", 168: "7d", 720: "30d" };

export const label = (s) => (s ? String(s).replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase()) : "—");

export const VERDICT_LABEL = { normal: "Allowed", suspicious: "Suspicious", blocked: "Blocked" };
export const VERDICT_CLASS = { normal: "allowed", suspicious: "suspicious", blocked: "blocked" };

export function micros(us) {
  if (us === null || us === undefined) return "—";
  return us >= 1000 ? `${(us / 1000).toFixed(2)} ms` : `${us} µs`;
}
