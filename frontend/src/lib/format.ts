export type R = Record<string, any>;

export const present = (v: unknown) => v !== null && v !== undefined && v !== "";

export const text = (v: unknown, fallback = "unknown") => (present(v) ? String(v) : fallback);

export function num(v: unknown, fallback = "unknown") {
  if (!present(v) || typeof v === "boolean") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString() : String(v);
}

export function percent(v: unknown, fallback = "unknown") {
  if (!present(v) || typeof v === "boolean") return fallback;
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return `${(n * 100).toFixed(n < 0.01 ? 2 : 1)}%`;
}

export function yesNo(v: unknown) {
  if (v === true || v === 1) return "yes";
  if (v === false || v === 0) return "no";
  return "unknown";
}

export function fmtDate(v: unknown, precise = false, fallback = "unknown") {
  if (!present(v) || (typeof v !== "string" && typeof v !== "number")) return fallback;
  const raw = typeof v === "string" ? v.trim() : v;
  const dateOnly = typeof raw === "string" && /^\d{4}-\d{2}-\d{2}$/.test(raw);
  const naiveUtc = typeof raw === "string" && /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(raw);
  const parsed = typeof raw === "number" ? (raw < 1e12 ? raw * 1000 : raw) : dateOnly ? `${raw}T00:00:00Z` : naiveUtc ? `${raw.replace(" ", "T")}Z` : raw;
  const d = new Date(parsed);
  if (Number.isNaN(d.getTime())) return String(v);
  if (dateOnly) return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
  return precise
    ? d.toLocaleString()
    : d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function toArray(v: unknown): any[] {
  if (Array.isArray(v)) return v;
  if (!present(v)) return [];
  if (typeof v === "string") {
    try {
      const parsed = JSON.parse(v);
      if (Array.isArray(parsed)) return parsed;
    } catch {}
  }
  return [v];
}

export function describe(v: unknown): string {
  if (!present(v)) return "";
  if (typeof v !== "object") return String(v);
  const o = v as R;
  for (const k of ["name", "product", "criteria", "cpe", "package", "value", "url", "title", "reason", "message"]) {
    if (present(o[k]) && typeof o[k] !== "object") return String(o[k]);
  }
  if (o["package"] && typeof o["package"] === "object" && present(o["package"]["name"])) return String(o["package"]["name"]);
  return JSON.stringify(v);
}

export function safeHref(v: unknown): string | null {
  if (typeof v !== "string") return null;
  try {
    const u = new URL(v);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

export function host(v: unknown) {
  const h = safeHref(v);
  return h ? new URL(h).hostname : "unknown";
}

export function severityLabel(v: unknown) {
  if (!present(v) || typeof v === "boolean") return { label: "Unscored", tone: "" };
  const n = Number(v);
  if (!Number.isFinite(n)) return { label: String(v), tone: "" };
  const name = n >= 9 ? "Critical" : n >= 7 ? "High" : n >= 4 ? "Medium" : n > 0 ? "Low" : "None";
  return { label: `${n.toFixed(1)} ${name}`, tone: n >= 9 ? "kev" : n >= 7 ? "warn" : "" };
}

export const humanize = (v: unknown) => text(v).replaceAll("_", " ");

export function confidence(v: unknown) {
  if (!present(v) || typeof v === "boolean") return "unknown";
  const n = Number(v);
  return Number.isFinite(n) ? `${Math.round(n * 100)}%` : String(v);
}
