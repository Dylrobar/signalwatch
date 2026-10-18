import { describe, toArray, type R } from "./format";

export const FAMILIES = ["nvd", "kev", "epss", "github", "osv", "cve_program", "csaf", "network", "wikidata", "news", "web"];

export type Health = "collecting" | "error" | "partial" | "interrupted" | "disabled" | "not_collected" | "healthy" | "unknown";

export function sourceErrors(s: R): string[] {
  const out = new Set<string>();
  if (s?.["error"]) out.add(describe(s["error"]));
  const e = s?.["counts"]?.["errors"];
  if (typeof e === "number" && e > 0) out.add(`${e} errors reported`);
  else if (typeof e === "string" && e) out.add(e);
  else if (Array.isArray(e))
    for (const item of e) {
      if (item && typeof item === "object") {
        const where = item["source"] || item["name"] || item["url"];
        const what = item["error"] || item["message"] || describe(item);
        out.add([where, what].filter(Boolean).join(": "));
      } else if (item) out.add(String(item));
    }
  return [...out].filter(Boolean);
}

export function sourceHealth(s: R, running: boolean): Health {
  if (running) return "collecting";
  if (!s["persisted"]) return s["enabled"] === false ? "disabled" : "not_collected";
  if (s["status"] === "error") return "error";
  if (s["status"] === "interrupted") return "interrupted";
  if (s["status"] === "running") return "collecting";
  if (sourceErrors(s).length || s["status"] === "partial") return s["last_success"] ? "partial" : "error";
  if (s["enabled"] === false) return "disabled";
  if (s["last_success"]) return "healthy";
  return "unknown";
}

export function sourceRecords(s: R): number | null {
  const c = s?.["counts"];
  if (!c || typeof c !== "object") return null;
  for (const key of ["records", "advisories", "articles", "observations", "kev", "epss", "companies", "enriched", "entities", "domains"])
    if (typeof c[key] === "number" && Number.isFinite(c[key])) return c[key];
  return null;
}

export function mergeSources(status: R | undefined) {
  const configured: Record<string, boolean> = status?.["config"]?.["sources"] ?? {};
  const names = Object.keys(configured).length ? Object.keys(configured) : FAMILIES;
  const saved = toArray(status?.["sources"]).filter(Boolean).map((s) => (typeof s === "string" ? { name: s } : s)) as R[];
  const byName = new Map(saved.map((s) => [String(s["name"]), s]));
  const families: R[] = names.map((name) => ({
    name,
    enabled: configured[name],
    configured: Object.prototype.hasOwnProperty.call(configured, name),
    ...(byName.get(name) ?? {}),
    persisted: byName.has(name),
  }));
  const historical = saved.filter((s) => !names.includes(String(s["name"])));
  return { families, historical };
}

export function feedList(raw: unknown): R[] {
  if (Array.isArray(raw)) return raw.filter((f) => f && typeof f === "object" && !Array.isArray(f));
  if (raw && typeof raw === "object") return Object.entries(raw as R).filter(([, f]) => f && typeof f === "object" && !Array.isArray(f)).map(([url, f]) => ({ url, ...(f as R) }));
  return [];
}

export function sbomLimitMiB(status: R | undefined) {
  const n = Number(status?.["config"]?.["sbom_max_mb"]);
  return Number.isFinite(n) && n > 0 ? n : 20;
}
