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

const ISSUE_START = /;\s*(?=(?:HTTP\s+\d{3}\b|Cannot connect\b|Connection timeout\b|robots\.txt\b|TimeoutError\b|ClientConnectorError\b))/i;
const MAX_ISSUE_DETAILS = 12;

/** Make old persisted HTTP errors readable without echoing entire query strings or response pages. */
export function sourceIssues(errors: string[]) {
  const unique = new Set<string>();
  for (const error of errors) {
    for (const part of error.slice(0, 64000).split(ISSUE_START)) {
      const html = part.search(/<!doctype|<\/?(?:html|head|body|style|script|meta)\b/i);
      const plain = (html < 0 ? part : `${part.slice(0, html)} [response body omitted]`)
        .replace(/https?:\/\/[^\s<>]+/gi, (raw) => {
          try {
            const url = new URL(raw);
            return `${url.origin}${url.pathname}${url.search || url.hash ? "?…" : ""}`;
          } catch { return raw.split(/[?#]/, 1)[0] ?? raw; }
        })
        .replace(/\s+/g, " ").trim();
      if (plain) unique.add(plain.length > 400 ? `${plain.slice(0, 399)}…` : plain);
    }
  }
  const details = [...unique];
  const joined = details.join(" ");
  const reasons: string[] = [];
  if (/\b(?:HTTP\s+429|rate.limit|too many requests)\b/i.test(joined)) reasons.push(/\bHTTP\s+429\b/i.test(joined) ? "Rate limited (HTTP 429)" : "Rate limited");
  if (/robots\.txt disallows/i.test(joined)) reasons.push("Blocked by robots.txt");
  if (details.some((detail) => /robots\.txt/i.test(detail) && /timeout|timed out|Cannot connect|HTTP\s+[45]\d\d/i.test(detail))) reasons.push("robots.txt unavailable");
  if (/No address associated|Name or service not known|DNS (?:lookup|resolution).*fail/i.test(joined)) reasons.push("DNS lookup failed");
  if (/timeout|timed out/i.test(joined)) reasons.push("Connection timed out");
  if (/\bHTTP\s+5\d\d\b/i.test(joined)) reasons.push("Source server errors");
  if (/\bHTTP\s+4(?!29)\d\d\b/i.test(joined)) reasons.push("Source request errors");
  const summary = reasons.length
    ? `${reasons.slice(0, 2).join(" · ")}${reasons.length > 2 ? ` · ${reasons.length - 2} more issue types` : ""}`
    : (details[0] ?? "").slice(0, 150) + ((details[0]?.length ?? 0) > 150 ? "…" : "");
  return { summary, details: details.slice(0, MAX_ISSUE_DETAILS), omitted: Math.max(0, details.length - MAX_ISSUE_DETAILS) };
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
