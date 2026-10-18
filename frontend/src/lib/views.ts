export const TABS = ["intelligence", "warnings", "infrastructure", "news", "changes", "collectors"] as const;
export type Tab = (typeof TABS)[number];
export type DataTab = Exclude<Tab, "collectors">;

export const PAGE = 50;
export const VERSION_STATES = ["exact", "affected_range", "unknown", "version_unverified"] as const;
export const EVENT_KINDS: Record<string, string> = {
  advisory_added: "Advisory added",
  advisory_changed: "Advisory changed",
  kev_added: "Added to KEV",
  kev_removed: "Removed from KEV",
  warning_opened: "Warning opened",
  warning_resolved: "Warning resolved",
};

export type View = {
  tab: Tab;
  q: string;
  kind: string;
  event_kind: string;
  kev: boolean;
  version_state: string;
  sort: "rank" | "newest";
  offset: number;
};

export const VIEWS: Record<DataTab, { title: string; endpoint: string; exportKind: string; placeholder: string; noun: string }> = {
  intelligence: { title: "Vulnerability intelligence", endpoint: "/api/advisories", exportKind: "advisories", placeholder: "Search advisories, products, CVEs…", noun: "advisories" },
  warnings: { title: "Potential exposure matches", endpoint: "/api/alerts", exportKind: "alerts", placeholder: "Search assets, products, CVEs…", noun: "potential matches" },
  infrastructure: { title: "Infrastructure inventory", endpoint: "/api/search", exportKind: "entities", placeholder: "Search entities, vendors, technologies…", noun: "entities" },
  news: { title: "Reports and research", endpoint: "/api/articles", exportKind: "articles", placeholder: "Search reports, sources, CVEs…", noun: "reports" },
  changes: { title: "Changes observed locally", endpoint: "/api/events", exportKind: "events", placeholder: "Search changes, subjects, CVEs…", noun: "local changes" },
};

const str = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");

export function parseView(raw: Record<string, unknown>): View {
  const tab = (TABS as readonly string[]).includes(str(raw["tab"])) ? (str(raw["tab"]) as Tab) : "intelligence";
  const offset = Number(raw["offset"] ?? 0);
  const vs = str(raw["version_state"]);
  const ek = str(raw["event_kind"]);
  return {
    tab,
    q: str(raw["q"]),
    kind: str(raw["kind"]),
    event_kind: Object.hasOwn(EVENT_KINDS, ek) ? ek : "",
    kev: raw["kev"] === true || raw["kev"] === "true",
    version_state: (VERSION_STATES as readonly string[]).includes(vs) ? vs : "",
    sort: raw["sort"] === "newest" ? "newest" : "rank",
    offset: Number.isSafeInteger(offset) && offset > 0 ? Math.floor(offset / PAGE) * PAGE : 0,
  };
}

export function compactView(v: View): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = { tab: v.tab };
  if (v.q) out["q"] = v.q;
  if (v.tab === "infrastructure" && v.kind) out["kind"] = v.kind;
  if (v.tab === "changes" && v.event_kind) out["event_kind"] = v.event_kind;
  if (v.tab === "intelligence" || v.tab === "warnings") {
    if (v.kev) out["kev"] = true;
    if (v.sort !== "rank") out["sort"] = v.sort;
  }
  if (v.tab === "warnings" && v.version_state) out["version_state"] = v.version_state;
  if (v.offset) out["offset"] = v.offset;
  return out;
}

export function listParams(v: View): Record<string, string> {
  const p: Record<string, string> = { limit: String(PAGE), offset: String(v.offset) };
  if (v.q) p["q"] = v.q;
  if (v.tab === "infrastructure" && v.kind) p["kind"] = v.kind;
  if (v.tab === "changes" && v.event_kind) p["kind"] = v.event_kind;
  if (v.tab === "intelligence" || v.tab === "warnings") {
    if (v.kev) p["kev"] = "true";
    p["sort"] = v.sort;
  }
  if (v.tab === "warnings" && v.version_state) p["version_state"] = v.version_state;
  return p;
}

export function exportParams(v: View): Record<string, string> {
  const p: Record<string, string> = { kind: VIEWS[v.tab as DataTab].exportKind };
  if (v.q) p["q"] = v.q;
  if (v.tab === "infrastructure" && v.kind) p["entity_kind"] = v.kind;
  if (v.tab === "changes" && v.event_kind) p["event_kind"] = v.event_kind;
  if (v.tab === "intelligence" || v.tab === "warnings") {
    if (v.kev) p["kev"] = "true";
    p["sort"] = v.sort;
  }
  if (v.tab === "warnings" && v.version_state) p["version_state"] = v.version_state;
  return p;
}

export function clampOffset(offset: number, total: number) {
  if (offset <= 0) return 0;
  if (total <= 0) return 0;
  if (offset < total) return offset;
  return Math.floor((total - 1) / PAGE) * PAGE;
}
