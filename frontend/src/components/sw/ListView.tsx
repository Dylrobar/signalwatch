import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Download, RefreshCw, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api, ApiError, download } from "@/lib/api";
import { describe, fmtDate, host, humanize, num, text, toArray, confidence, type R } from "@/lib/format";
import { clampOffset, EVENT_KINDS, exportParams, listParams, PAGE, VERSION_STATES, VIEWS, type DataTab, type View } from "@/lib/views";
import { Badge, EventBadge, Notice, Severity, Signals } from "./bits";

const KIND_LABELS: Record<string, string> = {
  company: "Companies", domain: "Domains", ip: "IP addresses", asn: "Networks / ASNs", product: "Products",
  technology: "Technologies", device: "Devices", os: "Operating systems", url: "URLs", vendor: "Vendors",
  package: "Packages", vulnerability: "Vulnerability records",
};

type Props = {
  view: View;
  gen: number;
  stats: R | undefined;
  onChange: (patch: Partial<View>, replace?: boolean) => void;
  onOpen: (row: R, tab: DataTab) => void;
  onCollectors: () => void;
  onCreateCompany: () => void;
};

function advisoryTitle(item: R) {
  const t = item["title"] || "";
  if (t && t !== item["canonical_id"] && t !== item["id"]) return t;
  const s = String(item["summary"] || t || item["canonical_id"] || item["id"] || "").replace(/\s+/g, " ");
  return s.length > 175 ? `${s.slice(0, 175)}…` : s;
}

function Main({ id, title, sub }: { id?: unknown; title: unknown; sub?: unknown }) {
  return (
    <div className="min-w-[16rem] max-w-[42rem]">
      {id ? <div className="sw-mono">{String(id)}</div> : null}
      <div className="font-semibold leading-snug">{text(title, "Untitled")}</div>
      {sub ? <div className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">{String(sub)}</div> : null}
    </div>
  );
}

function cells(tab: DataTab, item: R, sort: string) {
  switch (tab) {
    case "intelligence": {
      const affected = toArray(item["affected"]).slice(0, 4).map(describe).join(" · ");
      return [
        <Severity value={item["severity"]} />,
        <Main id={item["canonical_id"] || item["id"]} title={advisoryTitle(item)} sub={affected || item["summary"]} />,
        <Signals item={item} />,
        fmtDate(sort === "newest" ? item["modified"] || item["published"] : item["published"]),
      ];
    }
    case "warnings":
      return [
        <div className="space-y-1">
          <Severity value={item["severity"]} />
          <div className="text-xs text-muted-foreground">Rank {num(item["rank"])}</div>
        </div>,
        <Main id={item["advisory_id"]} title={item["asset_name"] || item["asset_id"] || item["product"]} sub={item["title"]} />,
        <div className="space-y-1">
          <Badge tone="warn">{confidence(item["confidence"])} evidence</Badge>
          <div className="text-xs text-muted-foreground">{humanize(item["version_state"])}</div>
        </div>,
        <Signals item={item} />,
        fmtDate(sort === "newest" ? item["first_seen"] : item["last_seen"]),
      ];
    case "infrastructure": {
      const m = item["metadata"] && typeof item["metadata"] === "object" ? item["metadata"] : {};
      const ctx = [m["vendor"], m["product"], m["version"]].filter(Boolean).join(" · ");
      return [
        <Badge tone="ok">{text(item["kind"])}</Badge>,
        <Main title={item["name"] || item["value"]} sub={ctx || (item["name"] !== item["value"] ? item["value"] : "")} />,
        host(item["source_url"]),
        fmtDate(item["observed_at"] || item["updated_at"]),
      ];
    }
    case "news":
      return [
        <Main title={item["title"] || item["url"]} sub={item["summary"]} />,
        text(item["source"], host(item["url"])),
        <span className="font-mono text-xs">{toArray(item["cves"]).join(", ") || "none"}</span>,
        fmtDate(item["published"]),
      ];
    case "changes":
      return [
        <EventBadge kind={item["kind"]} />,
        <Main title={item["title"]} sub={item["subject_id"] || item["canonical_id"]} />,
        text(item["source"], host(item["url"])),
        fmtDate(item["observed_at"], true),
      ];
  }
}

function headers(tab: DataTab, sort: string) {
  switch (tab) {
    case "intelligence": return ["Severity", "Advisory / affected product", "Signals", sort === "newest" ? "Modified" : "Published"];
    case "warnings": return ["Priority", "Asset / advisory", "Match confidence", "Signals", sort === "newest" ? "First matched" : "Last seen"];
    case "infrastructure": return ["Type", "Entity", "Evidence source", "Observed"];
    case "news": return ["Report", "Source", "Referenced CVEs", "Published"];
    case "changes": return ["Change", "Event / subject", "Source", "Observed locally"];
  }
}

export function ListView({
  view,
  gen,
  stats,
  onChange,
  onOpen,
  onCollectors,
  onCreateCompany,
}: Props) {
  const tab = view.tab as DataTab;
  const cfg = VIEWS[tab];
  const [q, setQ] = useState(view.q);
  const [exporting, setExporting] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const searchRef = useRef<HTMLInputElement>(null);
  const changeRef = useRef(onChange);
  changeRef.current = onChange;

  useEffect(() => {
    clearTimeout(timer.current);
    setQ(view.q);
  }, [view.q, tab]);
  useEffect(() => () => clearTimeout(timer.current), []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = (e.target as HTMLElement)?.tagName;
      if (e.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(t) && !document.querySelector('[aria-modal="true"]')) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const params = listParams(view);
  const query = useQuery<{ items: R[]; total: number }, ApiError>({
    queryKey: ["list", gen, tab, params],
    queryFn: ({ signal }) => api(cfg.endpoint, { params, signal }),
    placeholderData: keepPreviousData,
    retry: false,
  });

  const items = toArray(query.data?.items) as R[];
  const total = Number(query.data?.total ?? items.length);
  const stale = query.isPlaceholderData;

  useEffect(() => {
    if (!query.data || stale) return;
    const fixed = clampOffset(view.offset, total);
    if (fixed !== view.offset) onChange({ offset: fixed }, true);
  }, [query.data, stale, total, view.offset, onChange]);

  const filtered = Boolean(view.q || (tab === "infrastructure" && view.kind) || (tab === "changes" && view.event_kind) || ((tab === "intelligence" || tab === "warnings") && view.kev) || (tab === "warnings" && view.version_state));
  const kinds: Record<string, number> = stats?.["entity_kinds"] ?? {};

  async function doExport() {
    setExporting(true);
    try {
      const size = await download("/api/export", exportParams(view), `signalwatch-${cfg.exportKind}.json`);
      toast.success(`Export downloaded (${num(size)} bytes, all filtered records).`);
    } catch (e) {
      if ((e as ApiError).kind !== "aborted") toast.error(`Export failed: ${(e as Error).message}`);
    } finally {
      setExporting(false);
    }
  }

  const sel = "sw-input w-auto";
  return (
    <section aria-labelledby="view-title" className="sw-panel overflow-hidden">
      <div className="border-b border-border p-3 sm:p-4">
        <h2 id="view-title" className="text-base font-semibold">{cfg.title}</h2>
        {tab === "changes" && <p className="mt-0.5 text-xs text-muted-foreground">Times are when this database observed the change, not original disclosure dates.</p>}
        {tab === "warnings" && <p className="mt-0.5 text-xs text-muted-foreground">Potential correlations between observed products and advisories. Match confidence is evidence strength, not exploitation probability.</p>}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <div className="relative min-w-0 flex-[1_1_16rem]">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              ref={searchRef}
              type="search"
              aria-label={cfg.placeholder}
              placeholder={cfg.placeholder}
              className="sw-input pl-8"
              value={q}
              onChange={(e) => {
                const v = e.target.value;
                setQ(v);
                clearTimeout(timer.current);
                timer.current = setTimeout(() => changeRef.current({ q: v.trim(), offset: 0 }, true), 250);
              }}
            />
          </div>
          {tab === "infrastructure" && (
            <select aria-label="Entity type" className={sel} value={view.kind} onChange={(e) => onChange({ kind: e.target.value, offset: 0 })}>
              <option value="">All entity types</option>
              {Object.keys(kinds).sort().map((k) => (
                <option key={k} value={k}>{KIND_LABELS[k] ?? k} ({num(kinds[k])})</option>
              ))}
              {view.kind && !Object.hasOwn(kinds, view.kind) && <option value={view.kind}>{view.kind}</option>}
            </select>
          )}
          {tab === "changes" && (
            <select aria-label="Change type" className={sel} value={view.event_kind} onChange={(e) => onChange({ event_kind: e.target.value, offset: 0 })}>
              <option value="">All changes</option>
              {Object.entries(EVENT_KINDS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
          )}
          {tab === "warnings" && (
            <select aria-label="Version state" className={sel} value={view.version_state} onChange={(e) => onChange({ version_state: e.target.value, offset: 0 })}>
              <option value="">All version states</option>
              {VERSION_STATES.map((v) => <option key={v} value={v}>{v.replaceAll("_", " ")}</option>)}
            </select>
          )}
          {(tab === "intelligence" || tab === "warnings") && (
            <>
              <select aria-label="Sort" className={sel} value={view.sort} onChange={(e) => onChange({ sort: e.target.value as View["sort"], offset: 0 })}>
                <option value="rank">Highest signal</option>
                <option value="newest">Newest</option>
              </select>
              <label className="flex items-center gap-1.5 text-sm text-muted-foreground">
                <input type="checkbox" checked={view.kev} onChange={(e) => onChange({ kev: e.target.checked, offset: 0 })} />
                Known exploited only
              </label>
            </>
          )}
          {tab === "infrastructure" && (
            <button type="button" className="sw-btn-primary" onClick={onCreateCompany}>
              Add company
            </button>
          )}
          <button type="button" className="sw-btn" onClick={() => query.refetch()} disabled={query.isFetching}>
            <RefreshCw className={`h-3.5 w-3.5 ${query.isFetching ? "animate-spin" : ""}`} aria-hidden /> Refresh
          </button>
          <button type="button" className="sw-btn" onClick={doExport} disabled={exporting || !query.data}>
            <Download className="h-3.5 w-3.5" aria-hidden /> {exporting ? "Exporting…" : "Export"}
          </button>
        </div>
      </div>

      <div className="flex items-center justify-between gap-2 border-b border-border bg-background/40 px-3 py-1.5 text-xs text-muted-foreground sm:px-4" aria-live="polite">
        <span>
          {query.isPending ? "Loading…" : query.error && !query.data ? "Unable to load records" : `${num(total)} ${cfg.noun}${filtered ? " matching filters" : ""}`}
          {query.isFetching && query.data ? " · updating…" : ""}
        </span>
        {query.dataUpdatedAt > 0 && <span>Updated {new Date(query.dataUpdatedAt).toLocaleTimeString()}</span>}
      </div>

      {query.error && (
        <div className="p-3 sm:p-4">
          <Notice tone="danger" title={query.error.kind === "unauthorized" ? "Not authorized" : query.error.kind === "network" ? "Backend unreachable" : "Backend error"}>
            {query.error.message}
          </Notice>
        </div>
      )}

      {query.data && !items.length && !query.error && (
        <div className="p-6 text-center">
          <div className="font-semibold">{filtered ? "No matching records" : `No ${cfg.noun} collected yet`}</div>
          <p className="mt-1 text-sm text-muted-foreground">
            {filtered ? "Adjust your search or filters." : "The backend returned an empty list. Run collectors or add evidence."}
          </p>
          {!filtered && <button type="button" className="sw-btn mt-3" onClick={onCollectors}>Open collectors</button>}
        </div>
      )}

      {items.length > 0 && (
        <div className={`sw-scroll ${stale ? "opacity-60" : ""}`} tabIndex={0} aria-label={`${cfg.title} table`}>
          <table className="sw-table">
            <thead>
              <tr>{headers(tab, view.sort).map((h) => <th key={h} scope="col">{h}</th>)}</tr>
            </thead>
            <tbody>
              {items.map((item, i) => (
                <tr
                  key={String(item["id"] ?? item["canonical_id"] ?? i)}
                  data-record-id={String(item["id"] ?? item["canonical_id"] ?? i)}
                  className="sw-row"
                  tabIndex={0}
                  aria-label={`Open details: ${text(item["title"] || item["name"] || item["asset_name"] || item["canonical_id"] || item["id"], "record")}`}
                  onClick={(e) => {
                    e.currentTarget.focus();
                    onOpen(item, tab);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onOpen(item, tab);
                    }
                  }}
                >
                  {cells(tab, item, view.sort).map((c, j) => (
                    <td key={j} className={j > 1 ? "whitespace-nowrap text-xs text-muted-foreground" : ""}>{c}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {total > PAGE && items.length > 0 && (
        <nav aria-label="Pagination" className="flex flex-wrap items-center justify-end gap-2 p-3 text-xs text-muted-foreground">
          <span>{num(view.offset + 1)}–{num(Math.min(view.offset + items.length, total))} of {num(total)}</span>
          <button type="button" className="sw-btn" disabled={view.offset === 0} onClick={() => onChange({ offset: Math.max(0, view.offset - PAGE) })}>Previous</button>
          <button type="button" className="sw-btn" disabled={view.offset + PAGE >= total} onClick={() => onChange({ offset: view.offset + PAGE })}>Next</button>
        </nav>
      )}
    </section>
  );
}
