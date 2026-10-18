import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Settings } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Toaster } from "sonner";
import { Notice } from "@/components/sw/bits";
import { Collectors, runCollect } from "@/components/sw/Collectors";
import { ConnectionDialog } from "@/components/sw/ConnectionDialog";
import { Drawer } from "@/components/sw/Drawer";
import { ListView } from "@/components/sw/ListView";
import { SourceIssues } from "@/components/sw/SourceIssues";
import { phaseOf, useStatus, type ConnPhase } from "@/hooks/use-signalwatch";
import { connection } from "@/lib/api";
import { describe, num, type R } from "@/lib/format";
import { compactView, parseView, TABS, type DataTab, type Tab, type View } from "@/lib/views";

export const Route = createFileRoute("/")({
  validateSearch: (s: Record<string, unknown>) => compactView(parseView(s)),
  head: () => ({
    meta: [
      { title: "SignalWatch — Infrastructure early warning" },
      { name: "description", content: "Dashboard for a SignalWatch backend: advisories, potential exposure warnings, infrastructure evidence and collectors." },
      { property: "og:title", content: "SignalWatch — Infrastructure early warning" },
      { property: "og:description", content: "Connect to your SignalWatch API to review advisories, warnings and source health." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: App,
});

const LABELS: Record<Tab, string> = { intelligence: "Intelligence", warnings: "Warnings", infrastructure: "Infrastructure", news: "News", changes: "Changes", collectors: "Collectors" };

function Pulse() {
  return (
    <svg viewBox="0 0 24 24" className="h-6 w-6 text-primary" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <path d="M2 12h4l2-6 4 12 3-9 2 3h5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function App() {
  const search = Route.useSearch();
  const view = parseView(search);
  const navigate = useNavigate({ from: "/" });
  const qc = useQueryClient();
  const status = useStatus();
  const { conn } = status;
  const phase = phaseOf(conn.baseUrl, status);
  const [settings, setSettings] = useState(false);
  const [drawer, setDrawer] = useState<{ row: R; tab: DataTab } | null>(null);
  const navRef = useRef<HTMLElement>(null);
  const memory = useRef<Partial<Record<Tab, View>>>({});
  memory.current[view.tab] = view;

  useEffect(() => connection.hydrate(), []);
  useEffect(() => {
    setDrawer(null);
    qc.cancelQueries({ predicate: (q) => q.queryKey[1] !== conn.gen });
    qc.removeQueries({ predicate: (q) => q.queryKey[1] !== conn.gen });
  }, [conn.gen, qc]);
  useEffect(() => {
    if (phase !== "connected") setDrawer(null);
  }, [phase]);
  useEffect(() => {
    const nav = navRef.current;
    const active = nav?.querySelector<HTMLElement>('[aria-current="page"]');
    if (!nav || !active) return;
    const bounds = nav.getBoundingClientRect();
    const position = active.getBoundingClientRect();
    if (position.left < bounds.left) nav.scrollLeft += position.left - bounds.left - 8;
    else if (position.right > bounds.right) nav.scrollLeft += position.right - bounds.right + 8;
  }, [view.tab]);
  useEffect(() => {
    const closeDrawer = () => setDrawer(null);
    window.addEventListener("popstate", closeDrawer);
    return () => window.removeEventListener("popstate", closeDrawer);
  }, []);

  const change = useCallback(
    (patch: Partial<View>, replace = false) => navigate({ search: compactView({ ...parseView(search), ...patch }), replace }),
    [navigate, search],
  );
  const goTab = (tab: Tab) => navigate({ search: compactView(memory.current[tab] ?? parseView({ tab })) });

  const d = phase === "connected" ? status.data : undefined;
  const stats = d?.["stats"];
  const metric = (k: string) => (stats ? num(stats[k]) : "—");
  const pill: Record<ConnPhase, [string, string]> = {
    disconnected: ["Not connected", "text-muted-foreground"], checking: ["Connecting…", "text-muted-foreground"],
    connected: [d?.["running"] ? "Collecting" : "Connected", "text-primary"], unauthorized: ["Unauthorized", "text-destructive"],
    unreachable: ["Unreachable", "text-destructive"], error: ["Backend error", "text-destructive"],
  };

  return (
    <div className="min-h-screen">
      <Toaster theme="dark" position="bottom-right" />
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-3 px-3 py-3 sm:px-6">
          <div className="flex items-center gap-2">
            <Pulse />
            <div>
              <div className="text-lg font-semibold leading-none">Signal<span className="font-normal">Watch</span></div>
              <div className="text-[10px] uppercase tracking-[0.16em] text-muted-foreground">Infrastructure early warning</div>
            </div>
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <button type="button" className="sw-btn" onClick={() => setSettings(true)} aria-label="Connection settings">
              <span className={pill[phase][1]}>●</span> {pill[phase][0]} <Settings className="h-3.5 w-3.5" aria-hidden />
            </button>
            <button type="button" className="sw-btn-primary" disabled={phase !== "connected" || Boolean(d?.["running"])} onClick={() => runCollect(null, () => status.refetch())}>
              {d?.["running"] ? "Collecting…" : "Collect now"}
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1400px] space-y-4 px-3 py-4 sm:px-6">
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-4">
          {([["Advisories", "advisories"], ["Entities", "entities"], ["Potential matches", "alerts"], ["News reports", "articles"]] as const).map(([l, k]) => (
            <div key={k} className="bg-card px-4 py-3">
              <dt className="text-xs text-muted-foreground">{l}</dt>
              <dd className="mt-1 font-mono text-2xl">{metric(k)}</dd>
            </div>
          ))}
        </dl>

        <nav ref={navRef} aria-label="Sections" className="flex gap-1 overflow-x-auto border-b border-border">
          {TABS.map((t) => (
            <button key={t} type="button" onClick={() => goTab(t)} aria-current={view.tab === t ? "page" : undefined}
              className={`whitespace-nowrap border-b-2 px-3 py-2 text-sm ${view.tab === t ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`}>
              {LABELS[t]}{t === "warnings" && stats?.["alerts"] ? <span className="ml-1 text-warn">{num(stats["alerts"])}</span> : null}
            </button>
          ))}
        </nav>

        {d?.["error"] && <Notice tone="danger" title="Collection failed"><SourceIssues errors={[describe(d["error"])]} /></Notice>}

        {phase === "disconnected" ? (
          <Notice title="No backend connected">
            This dashboard reads a separately hosted SignalWatch Python API. No data is shown until you connect one.
            <div className="mt-3"><button type="button" className="sw-btn-primary" onClick={() => setSettings(true)}>Set up connection</button></div>
          </Notice>
        ) : phase === "checking" ? (
          <Notice title="Connecting…">Requesting {conn.baseUrl}/api/status</Notice>
        ) : phase !== "connected" ? (
          <Notice tone="danger" title={phase === "unauthorized" ? "Unauthorized — check the Bearer token" : phase === "unreachable" ? "Backend unreachable (network or CORS)" : "Backend returned an error"}>
            {status.error?.message}
            <div className="mt-3 flex gap-2">
              <button type="button" className="sw-btn" onClick={() => status.refetch()}>Retry</button>
              <button type="button" className="sw-btn" onClick={() => setSettings(true)}>Connection settings</button>
            </div>
          </Notice>
        ) : view.tab === "collectors" ? (
          <Collectors key={conn.gen} status={d!} refresh={() => status.refetch()} />
        ) : (
          <ListView key={`${conn.gen}:${view.tab}`} view={view} gen={conn.gen} stats={stats} onChange={change} onOpen={(row, tab) => setDrawer({ row, tab })} onCollectors={() => goTab("collectors")} onCreateCompany={() => setDrawer({ row: { kind: "company", new_company: true }, tab: "infrastructure" })} />
        )}
      </main>
      <footer className="mx-auto flex max-w-[1400px] flex-wrap justify-between gap-2 px-3 pb-6 text-xs text-muted-foreground sm:px-6">
        <span className="min-w-0 [overflow-wrap:anywhere]">SignalWatch · {conn.baseUrl ?? "not connected"}</span>
        {stats && <span>{num(stats["observations"])} observations · {num(stats["edges"])} connections · {num(stats["events"])} events</span>}
      </footer>
      <ConnectionDialog open={settings} onClose={() => setSettings(false)} />
      <Drawer key={conn.gen} initial={phase === "connected" ? drawer : null} onClose={() => setDrawer(null)} />
    </div>
  );
}
