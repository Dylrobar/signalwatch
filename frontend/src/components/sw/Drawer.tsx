import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, X } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, ApiError } from "@/lib/api";
import { confidence, describe, fmtDate, host, humanize, num, percent, present, safeHref, text, toArray, yesNo, type R } from "@/lib/format";
import { EVENT_KINDS, type DataTab } from "@/lib/views";
import { Badge, EventBadge, ExtLink, Severity, Signals } from "./bits";
import { Modal } from "./Modal";
import { CompanyIdentityForm, CompanyProfile } from "./CompanyProfile";
import type { CompanyProfile as Profile } from "@/lib/companies";
import type { CompanyWirelessSummary } from "@/lib/wireless";

type Kind = "intelligence" | "news" | "infrastructure" | "warnings" | "changes" | "unavailable";
type Frame = { kind: Kind; row: R; detail?: R; loading: boolean; error?: string; id?: string; originalUrl?: string; request?: { path: string; id: string } };

const ARRAY_KEYS = ["relationships", "observations", "advisories", "alerts", "related_articles", "articles"];

function detailKind(d: R, fallback: Kind): Kind {
  if (d["advisory"] || d["kind"] === "vulnerability") return "intelligence";
  if (d["article"]) return "news";
  if (d["kind"]) return "infrastructure";
  return fallback;
}

function rootOf(d: R | undefined) {
  if (!d) return {};
  const out: R = {};
  for (const [k, v] of Object.entries(d)) if (!ARRAY_KEYS.includes(k) && k !== "advisory" && k !== "article") out[k] = v;
  return out;
}

function merged(f: Frame): R {
  const d = f.detail;
  if (f.kind === "intelligence") return { ...f.row, ...rootOf(d), ...(d?.["advisory"] ?? {}), aliases: d?.["aliases"] ?? d?.["advisory"]?.aliases ?? f.row["aliases"] };
  if (f.kind === "news") return { ...f.row, ...rootOf(d), ...(d?.["article"] ?? {}) };
  return { ...f.row, ...rootOf(d) };
}

export function Drawer({ initial, onClose }: { initial: { row: R; tab: DataTab } | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [stack, setStack] = useState<Frame[]>([]);
  const ctrl = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const backRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  function load(frame: Frame, path: string, id: string, replaceTop: boolean) {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    const next = { ...frame, id, loading: true, request: { path, id } };
    delete next.error;
    setStack((s) => (replaceTop ? [...s.slice(0, -1), next] : [...s, next]));
    api<R>(path, { params: { id }, signal: c.signal })
      .then((detail: R) => {
        if (c.signal.aborted) return;
        const kind = frame.kind === "changes" ? "changes" : detailKind(detail, frame.kind);
        const row = frame.kind === "unavailable" ? {} : frame.row;
        setStack((s) => [...s.slice(0, -1), { ...next, row, kind, detail, loading: false }]);
      })
      .catch((e: ApiError) => {
        if (c.signal.aborted) return;
        if (e["status"] === 404) {
          setStack((s) => [...s.slice(0, -1), { ...next, kind: "unavailable", loading: false }]);
        } else {
          setStack((s) => [...s.slice(0, -1), { ...next, loading: false, error: e["message"] }]);
        }
      });
  }

  useEffect(() => {
    if (!initial) {
      ctrl.current?.abort();
      setStack([]);
      return;
    }
    ctrl.current?.abort();
    const { row, tab } = initial;
    setStack([]);
    const originalUrl = safeHref(row["url"]) ?? safeHref(row["source_url"]);
    const frame = { kind: tab, row, loading: true, ...(originalUrl ? { originalUrl } : {}) };
    if (tab === "warnings") setStack([{ kind: "warnings", row, loading: false }]);
    else if (tab === "changes" && present(row["id"])) load({ ...frame, kind: "changes" }, "/api/event", String(row["id"]), true);
    else if (present(row["id"])) load(frame, "/api/entity", String(row["id"]), true);
    else setStack([{ kind: tab, row, loading: false }]);
    return () => ctrl.current?.abort();
  }, [initial]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0 });
  }, [stack.length]);

  const go = (id: unknown, originalUrl?: unknown) => {
    if (!present(id)) return;
    load({ kind: "infrastructure", row: { id: String(id) }, id: String(id), ...(typeof originalUrl === "string" ? { originalUrl } : {}), loading: true }, "/api/entity", String(id), false);
    requestAnimationFrame(() => backRef.current?.focus());
  };
  const openWarning = (alert: R) => {
    ctrl.current?.abort();
    setStack((s) => [...s, { kind: "warnings", row: alert, loading: false }]);
    requestAnimationFrame(() => backRef.current?.focus());
  };
  const back = () => {
    const previous = stack[stack.length - 2];
    ctrl.current?.abort();
    setStack((s) => s.slice(0, -1));
    if (previous?.loading && previous.request) load(previous, previous.request.path, previous.request.id, true);
    requestAnimationFrame(() => (stack.length > 2 ? backRef.current : closeRef.current)?.focus());
  };

  const top = stack[stack.length - 1];
  const label = top?.row["new_company"]
    ? "Add company"
    : top?.detail?.["company_profile"]
      ? "Company profile"
      : top
        ? KIND_LABEL[top.kind]
        : "Details";
  const saved = (detail: R) => {
    setStack((s) =>
      s[s.length - 1] === top
        ? [
            ...s.slice(0, -1),
            {
              kind: "infrastructure",
              row: { id: detail["id"], kind: "company" },
              id: String(detail["id"]),
              detail,
              loading: false,
            },
          ]
        : s,
    );
    qc.invalidateQueries({ queryKey: ["list"] });
    qc.invalidateQueries({ queryKey: ["status"] });
  };

  return (
    <Modal open={Boolean(initial)} onClose={onClose} label={`${label} details`} variant="drawer">
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        {stack.length > 1 && (
          <button ref={backRef} type="button" className="sw-btn px-2" onClick={back} aria-label="Back to previous record">
            <ArrowLeft className="h-4 w-4" aria-hidden /> Back
          </button>
        )}
        <span className="sw-eyebrow truncate">{label}</span>
        <button ref={closeRef} type="button" className="sw-btn ml-auto px-2" onClick={onClose} aria-label="Close details" data-autofocus>
          <X className="h-4 w-4" aria-hidden />
        </button>
      </div>
      <div ref={scrollRef} className="sw-section min-w-0 flex-1 overflow-y-auto px-4 pb-8 pt-3 text-sm [overflow-wrap:anywhere]">
        {top && (
          <FrameBody
            key={top.id ?? "new-company"}
            frame={top}
            go={go}
            openWarning={openWarning}
            onSaved={saved}
          />
        )}
      </div>
    </Modal>
  );
}

const KIND_LABEL: Record<Kind, string> = {
  intelligence: "Vulnerability intelligence",
  news: "News & research",
  infrastructure: "Public evidence",
  warnings: "Potential exposure match",
  changes: "Local change",
  unavailable: "Original source",
};

type Nav = { go: (id: unknown, url?: unknown) => void; openWarning: (a: R) => void };

function FrameBody({
  frame,
  go,
  openWarning,
  onSaved,
}: { frame: Frame; onSaved: (detail: R) => void } & Nav) {
  if (frame.row["new_company"]) return <CompanyIdentityForm onSaved={onSaved} />;
  if (frame.kind === "unavailable")
    return (
      <div>
        <h2 className="text-lg font-semibold break-words">{frame.id}</h2>
        <p className="mt-2 text-muted-foreground">This record is not available in the local graph (HTTP 404).</p>
        {safeHref(frame.originalUrl) && <p className="mt-2"><ExtLink href={frame.originalUrl}>Open original source ↗</ExtLink></p>}
      </div>
    );
  const e = merged(frame);
  return (
    <div>
      {frame.loading && <p role="status" className="mb-2 text-xs text-muted-foreground">Loading connected evidence…</p>}
      {frame.error && <p role="alert" className="mb-2 text-xs text-destructive">Connected evidence unavailable: {frame.error}</p>}
      {frame.kind === "changes" ? (
        <EventBody e={e} go={go} />
      ) : frame.kind === "warnings" ? (
        <WarningBody e={e} go={go} />
      ) : frame.kind === "infrastructure" ? (
        <EntityBody e={e} d={frame.detail} go={go} openWarning={openWarning} onSaved={onSaved} />
      ) : (
        <RecordBody e={e} d={frame.detail} kind={frame.kind} go={go} openWarning={openWarning} />
      )}
      <References e={e} />
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function Fields({ title, rows }: { title: string; rows: [string, ReactNode][] }) {
  return (
    <Section title={title}>
      <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted-foreground">{k}</dt>
            <dd className="min-w-0 break-words">{v}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function List({ title, items, render }: { title: string; items: any[]; render: (x: any, i: number) => ReactNode }) {
  if (!items.length) return null;
  return (
    <Section title={`${title} (${num(items.length)})`}>
      <ul className="space-y-2">
        {items.map((x, i) => (
          <li key={i} className="rounded border border-border p-2">{render(x, i)}</li>
        ))}
      </ul>
    </Section>
  );
}

function Go({ id, url, go, children }: { id: unknown; url?: unknown; go: Nav["go"]; children?: ReactNode }) {
  if (!present(id)) return url ? <ExtLink href={url}>{children}</ExtLink> : <span>{children}</span>;
  return (
    <button type="button" className="sw-link break-all" onClick={() => go(id, url)}>
      {children ?? String(id)}
    </button>
  );
}

const Json = ({ v }: { v: unknown }) => <pre>{JSON.stringify(v, null, 2)}</pre>;

function Header({ id, title, tags }: { id?: unknown; title: unknown; tags?: ReactNode }) {
  return (
    <div>
      {present(id) && <div className="sw-mono break-all">{String(id)}</div>}
      <h2 className="mt-0.5 text-lg font-semibold leading-snug break-words">{text(title, "Record details")}</h2>
      {tags && <div className="mt-2 flex flex-wrap gap-1">{tags}</div>}
    </div>
  );
}

function WarningBody({ e, go }: { e: R; go: Nav["go"] }) {
  return (
    <>
      <Header id={e["advisory_id"]} title={e["asset_name"] || e["asset_id"]} tags={<><Severity value={e["severity"]} /><Signals item={e} /><Badge tone="warn">POTENTIAL MATCH</Badge></>} />
      <p className="mt-3 rounded border border-warn/40 p-2 text-xs text-warn">
        Potential correlation only. Confidence describes supporting-evidence strength, not exploitation probability. Verify the version
        evidence below before treating this asset as affected.
      </p>
      {present(e["title"]) && <p className="mt-3 font-medium">{e["title"]}</p>}
      {present(e["summary"]) && <p className="mt-1 whitespace-pre-wrap text-muted-foreground">{e["summary"]}</p>}
      <Fields
        title="Match details"
        rows={[
          ["Asset", <Go id={e["asset_id"]} url={e["source_url"]} go={go}>{text(e["asset_name"] || e["asset_id"])}</Go>],
          ["Advisory", <Go id={e["advisory_id"]} url={e["url"]} go={go} />],
          ["Product", [e["vendor"], e["product"], e["version"]].filter(present).join(" ") || "unknown"],
          ["Evidence confidence", confidence(e["confidence"])],
          ["Version state", humanize(e["version_state"])],
          ["Status", text(e["status"])],
          ["Priority rank", num(e["rank"])],
          ["EPSS", `${percent(e["epss"])} (percentile ${percent(e["percentile"])}, ${fmtDate(e["epss_date"])})`],
          ["KEV added", fmtDate(e["kev_date"])],
          ["Observed", fmtDate(e["observed_at"], true)],
          ["First matched", fmtDate(e["first_seen"], true)],
          ["Last seen", fmtDate(e["last_seen"], true)],
        ]}
      />
      <List title="Why this matched" items={toArray(e["reasons"])} render={(r) => describe(r)} />
      <List
        title="Observation evidence"
        items={toArray(e["evidence"])}
        render={(ev) => (typeof ev === "object" && ev ? <div>{describe(ev)} {safeHref(ev.url || ev.source_url) && <ExtLink href={ev.url || ev.source_url}>{host(ev.url || ev.source_url)}</ExtLink>}</div> : <span className="whitespace-pre-wrap break-words">{String(ev)}</span>)}
      />
    </>
  );
}

function EventBody({ e, go }: { e: R; go: Nav["go"] }) {
  const b = e["before"];
  const a = e["after"];
  const obj = (v: unknown): R | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as R) : null);
  const bo = obj(b);
  const ao = obj(a);
  const keys = bo || ao ? [...new Set([...Object.keys(bo ?? {}), ...Object.keys(ao ?? {})])].filter((k) => k !== "changed_fields" && JSON.stringify(bo?.[k]) !== JSON.stringify(ao?.[k])) : [];
  const show = (o: R | null, raw: unknown, k: string) => (o ? (k in o ? JSON.stringify(o[k], null, 2) : "not present") : raw === null || raw === undefined ? "null (no snapshot)" : JSON.stringify(raw, null, 2));
  return (
    <>
      <Header id={e["id"]} title={e["title"] || EVENT_KINDS[e["kind"]] || "Local change"} tags={<EventBadge kind={e["kind"]} />} />
      <p className="mt-3 text-xs text-muted-foreground">Observed locally is when this database recorded the change. It is not the original disclosure date.</p>
      <Fields
        title="Local observation"
        rows={[
          ["Observed locally", fmtDate(e["observed_at"], true)],
          ["Subject", <Go id={e["subject_id"]} url={e["url"]} go={go} />],
          ["Canonical advisory", <Go id={e["canonical_id"]} url={e["url"]} go={go} />],
          ["Source", text(e["source"])],
        ]}
      />
      <Section title="Before / after">
        {!bo && !ao ? (
          <dl className="grid grid-cols-[6rem_1fr] gap-1">
            <dt className="text-muted-foreground">Before</dt><dd><pre>{show(null, b, "")}</pre></dd>
            <dt className="text-muted-foreground">After</dt><dd><pre>{show(null, a, "")}</pre></dd>
          </dl>
        ) : keys.length ? (
          <div className="sw-scroll" tabIndex={0} aria-label="Changed fields">
            <table className="sw-table">
              <thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k}><td className="font-mono text-xs">{k}</td><td><pre>{show(bo, b, k)}</pre></td><td><pre>{show(ao, a, k)}</pre></td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-muted-foreground">No differing fields were recorded in the snapshots.</p>
        )}
        {toArray(ao?.["changed_fields"] ?? bo?.["changed_fields"]).length > 0 && (
          <p className="mt-2 text-xs text-muted-foreground">Changed fields: {toArray(ao?.["changed_fields"] ?? bo?.["changed_fields"]).join(", ")}</p>
        )}
      </Section>
    </>
  );
}

function Related({ d, go, openWarning }: { d?: R | undefined } & Nav) {
  if (!d) return null;
  return (
    <>
      <List
        title="Relationships"
        items={toArray(d["relationships"])}
        render={(r) => (
          <div className="flex flex-wrap items-center gap-1">
            <Go id={r.from_id} go={go}>{text(r.from_name || r.from_id)}</Go>
            <span className="text-xs text-muted-foreground">→ {humanize(r.relation)} →</span>
            <Go id={r.to_id} go={go}>{text(r.to_name || r.to_id)}</Go>
            {safeHref(r.source_url) && <span className="w-full text-xs"><ExtLink href={r.source_url}>{host(r.source_url)}</ExtLink></span>}
          </div>
        )}
      />
      <List
        title="Observations"
        items={toArray(d["observations"])}
        render={(o) => (
          <div>
            <div>{[o["vendor_name"] || o["vendor"], o["product_name"] || o["product"], o["version"]].filter(present).join(" ") || "unknown product"}</div>
            {present(o["evidence"]) && <div className="text-xs text-muted-foreground whitespace-pre-wrap">{describe(o["evidence"])}</div>}
            <div className="text-xs text-muted-foreground">{text(o["origin"])} · {fmtDate(o["observed_at"], true)} {safeHref(o["source_url"]) && <ExtLink href={o["source_url"]}>{host(o["source_url"])}</ExtLink>}</div>
          </div>
        )}
      />
      <List
        title="Potential warnings"
        items={toArray(d["alerts"])}
        render={(a) => (
          <div>
            <button type="button" className="sw-link" onClick={() => openWarning(a)}>{text(a["advisory_id"])} · {text(a["title"], "")}</button>
            <div className="text-xs text-muted-foreground">{confidence(a["confidence"])} evidence · {humanize(a["version_state"])}</div>
          </div>
        )}
      />
      <List
        title="Related advisories"
        items={toArray(d["advisories"])}
        render={(a) => (
          <div>
            <Go id={a["id"] || a["canonical_id"]} url={a["url"]} go={go}>{text(a["canonical_id"] || a["id"])} · {text(a["title"], "")}</Go>
            {safeHref(a["url"]) && <div className="text-xs"><ExtLink href={a["url"]}>Original source ↗</ExtLink></div>}
          </div>
        )}
      />
      <List
        title="Related news signals"
        items={toArray(d["related_articles"])}
        render={(entry) => {
          const a = entry.article || entry;
          return (
            <div>
              <Go id={a["id"]} url={a["url"]} go={go}>{text(a["title"] || a["url"])}</Go>
              <div className="text-xs text-muted-foreground">{text(a["source"], host(a["url"]))} · {fmtDate(a["published"])} · {humanize(entry.match_type || "product mention")}</div>
              {toArray(entry.match_phrases).length > 0 && <div className="text-xs text-muted-foreground">Matched: {toArray(entry.match_phrases).join(" · ")}</div>}
              {present(entry.reason) && <div className="text-xs text-muted-foreground">{describe(entry.reason)}</div>}
            </div>
          );
        }}
      />
      <List
        title="Related reporting"
        items={toArray(d["articles"])}
        render={(a) => (
          <div>
            <Go id={a["id"]} url={a["url"]} go={go}>{text(a["title"] || a["url"])}</Go>
            <div className="text-xs text-muted-foreground">{text(a["source"], host(a["url"]))} · {fmtDate(a["published"])}</div>
          </div>
        )}
      />
    </>
  );
}

function EntityBody({
  e,
  d,
  go,
  openWarning,
  onSaved,
}: { e: R; d?: R | undefined; onSaved: (detail: R) => void } & Nav) {
  const meta = e["metadata"] && typeof e["metadata"] === "object" ? e["metadata"] : {};
  return (
    <>
      <Header title={e["name"] || e["value"] || e["id"]} tags={<Badge tone="ok">{text(e["kind"])}</Badge>} />
      {d?.["company_profile"] && (
        <CompanyProfile
          key={String(e["id"])}
          profile={d["company_profile"] as Profile}
          onSaved={onSaved}
          go={go}
          wirelessSummary={d["wireless_summary"] as CompanyWirelessSummary | undefined}
        />
      )}
      <Fields
        title="Entity details"
        rows={[
          ["ID", <span className="font-mono text-xs break-all">{text(e["id"])}</span>],
          ["Value", text(e["value"])],
          ["Observed", fmtDate(e["observed_at"], true)],
          ["Updated", fmtDate(e["updated_at"], true)],
          ["Confidence", confidence(e["confidence"])],
          ["Evidence source", safeHref(e["source_url"]) ? <ExtLink href={e["source_url"]} /> : "unknown"],
        ]}
      />
      {Object.keys(meta).length > 0 && (
        <Fields title="Attributes" rows={Object.entries(meta).map(([k, v]) => [k, typeof v === "object" && v !== null ? <Json v={v} /> : text(v)])} />
      )}
      <Related d={d} go={go} openWarning={openWarning} />
      {d && !toArray(d["relationships"]).length && !toArray(d["observations"]).length && <p className="mt-4 text-muted-foreground">No relationships or technology observations have been collected for this entity.</p>}
    </>
  );
}

function Affected({ a }: { a: R }) {
  if (typeof a !== "object" || !a) return <span>{String(a)}</span>;
  const bounds = ([
    ["versionStartIncluding", "≥"],
    ["versionStartExcluding", ">"],
    ["versionEndIncluding", "≤"],
    ["versionEndExcluding", "<"],
  ] as const).filter(([k]) => present(a[k])).map(([k, op]) => `${op} ${a[k]}`);
  const patched = a["first_patched_version"];
  return (
    <div className="space-y-1">
      <div className="font-medium">{[a["vendor"], a["product"] || a["package"]?.name || a["package"]].filter((x) => present(x) && typeof x !== "object").join(" / ") || describe(a)}</div>
      <div className="flex flex-wrap gap-1 text-xs text-muted-foreground">
        {present(a["part"]) && <Badge>{String(a["part"])}</Badge>}
        {present(a["ecosystem"]) && <Badge>{String(a["ecosystem"])}</Badge>}
        {a["vulnerable"] === false && <Badge>environment criterion</Badge>}
        {a["version_unverified"] && <Badge tone="warn">version constraints unverified</Badge>}
      </div>
      {present(a["criteria"]) && <div className="sw-mono break-all">{a["criteria"]}</div>}
      {present(a["purl"]) && <div className="sw-mono break-all">{a["purl"]}</div>}
      {present(a["version"]) && !["*", "-"].includes(a["version"]) && <div className="text-xs">Version {a["version"]}</div>}
      {bounds.length > 0 && <div className="text-xs">CPE bounds: {bounds.join(" · ")}</div>}
      {present(a["version_range"]) && <div className="text-xs">GitHub vulnerable range: <span className="font-mono">{a["version_range"]}</span></div>}
      {present(patched) && <div className="text-xs">First patched: <span className="font-mono">{typeof patched === "object" ? describe(patched.identifier ?? patched) : String(patched)}</span></div>}
      {present(a["cve_default_status"]) && <div className="text-xs">CVE default status: {a["cve_default_status"]}</div>}
      {present(a["cve_version_status"]) && <div className="text-xs">CVE version status: {describe(a["cve_version_status"])}</div>}
      {toArray(a["cve_versions"]).length > 0 && <><div className="text-xs text-warn">CVE native version rules (unverified)</div><Json v={a["cve_versions"]} /></>}
      {toArray(a["versions"]).length > 0 && <><div className="text-xs">OSV native versions</div><Json v={a["versions"]} /></>}
      {toArray(a["ranges"]).length > 0 && <><div className="text-xs">OSV ranges</div><Json v={a["ranges"]} /></>}
    </div>
  );
}

function cpeMatches(v: unknown, out: R[] = []): R[] {
  if (Array.isArray(v)) v.forEach((x) => cpeMatches(x, out));
  else if (v && typeof v === "object") {
    const o = v as R;
    if (typeof o["criteria"] === "string") out.push(o);
    else Object.values(o).forEach((x) => cpeMatches(x, out));
  }
  return out;
}

function RecordBody({ e, d, kind, go, openWarning }: { e: R; d?: R | undefined; kind: Kind } & Nav) {
  const conf = e["configurations"];
  const csaf = conf && typeof conf === "object" && !Array.isArray(conf) && ("remediations" in conf || "unverified_products" in conf || "csaf_product_tree" in conf);
  const cpes = !csaf && conf ? cpeMatches(conf) : [];
  const isNews = kind === "news";
  return (
    <>
      <Header
        id={isNews ? undefined : e["canonical_id"] || e["id"]}
        title={e["title"] || e["canonical_id"] || e["url"]}
        tags={isNews ? undefined : <><Severity value={e["severity"]} /><Signals item={e} />{e["rejected"] ? <Badge tone="kev">REJECTED</Badge> : null}</>}
      />
      {!isNews && d && !d["advisory"] && <p className="mt-3 text-xs text-muted-foreground">The source advisory record is no longer available. Retained graph evidence is shown below.</p>}
      {present(e["summary"]) && <p className="mt-3 whitespace-pre-wrap">{e["summary"]}</p>}
      {isNews ? (
        <Fields title="Publication" rows={[["Source", toArray(e["feed_sources"]).join(", ") || text(e["source"], host(e["url"]))], ["Published", fmtDate(e["published"], true)], ["Updated", fmtDate(e["updated_at"], true)], ["Original", <ExtLink href={e["url"]} />]]} />
      ) : (
        <Fields
          title="Publication"
          rows={[
            ["Source", text(e["source"])],
            ["Source record", text(e["source_record_id"] || e["id"])],
            ["Published", fmtDate(e["published"], true)],
            ["Modified", fmtDate(e["modified"], true)],
            ["Aliases", toArray(e["aliases"]).join(", ") || "none"],
            ["Known exploited", yesNo(e["kev"])],
            ["KEV added", fmtDate(e["kev_date"])],
            ["EPSS", `${percent(e["epss"])} · percentile ${percent(e["percentile"])} · ${fmtDate(e["epss_date"])}`],
            ["Rank", num(e["rank"])],
          ]}
        />
      )}
      <List title="Affected products & versions" items={toArray(e["affected"])} render={(a) => <Affected a={a} />} />
      {cpes.length > 0 && (
        <List
          title="CPE configurations"
          items={cpes}
          render={(m) => (
            <div>
              <div className="sw-mono break-all">{m["criteria"]}</div>
              <div className="text-xs text-muted-foreground">
                {m["vulnerable"] === false ? "environment criterion · " : m["vulnerable"] === true ? "affected-product criterion · " : ""}
                {([["versionStartIncluding", "≥"], ["versionStartExcluding", ">"], ["versionEndIncluding", "≤"], ["versionEndExcluding", "<"]] as const).filter(([k]) => present(m[k])).map(([k, op]) => `${op} ${m[k]}`).join(" · ") || "no version bounds"}
              </div>
            </div>
          )}
        />
      )}
      {!csaf && conf && !cpes.length && (Array.isArray(conf) ? conf.length > 0 : Object.keys(conf).length > 0) && <Section title="Configurations"><Json v={conf} /></Section>}
      {csaf && (
        <>
          <List
            title="Affected product labels · identity unverified"
            items={toArray(conf.unverified_products).filter((p) => p && typeof p === "object")}
            render={(p) => (
              <div>
                <div>{p.name || [p.vendor, p.product].filter(present).join(" / ") || p.product_id || describe(p)}</div>
                <div className="text-xs text-muted-foreground">{[p.product_id && `Product ID: ${p.product_id}`, p.identity_status || "identity unverified"].filter(Boolean).join(" · ")}</div>
                {toArray(p.versions).length > 0 && <Json v={p.versions} />}
              </div>
            )}
          />
          <List
            title="Publisher remediations"
            items={toArray(conf.remediations).filter((r) => r && typeof r === "object")}
            render={(r) => (
              <div>
                <div className="font-medium">{r.title || humanize(r.category || "remediation")}</div>
                {present(r.details) && <div className="whitespace-pre-wrap text-xs text-muted-foreground">{String(r.details)}</div>}
                {toArray(r.product_ids).length > 0 && <div className="text-xs text-muted-foreground">Products: {toArray(r.product_ids).join(", ")}</div>}
                {safeHref(r.url) && <ExtLink href={r.url} />}
              </div>
            )}
          />
          {conf.product_status && Object.keys(conf.product_status).length > 0 && <Section title="CSAF product status"><Json v={conf.product_status} /></Section>}
        </>
      )}
      <List
        title="Referenced CVEs"
        items={toArray(e["cves"])}
        render={(c) => <Go id={describe(c)} url={`https://www.cve.org/CVERecord?id=${encodeURIComponent(describe(c))}`} go={go} />}
      />
      <Related d={d} go={go} openWarning={openWarning} />
    </>
  );
}

function References({ e }: { e: R }) {
  const seen = new Set<string>();
  const refs = [...toArray(e["references"]), ...toArray(e["url"]), ...toArray(e["source_url"]), ...toArray(e["feed_urls"]), ...toArray(e["feed_url"])]
    .map((r) => (typeof r === "object" && r ? { url: r.url || r.source_url, tags: toArray(r.tags).join(", ") || r.source } : { url: r, tags: "" }))
    .filter((r) => {
      const h = safeHref(r.url);
      if (!h || seen.has(h)) return false;
      seen.add(h);
      return true;
    });
  if (!refs.length) return null;
  return (
    <Section title={`Sources & references (${num(refs.length)})`}>
      <ul className="space-y-1">
        {refs.map((r) => (
          <li key={r.url} className="text-xs">
            <ExtLink href={r.url} />
            {r.tags && <span className="ml-1 text-muted-foreground">{String(r.tags)}</span>}
          </li>
        ))}
      </ul>
    </Section>
  );
}
