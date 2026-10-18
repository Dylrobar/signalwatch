import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import { api, ApiError } from "@/lib/api";
import { fmtDate, num, safeHref, text, type R } from "@/lib/format";
import { feedList, mergeSources, sbomLimitMiB, sourceErrors, sourceHealth, sourceRecords, type Health } from "@/lib/sources";
import { Badge, ExtLink } from "./bits";

const HEALTH: Record<Health, [string, string]> = {
  collecting: ["Collecting…", "ok"], error: ["Error", "kev"], partial: ["Partial", "warn"], interrupted: ["Interrupted", "warn"],
  disabled: ["Disabled", ""], not_collected: ["Not collected", ""], healthy: ["Healthy", "ok"], unknown: ["Unknown", ""],
};
const COUNT_KEYS = ["targets", "pages", "enriched", "routed", "feeds", "feed_pages_pending", "dns_hosts", "dns_records", "dns_failed", "dns_fallbacks"];

export async function runCollect(sources: string[] | null, refresh: () => void) {
  try {
    const r = await api<R>("/api/collect", { method: "POST", body: sources ? { sources } : {} });
    if (r["queued"]) toast.success(`Collection queued: ${(r["sources"] ?? []).join(", ") || "all"}`);
    else if (r["running"]) toast.message("A collection is already running; nothing new was queued.");
    else toast.message(JSON.stringify(r));
  } catch (e) {
    if (e instanceof ApiError && e.kind === "aborted") return;
    toast.error(`Collect failed: ${(e as Error).message}`);
  }
  refresh();
}

function Coverage({ s }: { s: R }) {
  const out: string[] = [];
  const counts = s["counts"] ?? {};
  const cov = s["coverage"] ?? counts["coverage"];
  const scopes = new Set([s["coverage_scope"], counts["coverage_scope"], typeof cov === "string" ? cov : null].filter(Boolean));
  for (const scope of scopes) out.push(String(scope).replaceAll("_", " "));
  if (cov && typeof cov === "object")
    for (const [k, v] of Object.entries(cov)) if (v !== null && typeof v !== "object" && !k.endsWith("_at")) out.push(`${k.replaceAll("_", " ")}: ${typeof v === "boolean" ? (v ? "yes" : "no") : num(v)}`);
  const pending = s["pending"] ?? counts["pending"];
  if (typeof pending === "number") out.push(`${num(pending)} pending`);
  else if (typeof pending === "boolean") out.push(pending ? "more pending" : "nothing pending");
  if (counts["more"] === true) out.push("more pages pending");
  for (const k of COUNT_KEYS) if (typeof counts[k] === "number") out.push(`${k.replaceAll("_", " ")}: ${num(counts[k])}`);
  if (s["coverage_floor"]) out.push(`since ${fmtDate(s["coverage_floor"], true)}`);
  if (s["coverage_through"]) out.push(`through ${fmtDate(s["coverage_through"], true)}`);
  if (s["gap"]) out.push(typeof s["gap"] === "string" ? `gap: ${s["gap"]}` : "collection gap flagged");
  if (s["checked_at"]) out.push(`checked ${fmtDate(s["checked_at"], true)}`);
  return <div className="max-w-sm text-xs text-muted-foreground">{out.length ? out.join(" · ") : "not reported"}</div>;
}

function Feeds({ s }: { s: R }) {
  const feeds = feedList(s["feed_health"]);
  const cov = s["coverage"] && typeof s["coverage"] === "object" ? s["coverage"] : s["counts"] ?? {};
  const metrics = ["configured", "attempted", "successful", "unchanged", "failed"].filter((k) => typeof cov[k] === "number");
  if (!feeds.length && !metrics.length) return null;
  return (
    <details className="sw-panel mt-3 p-3">
      <summary className="cursor-pointer text-sm font-semibold">News feed health {typeof cov["failed"] === "number" && cov["failed"] > 0 ? `· ${cov["failed"]} failed` : ""}</summary>
      {metrics.length > 0 && <p className="mt-2 text-xs text-muted-foreground">{metrics.map((k) => `${k}: ${num(cov[k])}`).join(" · ")} (successful includes unchanged)</p>}
      <div className="sw-scroll mt-2" tabIndex={0} aria-label="Feed health">
        <table className="sw-table">
          <thead><tr><th>Feed</th><th>Status</th><th>Last parsed entries</th><th>Last success</th><th>Last attempt / error</th></tr></thead>
          <tbody>
            {feeds.map((f) => (
              <tr key={String(f["url"])}>
                <td><ExtLink href={f["url"]}>{text(f["name"], String(f["url"]))}</ExtLink></td>
                <td><Badge tone={f["status"] === "ok" || f["status"] === "unchanged" ? "ok" : f["status"] === "error" ? "kev" : ""}>{f["status"] === "ok" ? "Updated" : f["status"] === "unchanged" ? "Unchanged" : f["status"] === "error" ? "Failed" : "Not attempted"}</Badge></td>
                <td>{f["last_success"] ? num(f["articles"]) : "unknown"}</td>
                <td className="text-xs">{fmtDate(f["last_success"], true)}</td>
                <td className="text-xs">{fmtDate(f["last_attempt"], true)}{f["error"] && <div className="text-destructive">{String(f["error"])}</div>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

function Form({ title, onSubmit, children, result }: { title: string; onSubmit: (e: FormEvent<HTMLFormElement>) => void; children: ReactNode; result: { ok: boolean; msg: string } | null }) {
  return (
    <form className="sw-panel space-y-2 p-3" onSubmit={onSubmit}>
      <h3 className="text-sm font-semibold">{title}</h3>
      {children}
      {result && <p role="status" className={`text-xs break-words ${result.ok ? "text-primary" : "text-destructive"}`}>{result.msg}</p>}
    </form>
  );
}

function useSubmit(refresh: () => void) {
  const [res, setRes] = useState<{ ok: boolean; msg: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<string>, form?: HTMLFormElement) => {
    setBusy(true); setRes(null);
    try { setRes({ ok: true, msg: await fn() }); form?.reset(); refresh(); }
    catch (e) { setRes({ ok: false, msg: (e as Error).message }); }
    finally { setBusy(false); }
  };
  return { res, busy, run };
}

const field = (f: FormData, k: string) => String(f.get(k) ?? "").trim();
const needUrl = (u: string) => {
  const href = safeHref(u);
  if (!href) throw new Error("Enter a full HTTP(S) URL.");
  const parsed = new URL(href);
  if (parsed.username || parsed.password) throw new Error("Enter a URL without embedded credentials.");
  return u;
};

export function Collectors({ status, refresh }: { status: R; refresh: () => void }) {
  const qc = useQueryClient();
  const refreshAll = () => { refresh(); qc.invalidateQueries({ queryKey: ["list"] }); };
  const { families, historical } = mergeSources(status);
  const running: string[] = (status["current_sources"] ?? []).map(String);
  const busy = Boolean(status["running"]);
  const seed = useSubmit(refreshAll), feed = useSubmit(refreshAll), obs = useSubmit(refreshAll), sbom = useSubmit(refreshAll);
  const [report, setReport] = useState<R | null>(null);
  const limit = sbomLimitMiB(status);
  const news = families.find((f) => f["name"] === "news");

  return (
    <div className="space-y-4">
      <section className="sw-panel overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <h2 className="text-base font-semibold">Sources and collection</h2>
          <span className="text-xs text-muted-foreground">{busy ? `Running: ${running.join(", ") || "collection"}` : "Idle"}{historical.length ? ` · ${historical.length} historical NVD year runs` : ""}</span>
          <button type="button" className="sw-btn-primary ml-auto" disabled={busy} onClick={() => runCollect(null, refresh)}>{busy ? "Collection running…" : "Collect all"}</button>
        </div>
        {status["error"] && <p role="alert" className="border-b border-border p-3 text-xs text-destructive">Last job error: {String(status["error"])}</p>}
        <div className="sw-scroll" tabIndex={0} aria-label="Collector health">
          <table className="sw-table">
            <thead><tr><th>Source</th><th>Health</th><th>Last success</th><th title="Most recent reported batch, not total stored records">Last batch records</th><th>Coverage</th><th /></tr></thead>
            <tbody>
              {families.map((s) => {
                const h = HEALTH[sourceHealth(s, running.includes(s["name"]))];
                const errs = sourceErrors(s);
                const rec = sourceRecords(s);
                return (
                  <tr key={s["name"]}>
                    <td className="font-mono text-xs">{s["name"]}{s["enabled"] === false && <div className="text-muted-foreground">disabled in config</div>}</td>
                    <td><Badge tone={h[1]}>{h[0]}</Badge>{errs.map((e) => <div key={e} className="mt-1 max-w-xs text-xs text-destructive">{e}</div>)}</td>
                    <td className="whitespace-nowrap text-xs">{s["persisted"] ? fmtDate(s["last_success"], true, "never") : "not collected"}</td>
                    <td className="text-xs" title={s["counts"] ? Object.entries(s["counts"]).filter(([, v]) => typeof v === "number").map(([k, v]) => `${k}: ${v}`).join(" · ") : undefined}>{rec === null ? "unknown" : num(rec)}</td>
                    <td><Coverage s={s} /></td>
                    <td><button type="button" className="sw-btn" disabled={busy || !s["configured"]} onClick={() => runCollect([s["name"]], refresh)} aria-label={`Run ${s["name"]} collector`}>Run</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
      {news && <Feeds s={news} />}

      <div className="grid gap-3 md:grid-cols-2">
        <Form title="Add URL seeds" result={seed.res} onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.currentTarget); const form = e.currentTarget;
          seed.run(async () => { const urls = [...new Set(field(f, "urls").split(/\s+/).filter(Boolean))]; if (!urls.length) throw new Error("Enter at least one URL."); urls.forEach(needUrl); const r = await api<R>("/api/seeds", { method: "POST", body: { urls } }); return `${num(r["count"])} seeds queued.`; }, form); }}>
          <textarea name="urls" rows={3} className="sw-input font-mono" aria-label="Seed URLs, one per line" placeholder="https://example.com/ (one per line)" />
          <button className="sw-btn" disabled={seed.busy}>Add seeds</button>
        </Form>
        <Form title="Add RSS / Atom feed" result={feed.res} onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.currentTarget); const form = e.currentTarget;
          feed.run(async () => { const r = await api<R>("/api/sources/feed", { method: "POST", body: { name: field(f, "name"), url: needUrl(field(f, "url")) } }); return `Feed saved (${num(r["count"])} configured).`; }, form); }}>
          <input name="name" required maxLength={200} className="sw-input" aria-label="Feed name" placeholder="Feed name" />
          <input name="url" required className="sw-input font-mono" aria-label="Feed URL" placeholder="https://…/feed.xml" />
          <button className="sw-btn" disabled={feed.busy}>Save feed</button>
        </Form>
        <Form title="Add technology observation" result={obs.res} onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.currentTarget); const form = e.currentTarget;
          obs.run(async () => { const r = await api<R>("/api/observations", { method: "POST", body: { asset_url: needUrl(field(f, "asset_url")), vendor: field(f, "vendor"), product: field(f, "product"), version: field(f, "version"), evidence: field(f, "evidence") } }); return `Observation saved for ${r["id"]}.`; }, form); }}>
          <input name="asset_url" required className="sw-input font-mono" aria-label="Asset URL" placeholder="https://asset.example.com/" />
          <div className="grid grid-cols-3 gap-2">
            <input name="vendor" required maxLength={200} className="sw-input" aria-label="Vendor" placeholder="Vendor" />
            <input name="product" required maxLength={300} className="sw-input" aria-label="Product" placeholder="Product" />
            <input name="version" maxLength={200} className="sw-input" aria-label="Version" placeholder="Version" />
          </div>
          <textarea name="evidence" required maxLength={10000} rows={2} className="sw-input" aria-label="Evidence" placeholder="Evidence (e.g. response header)" />
          <button className="sw-btn" disabled={obs.busy}>Save observation</button>
        </Form>
        <Form title="Import SBOM (CycloneDX 1.4–1.7 / SPDX 2.2–2.3 JSON)" result={sbom.res} onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.currentTarget);
          setReport(null);
          sbom.run(async () => {
            const asset_url = needUrl(field(f, "asset_url")); const source_key = field(f, "source_key") || "default"; const file = f.get("file");
            if (!(file instanceof File) || !file.size) throw new Error("Select a JSON SBOM file.");
            if (file.size > limit * 1024 * 1024) throw new Error(`File is ${num(file.size)} bytes; the backend request limit is ${num(limit)} MiB.`);
            let document: unknown; try { document = JSON.parse(await file.text()); } catch (x) { throw new Error(`Invalid JSON: ${(x as Error).message}`); }
            if (!document || typeof document !== "object" || Array.isArray(document)) throw new Error("SBOM must be a JSON object.");
            const rawBody = JSON.stringify({ asset_url, source_key, document });
            const size = new TextEncoder().encode(rawBody).byteLength;
            if (size > limit * 1024 * 1024) throw new Error(`Request is ${num(size)} bytes; the backend limit is ${num(limit)} MiB.`);
            const r = await api<R>("/api/import/sbom", { method: "POST", rawBody });
            setReport(r);
            if (r["saved"] === false) throw new Error("Backend did not save the inventory.");
            return `Inventory imported for ${r["id"]}.`;
          }); }}>
          <input name="asset_url" required className="sw-input font-mono" aria-label="Asset URL including path scope" placeholder="https://app.example.com/path" />
          <input name="source_key" maxLength={200} defaultValue="default" className="sw-input font-mono" aria-label="Source key" />
          <input name="file" type="file" accept="application/json,.json" className="text-xs" aria-label="SBOM JSON file" />
          <p className="text-[11px] text-muted-foreground">This asset URL and source key identify the inventory snapshot to replace. Request limit {num(limit)} MiB.</p>
          <button className="sw-btn" disabled={sbom.busy}>{sbom.busy ? "Importing…" : "Import SBOM"}</button>
          {report && (
            <div className="space-y-1 text-xs">
              <div>{text(report["report"]?.["format"])} {text(report["report"]?.["spec_version"], "")}</div>
              <div>{["total", "imported", "skipped", "duplicates", "observations"].map((k) => `${k}: ${num(report["report"]?.[k])}`).join(" · ")}</div>
              {report["report"]?.["skip_reasons"] && <div>Skip reasons: {Object.entries(report["report"].skip_reasons).map(([k, v]) => `${k}: ${v}`).join(" · ") || "none"}</div>}
              {(report["report"]?.["warnings"] ?? []).length > 0 && <pre className="max-h-32 overflow-auto">{JSON.stringify(report["report"].warnings, null, 2)}</pre>}
              <div className="font-semibold">Global correlation result</div>
              <pre className="max-h-32 overflow-auto">{JSON.stringify(report["matching"], null, 2)}</pre>
            </div>
          )}
        </Form>
      </div>
    </div>
  );
}
