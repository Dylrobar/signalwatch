import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, List, Map, RefreshCw, Search, Upload, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { num, type R } from "@/lib/format";
import {
  RADIO_LABELS,
  WIRELESS_ROLES,
  wirelessTime,
  wirelessTimeLabel,
  validBounds,
  type WirelessDataset,
  type WirelessDevice,
  type WirelessStats,
} from "@/lib/wireless";
import { Badge, Notice } from "./bits";
import { Modal } from "./Modal";
import { WirelessDetail } from "./WirelessDetail";
import { WirelessMap } from "./WirelessMap";
import { WirelessCompanyPicker } from "./WirelessCompanyPicker";

export function WirelessView({ gen, onCompany }: { gen: number; onCompany: (id: string) => void }) {
  const qc = useQueryClient();
  const [dataset, setDataset] = useState("");
  const [type, setType] = useState("");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [company, setCompany] = useState("");
  const [mode, setMode] = useState<"map" | "list">("map");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState("");
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [uploadResult, setUploadResult] = useState("");
  const [enriching, setEnriching] = useState(false);
  const [enrichmentError, setEnrichmentError] = useState("");
  const file = useRef<HTMLInputElement>(null);
  const upload = useRef<AbortController | null>(null);
  const enrichmentController = useRef<AbortController | null>(null);
  const priorEnrichment = useRef("");
  useEffect(() => () => upload.current?.abort(), []);
  useEffect(() => () => enrichmentController.current?.abort(), []);
  useEffect(() => {
    const timer = setTimeout(() => {
      setQ(search.trim());
      setOffset(0);
    }, 250);
    return () => clearTimeout(timer);
  }, [search]);
  const filters = {
    ...(dataset ? { dataset_id: dataset } : {}),
    ...(type ? { type } : {}),
    ...(q ? { q } : {}),
    ...(company ? { company_id: company } : {}),
  };
  const datasets = useQuery<{ items: WirelessDataset[]; total: number }, ApiError>({
    queryKey: ["wireless-datasets", gen],
    queryFn: ({ signal }) => api("/api/wireless/datasets", { signal }),
    retry: false,
    refetchInterval: (query) =>
      query.state.data?.items.some((item) =>
        ["queued", "importing", "processing"].includes(item.status),
      )
        ? 2500
        : false,
  });
  const stats = useQuery<WirelessStats, ApiError>({
    queryKey: ["wireless-stats", gen, dataset],
    queryFn: ({ signal }) =>
      api("/api/wireless/stats", { params: dataset ? { dataset_id: dataset } : {}, signal }),
    retry: false,
  });
  const enrichment = useQuery<R, ApiError>({
    queryKey: ["wireless-enrichment", gen],
    queryFn: ({ signal }) => api("/api/wireless/enrichment", { signal }),
    retry: false,
    refetchInterval: (query) =>
      enriching || query.state.data?.["status"] === "running" ? 2000 : false,
  });
  const enrichmentStatus = String(enrichment.data?.["status"] || "");
  useEffect(() => {
    if (
      ["complete", "partial", "failed"].includes(enrichmentStatus) &&
      enriching &&
      JSON.stringify(enrichment.data) !== priorEnrichment.current
    ) {
      setEnriching(false);
      for (const key of [
        "wireless-stats",
        "wireless-devices",
        "wireless-company",
        "wireless-companies",
      ])
        qc.invalidateQueries({ queryKey: [key, gen] });
    }
  }, [enrichment.data, enrichmentStatus, enriching, gen, qc]);

  async function enrichCompanies(facilities = false) {
    enrichmentController.current?.abort();
    const c = new AbortController();
    enrichmentController.current = c;
    priorEnrichment.current = JSON.stringify(enrichment.data);
    setEnriching(true);
    setEnrichmentError("");
    try {
      await api("/api/wireless/enrichment", {
        method: "POST",
        body: {
          manufacturers: !facilities,
          facilities: true,
          lookup_businesses: facilities,
          ...(facilities && validBounds(chosen?.bounds) ? { bbox: chosen.bounds } : {}),
        },
        signal: c.signal,
      });
      if (!c.signal.aborted) await enrichment.refetch();
    } catch (e) {
      if (!c.signal.aborted && (e as ApiError).kind !== "aborted") {
        setEnrichmentError((e as Error).message);
        setEnriching(false);
      }
    }
  }
  const devices = useQuery<{ items: WirelessDevice[]; total: number }, ApiError>({
    queryKey: ["wireless-devices", gen, filters, offset],
    queryFn: ({ signal }) =>
      api("/api/wireless/devices", {
        params: { ...filters, limit: "50", offset: String(offset) },
        signal,
      }),
    retry: false,
    placeholderData: keepPreviousData,
    enabled: mode === "list",
  });
  const chosen =
    datasets.data?.items.find((item) => item.id === dataset) ??
    (!dataset && datasets.data?.items.length === 1 ? datasets.data.items[0] : undefined);
  const total = devices.data?.total ?? 0;
  const deviceItems = devices.data?.items.map((device) => ({
    ...device,
    company_links: device.company_links?.filter(
      (link) => link.status !== "rejected" && !link.rejected_by_user,
    ),
  }));
  const busyDatasets =
    datasets.data?.items.filter((item) =>
      ["queued", "importing", "processing"].includes(item.status),
    ) ?? [];
  const completedSignature =
    datasets.data?.items.map((item) => `${item.id}:${item.status}`).join(",") ?? "";
  useEffect(() => {
    if (completedSignature) {
      qc.invalidateQueries({ queryKey: ["wireless-stats", gen] });
      qc.invalidateQueries({ queryKey: ["wireless-devices", gen] });
    }
  }, [completedSignature, gen, qc]);

  async function importFile(blob: File) {
    setUploadError("");
    setUploadResult("");
    if (blob.size > 32 * 1024 * 1024) {
      setUploadError(
        "The upload exceeds the default 32 MiB limit. Upload a gzip export or use the server import CLI for larger datasets.",
      );
      return;
    }
    upload.current?.abort();
    const c = new AbortController();
    upload.current = c;
    setUploading(true);
    try {
      const result = await api<{ dataset_id: string; status: string }>("/api/import/wigle", {
        method: "POST",
        rawBody: blob,
        contentType: /\.gz$/i.test(blob.name) ? "application/gzip" : "text/csv",
        filename: blob.name,
        signal: c.signal,
      });
      if (c.signal.aborted) return;
      setDataset(result.dataset_id);
      setOffset(0);
      setUploadResult("Export received. Import progress appears below.");
      await qc.invalidateQueries({ queryKey: ["wireless-datasets", gen] });
    } catch (e) {
      if (!c.signal.aborted && (e as ApiError).kind !== "aborted")
        setUploadError((e as Error).message);
    } finally {
      if (!c.signal.aborted) setUploading(false);
      if (file.current) file.current.value = "";
    }
  }

  return (
    <section className="sw-panel overflow-hidden" aria-labelledby="wireless-title">
      <div className="border-b border-border p-3 sm:p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="wireless-title" className="text-base font-semibold">
              Wireless observations
            </h2>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              WiGLE exports, scan locations and evidence for company relationships. GPS points
              describe where a signal was observed; relationship roles preserve how each company was
              linked.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="sw-btn"
              disabled={enriching || enrichmentStatus === "running" || !datasets.data?.items.length}
              onClick={() => enrichCompanies()}
            >
              <Building2 className="h-3.5 w-3.5" aria-hidden />
              {enriching || enrichmentStatus === "running"
                ? "Enriching companies…"
                : "Enrich companies"}
            </button>
            <button
              type="button"
              className="sw-btn"
              disabled={enriching || enrichmentStatus === "running" || !datasets.data?.items.length}
              onClick={() => enrichCompanies(true)}
            >
              Find nearby businesses with OpenStreetMap
            </button>
            <button
              type="button"
              className="sw-btn"
              disabled={uploading}
              onClick={() => file.current?.click()}
            >
              <Upload className="h-3.5 w-3.5" aria-hidden />
              {uploading ? "Uploading…" : "Import WiGLE"}
            </button>
            <input
              ref={file}
              type="file"
              accept=".csv,.gz,text/csv,application/gzip"
              className="sr-only"
              tabIndex={-1}
              aria-label="WiGLE CSV or gzip export"
              onChange={(event) => {
                const blob = event.target.files?.[0];
                if (blob) void importFile(blob);
              }}
            />
            <button
              type="button"
              className="sw-btn"
              aria-label="Refresh wireless data"
              onClick={() => {
                datasets.refetch();
                stats.refetch();
                devices.refetch();
              }}
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          Enrich companies refreshes manufacturer and recorded facility evidence. Nearby business
          lookup sends dataset location bounds to OpenStreetMap/Overpass when selected.
        </p>
        <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-3 md:grid-cols-4">
          {(
            [
              ["Datasets", stats.data?.datasets],
              ["Distinct radios", stats.data?.devices],
              ["Observations", stats.data?.observations],
              ["Company relationships", stats.data?.company_links],
            ] as const
          ).map(([label, value]) => (
            <div key={label}>
              <dt className="text-xs text-muted-foreground">{label}</dt>
              <dd className="mt-0.5 font-mono text-xl">{value == null ? "—" : num(value)}</dd>
            </div>
          ))}
        </dl>
        <div className="mt-4 grid min-w-0 gap-2 md:grid-cols-2">
          <div className="relative min-w-0">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <input
              type="search"
              className="sw-input pl-8"
              aria-label="Search wireless signals"
              placeholder="Search SSID or radio identifier…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <div className="flex min-w-0 flex-wrap gap-2">
            <select
              className="sw-input min-w-0 flex-[1_1_12rem]"
              aria-label="Wireless dataset"
              value={dataset}
              onChange={(event) => {
                setDataset(event.target.value);
                setOffset(0);
              }}
            >
              <option value="">All datasets</option>
              {datasets.data?.items.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} · {item.status}
                </option>
              ))}
            </select>
            <select
              className="sw-input min-w-0 flex-[1_1_8rem]"
              aria-label="Radio type"
              value={type}
              onChange={(event) => {
                setType(event.target.value);
                setOffset(0);
              }}
            >
              <option value="">All radio types</option>
              {Object.entries(RADIO_LABELS).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                  {stats.data?.signal_types?.[key] != null
                    ? ` (${num(stats.data.signal_types[key])})`
                    : ""}
                </option>
              ))}
            </select>
          </div>
          <WirelessCompanyPicker
            value={company}
            onChange={(value) => {
              setCompany(value);
              setOffset(0);
            }}
            gen={gen}
          />
          <div className="flex items-center justify-end gap-1" aria-label="Wireless display">
            <button
              type="button"
              className={mode === "map" ? "sw-btn-primary" : "sw-btn"}
              aria-pressed={mode === "map"}
              onClick={() => setMode("map")}
            >
              <Map className="h-3.5 w-3.5" aria-hidden />
              Map
            </button>
            <button
              type="button"
              className={mode === "list" ? "sw-btn-primary" : "sw-btn"}
              aria-pressed={mode === "list"}
              onClick={() => setMode("list")}
            >
              <List className="h-3.5 w-3.5" aria-hidden />
              Devices
            </button>
          </div>
        </div>
        {uploadError && (
          <p role="alert" className="mt-3 text-sm text-destructive">
            {uploadError}
          </p>
        )}
        {uploadResult && (
          <p role="status" className="mt-3 text-sm text-primary">
            {uploadResult}
          </p>
        )}
        {busyDatasets.map((item) => (
          <p key={item.id} role="status" className="mt-3 text-xs text-warn">
            {item.name}: {item.status}
            {typeof item.observations === "number"
              ? ` · ${num(item.observations)} observations imported`
              : ""}
          </p>
        ))}
        {chosen?.status === "failed" && (
          <p role="alert" className="mt-3 text-sm text-destructive">
            Import failed: {chosen.error || "See server import logs."}
          </p>
        )}
      </div>
      {datasets.error || stats.error ? (
        <div className="p-4">
          <Notice tone="danger" title="Wireless data unavailable">
            {datasets.error?.message || stats.error?.message}
          </Notice>
        </div>
      ) : datasets.isPending ? (
        <p role="status" className="p-4 text-sm text-muted-foreground">
          Loading wireless datasets…
        </p>
      ) : !datasets.data?.items.length ? (
        <div className="p-4">
          <Notice title="No wireless datasets imported">
            Import a WiGLE CSV or gzip export to map its observations and review supported company
            relationships.
          </Notice>
        </div>
      ) : mode === "map" ? (
        <WirelessMap
          key={`${gen}:${completedSignature}`}
          filters={filters}
          bounds={chosen?.bounds}
          onDevice={setSelected}
        />
      ) : (
        <>
          {devices.error && (
            <p role="alert" className="p-4 text-sm text-destructive">
              {devices.error.message}
            </p>
          )}
          <div className="overflow-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-background/30 text-xs text-muted-foreground">
                <tr>
                  {[
                    "Radio / identifier",
                    "Type",
                    "Observations",
                    "Company evidence",
                    wirelessTimeLabel(chosen?.timestamp_timezone),
                  ].map((heading) => (
                    <th key={heading} className="whitespace-nowrap px-3 py-3 font-medium">
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className={devices.isPlaceholderData ? "opacity-50" : ""}>
                {deviceItems?.map((device) => (
                  <tr key={device.id} className="border-t border-border hover:bg-panel-2/40">
                    <td className="max-w-sm px-3 py-3">
                      <button
                        type="button"
                        className="text-left font-medium text-primary hover:underline"
                        onClick={() => setSelected(device.id)}
                      >
                        {device.name || "Unnamed signal"}
                      </button>
                      <div className="mt-1 font-mono text-xs text-muted-foreground">
                        {device.identifier}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3">
                      <Badge>{RADIO_LABELS[device.type] ?? device.type}</Badge>
                    </td>
                    <td className="px-3 py-3 font-mono">{num(device.observations)}</td>
                    <td className="min-w-48 px-3 py-3">
                      <div className="space-y-1 text-xs">
                        {device.company_links?.length ? (
                          device.company_links.slice(0, 3).map((link, index) => (
                            <div key={index}>
                              <button
                                type="button"
                                className="text-primary hover:underline"
                                onClick={() => onCompany(link.company_id)}
                              >
                                {link.company_name || link.company_id}
                              </button>
                              <div className="text-muted-foreground">
                                {WIRELESS_ROLES[link.role] ?? link.role.replaceAll("_", " ")}
                              </div>
                            </div>
                          ))
                        ) : (
                          <span className="text-muted-foreground">No supported company link</span>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-xs text-muted-foreground">
                      {wirelessTime(device.first_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {devices.isPending ? (
            <p role="status" className="p-4 text-sm text-muted-foreground">
              Loading radios…
            </p>
          ) : !devices.data?.items.length && !devices.error ? (
            <p role="status" className="p-4 text-sm text-muted-foreground">
              No radios match these filters.
            </p>
          ) : null}
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-3 text-xs text-muted-foreground">
            <span>
              {total
                ? `${num(offset + 1)}–${num(Math.min(offset + 50, total))} of ${num(total)} radios`
                : "0 radios"}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                className="sw-btn text-xs"
                disabled={offset === 0 || devices.isFetching}
                onClick={() => setOffset(Math.max(0, offset - 50))}
              >
                Previous
              </button>
              <button
                type="button"
                className="sw-btn text-xs"
                disabled={offset + 50 >= total || devices.isFetching}
                onClick={() => setOffset(offset + 50)}
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
      {(enrichmentError || enrichment.error) && (
        <p role="alert" className="mt-3 text-sm text-destructive">
          {enrichmentError || enrichment.error?.message}
        </p>
      )}
      {enrichmentStatus === "failed" && (
        <p role="alert" className="mt-3 text-sm text-destructive">
          Company enrichment failed:{" "}
          {String(enrichment.data?.["error"] || "See source health for details.")}
        </p>
      )}
      {enrichmentStatus === "partial" && (
        <p role="status" className="mt-3 text-xs text-warn">
          Company enrichment completed with source errors. Available matches remain inspectable.
        </p>
      )}
      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected("")}
        label="Wireless signal evidence"
        variant="drawer"
      >
        <div className="flex items-center justify-between border-b border-border p-4">
          <h2 className="font-semibold">Signal evidence</h2>
          <button
            type="button"
            className="sw-btn"
            aria-label="Close wireless signal"
            onClick={() => setSelected("")}
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>
        <div className="min-w-0 overflow-y-auto p-4">
          {selected && (
            <WirelessDetail
              key={selected}
              id={selected}
              gen={gen}
              onCompany={(id) => {
                setSelected("");
                onCompany(id);
              }}
            />
          )}
        </div>
      </Modal>
    </section>
  );
}
