import { useEffect, useRef, useState } from "react";
import type * as Leaflet from "leaflet";
import "leaflet/dist/leaflet.css";
import { api, ApiError } from "@/lib/api";
import { num } from "@/lib/format";
import {
  mapParams,
  RADIO_COLORS,
  RADIO_LABELS,
  validBounds,
  type WirelessBounds,
  type WirelessMapData,
} from "@/lib/wireless";

export function WirelessMap({
  filters,
  bounds,
  onDevice,
}: {
  filters: Record<string, string>;
  bounds?: WirelessBounds | null | undefined;
  onDevice: (id: string) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const map = useRef<Leaflet.Map | null>(null);
  const markers = useRef<Leaflet.LayerGroup | null>(null);
  const library = useRef<typeof Leaflet | null>(null);
  const request = useRef<AbortController | null>(null);
  const selected = useRef(onDevice);
  const fitBounds = useRef(bounds);
  selected.current = onDevice;
  fitBounds.current = bounds;
  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tileError, setTileError] = useState(false);
  const [basemapEnabled, setBasemapEnabled] = useState(false);
  const [extent, setExtent] = useState("");
  const [summary, setSummary] = useState<{
    total: number;
    features: number;
    truncated: boolean;
  } | null>(null);
  const filtersKey = JSON.stringify(filters);
  const boundsKey = bounds?.join(",");

  function fit() {
    const b = fitBounds.current;
    if (map.current && validBounds(b))
      map.current.fitBounds(
        [
          [b[1], b[0]],
          [b[3], b[2]],
        ],
        { padding: [24, 24], maxZoom: 15 },
      );
  }

  useEffect(() => {
    let cancelled = false;
    import("leaflet")
      .then((L) => {
        if (cancelled || !container.current) return;
        library.current = L;
        const m = L.map(container.current, {
          preferCanvas: true,
          minZoom: 2,
          maxZoom: 19,
          worldCopyJump: true,
        }).setView([30, 0], 2);
        map.current = m;
        markers.current = L.layerGroup().addTo(m);
        fit();
        setReady(true);
      })
      .catch((e: Error) => {
        if (!cancelled) {
          setError(e.message);
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
      request.current?.abort();
      map.current?.remove();
      map.current = null;
      markers.current = null;
    };
  }, []);

  useEffect(() => {
    const m = map.current;
    const L = library.current;
    if (!ready || !m || !L || !basemapEnabled) return;
    setTileError(false);
    const tiles = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19,
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a>',
    }).addTo(m);
    tiles.on("tileerror", () => setTileError(true));
    return () => {
      tiles.remove();
    };
  }, [ready, basemapEnabled]);

  useEffect(() => {
    if (ready) fit();
  }, [ready, boundsKey]);

  useEffect(() => {
    const m = map.current;
    const L = library.current;
    if (!ready || !m || !L) return;
    let timer: ReturnType<typeof setTimeout>;
    const update = () => {
      request.current?.abort();
      clearTimeout(timer);
      setLoading(true);
      setError("");
      timer = setTimeout(async () => {
        const c = new AbortController();
        request.current = c;
        const b = m.getBounds();
        setExtent(
          `${b.getSouth().toFixed(4)}° to ${b.getNorth().toFixed(4)}° latitude · ${b.getWest().toFixed(4)}° to ${b.getEast().toFixed(4)}° longitude`,
        );
        const west = Math.max(-180, b.getWest());
        const east = Math.min(180, b.getEast());
        try {
          const result = await api<WirelessMapData>("/api/wireless/map", {
            params: mapParams(
              [west, Math.max(-90, b.getSouth()), east, Math.min(90, b.getNorth())],
              m.getZoom(),
              JSON.parse(filtersKey) as Record<string, string>,
            ),
            signal: c.signal,
          });
          if (c.signal.aborted) return;
          markers.current?.clearLayers();
          result.features.forEach((feature) => {
            const [lon, lat] = feature.geometry.coordinates;
            const p = feature.properties;
            const cluster = !p.device_id;
            const color = RADIO_COLORS[p.type ?? ""] ?? "#6ad8c7";
            const point = L.circleMarker([lat, lon], {
              radius: cluster ? Math.min(22, 8 + Math.log10(Math.max(1, p.count)) * 4) : 6,
              color,
              weight: 1.5,
              fillColor: color,
              fillOpacity: cluster ? 0.65 : 0.85,
            });
            const label = document.createElement("span");
            label.textContent = cluster
              ? `${num(p.count)} observations · zoom to inspect`
              : `${p.name || p.device_id} · ${RADIO_LABELS[p.type ?? ""] ?? p.type ?? "Signal"}`;
            point.bindTooltip(label);
            point.on("click", () => {
              if (cluster) m.setView([lat, lon], Math.min(19, m.getZoom() + 2));
              else if (p.device_id) selected.current(p.device_id);
            });
            markers.current?.addLayer(point);
          });
          setSummary({
            total: result.total,
            features: result.features.length,
            truncated: result.truncated,
          });
        } catch (e) {
          if (!c.signal.aborted && (e as ApiError).kind !== "aborted")
            setError((e as Error).message);
        } finally {
          if (!c.signal.aborted) setLoading(false);
        }
      }, 250);
    };
    m.on("moveend", update);
    update();
    return () => {
      clearTimeout(timer);
      request.current?.abort();
      m.off("moveend", update);
    };
  }, [ready, filtersKey]);

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2 text-xs">
        <span role="status" className="text-muted-foreground">
          {loading
            ? "Loading viewport…"
            : summary
              ? `${num(summary.total)} observations in view · ${num(summary.features)} map groups${summary.truncated ? " · zoom in for more" : ""}`
              : "Map unavailable"}
        </span>
        <button
          type="button"
          className="sw-btn text-xs"
          onClick={fit}
          disabled={!validBounds(bounds) || !ready}
        >
          Fit dataset
        </button>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2 text-xs text-muted-foreground">
        <span>
          {basemapEnabled
            ? "OpenStreetMap receives the visible map area."
            : "Local coordinate canvas. Loading OpenStreetMap shares the visible map area with its tile service."}
        </span>
        <button
          type="button"
          className="sw-btn text-xs"
          aria-pressed={basemapEnabled}
          onClick={() => setBasemapEnabled((value) => !value)}
          disabled={!ready}
        >
          {basemapEnabled ? "Remove OpenStreetMap basemap" : "Load OpenStreetMap basemap"}
        </button>
      </div>
      {error && (
        <p role="alert" className="border-b border-border px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}
      {tileError && (
        <p role="status" className="border-b border-border px-3 py-2 text-xs text-warn">
          Basemap tiles are unavailable. Imported observation points remain visible.
        </p>
      )}
      <div className="relative">
        <div
          ref={container}
          aria-label="Wireless observation map"
          className="sw-wireless-map h-[390px] w-full bg-background sm:h-[530px]"
        />
        <div className="pointer-events-none absolute bottom-5 left-2 z-[400] max-w-[calc(100%_-_1rem)] rounded bg-card/90 px-2 py-1 font-mono text-[10px] text-muted-foreground">
          {extent}
        </div>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-2 border-t border-border px-3 py-2 text-xs text-muted-foreground">
        {Object.entries(RADIO_LABELS).map(([key, label]) => (
          <span key={key} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: RADIO_COLORS[key] }} />
            {label}
          </span>
        ))}
        <span>Click a group to zoom; click a signal for its evidence.</span>
      </div>
    </div>
  );
}
