import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { tileLayer } from "leaflet";
import { WirelessMap } from "./WirelessMap";

const state = vi.hoisted(() => ({
  events: new Map<string, () => void>(),
  points: [] as Array<{ callback: () => void; label: HTMLElement }>,
  removed: vi.fn(),
  clear: vi.fn(),
  fit: vi.fn(),
  view: vi.fn(),
  zoom: 8,
}));
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  api: vi.fn(),
}));
vi.mock("leaflet", () => ({
  map: () => {
    const m = {
      setView: (...args: unknown[]) => {
        state.view(...args);
        return m;
      },
      fitBounds: state.fit,
      getBounds: () => ({
        getWest: () => -75,
        getSouth: () => 40,
        getEast: () => -74,
        getNorth: () => 41,
      }),
      getZoom: () => state.zoom,
      on: (name: string, fn: () => void) => state.events.set(name, fn),
      off: (name: string) => state.events.delete(name),
      remove: state.removed,
    };
    return m;
  },
  tileLayer: vi.fn(() => {
    const tiles = { addTo: () => tiles, on: vi.fn(), remove: vi.fn() };
    return tiles;
  }),
  layerGroup: () => {
    const group = { addTo: () => group, clearLayers: state.clear, addLayer: vi.fn() };
    return group;
  },
  circleMarker: () => {
    const point = { callback: () => {}, label: document.createElement("span") };
    state.points.push(point);
    return {
      bindTooltip: (label: HTMLElement) => {
        point.label = label;
      },
      on: (_event: string, callback: () => void) => {
        point.callback = callback;
      },
    };
  },
}));

const request = vi.mocked(api);
beforeEach(() => {
  vi.mocked(tileLayer).mockClear();
  request.mockReset();
  state.events.clear();
  state.points.length = 0;
  state.removed.mockClear();
  state.fit.mockClear();
  state.clear.mockClear();
  state.view.mockClear();
});
afterEach(cleanup);

describe("wireless map viewport contract", () => {
  it("keeps the coordinate canvas local until the basemap control is selected", async () => {
    request.mockResolvedValue({
      type: "FeatureCollection",
      features: [],
      total: 0,
      truncated: false,
    });
    render(<WirelessMap filters={{}} onDevice={vi.fn()} />);
    const load = screen.getByRole("button", { name: "Load OpenStreetMap basemap" });
    await waitFor(() => expect(load).toBeEnabled());
    expect(tileLayer).not.toHaveBeenCalled();
    fireEvent.click(load);
    expect(tileLayer).toHaveBeenCalledWith(
      "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
      expect.any(Object),
    );
    fireEvent.click(screen.getByRole("button", { name: "Remove OpenStreetMap basemap" }));
    expect(screen.getByRole("button", { name: "Load OpenStreetMap basemap" })).toBeInTheDocument();
  });

  it("requests only viewport aggregates and treats source names as text", async () => {
    request.mockResolvedValue({
      type: "FeatureCollection",
      features: [
        {
          type: "Feature",
          geometry: { type: "Point", coordinates: [-75, 40] },
          properties: {
            count: 4,
            device_id: "radio:fixture",
            name: '<img src=x onerror="throw 1">',
            type: "WIFI",
          },
        },
      ],
      total: 4,
      truncated: false,
    });
    const onDevice = vi.fn();
    render(
      <WirelessMap
        filters={{ dataset_id: "dataset:fixture" }}
        bounds={[-75, 40, -74, 41]}
        onDevice={onDevice}
      />,
    );
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith(
        "/api/wireless/map",
        expect.objectContaining({
          params: {
            dataset_id: "dataset:fixture",
            bbox: "-75.000000,40.000000,-74.000000,41.000000",
            zoom: "8",
          },
          signal: expect.any(AbortSignal),
        }),
      ),
    );
    await screen.findByText("4 observations in view · 1 map groups");
    expect(state.points[0]?.label.textContent).toContain("<img src=x");
    expect(state.points[0]?.label.querySelector("img")).toBeNull();
    state.points[0]?.callback();
    expect(onDevice).toHaveBeenCalledWith("radio:fixture");
    fireEvent.click(screen.getByRole("button", { name: "Fit dataset" }));
    expect(state.fit).toHaveBeenCalledWith(
      [
        [40, -75],
        [41, -74],
      ],
      { padding: [24, 24], maxZoom: 15 },
    );
  });

  it("aborts stale viewport requests on pan and component teardown", async () => {
    request.mockImplementation(() => new Promise(() => {}));
    const view = render(<WirelessMap filters={{}} onDevice={vi.fn()} />);
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    const first = request.mock.calls[0]?.[1]?.signal;
    state.events.get("moveend")?.();
    expect(first?.aborted).toBe(true);
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    const second = request.mock.calls[1]?.[1]?.signal;
    view.unmount();
    expect(second?.aborted).toBe(true);
    expect(state.removed).toHaveBeenCalledOnce();
  });

  it("zooms clusters instead of inventing a single device identity", async () => {
    request.mockResolvedValue({
      type: "FeatureCollection",
      features: [
        {
          type: "Feature",
          geometry: { type: "Point", coordinates: [-75, 40] },
          properties: { count: 500 },
        },
      ],
      total: 500,
      truncated: true,
    });
    const onDevice = vi.fn();
    render(<WirelessMap filters={{ type: "BLE" }} onDevice={onDevice} />);
    await screen.findByText(/zoom in for more/);
    state.points[0]?.callback();
    expect(state.view).toHaveBeenLastCalledWith([40, -75], 10);
    expect(onDevice).not.toHaveBeenCalled();
  });
});
