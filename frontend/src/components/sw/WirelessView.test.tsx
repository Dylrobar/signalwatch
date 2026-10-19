import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import type { WirelessDevice } from "@/lib/wireless";
import { WirelessView } from "./WirelessView";
import { WirelessCompanyLinks, WirelessDetail } from "./WirelessDetail";
import { CompanyWireless } from "./CompanyWireless";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  api: vi.fn(),
}));
vi.mock("./WirelessMap", () => ({
  WirelessMap: ({
    filters,
    onDevice,
  }: {
    filters: Record<string, string>;
    onDevice: (id: string) => void;
  }) => (
    <div aria-label="Wireless map test">
      <pre>{JSON.stringify(filters)}</pre>
      <button onClick={() => onDevice("radio:fixture")}>Inspect mapped radio</button>
    </div>
  ),
}));

const request = vi.mocked(api);
const device: WirelessDevice = {
  id: "radio:fixture",
  identifier: "02:00:00:00:00:01",
  name: "Test radio",
  type: "WIFI",
  observations: 4,
  first_seen: "1970-01-01 00:00:00",
  last_seen: "2026-10-01 12:00:00",
  timestamp_timezone: "UTC",
  rssi: -60,
  gps_accuracy: 120,
  locations: [{ latitude: 40, longitude: -75, gps_accuracy: 120, rssi: -60 }],
  company_links: [
    {
      company_id: "company:fixture",
      company_name: "Fixture Networks",
      role: "registered_manufacturer",
      confidence: 0.8,
      evidence: "Public registration",
    },
    {
      company_id: "company:nearby",
      company_name: "Nearby Fixture",
      role: "nearby_business_candidate",
      confidence: 0.2,
      distance_m: 100,
    },
  ],
  provenance: { source: "Imported fixture", source_sha256: "fixture-hash" },
};

function mount(element: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return {
    client,
    ...render(<QueryClientProvider client={client}>{element}</QueryClientProvider>),
  };
}

beforeEach(() => {
  request.mockReset();
  request.mockImplementation(async (path) => {
    if (path === "/api/wireless/datasets")
      return {
        items: [
          {
            id: "dataset:fixture",
            name: "Fixture export",
            status: "ready",
            observations: 4,
            devices: 1,
            bounds: [-75, 40, -75, 40],
            timestamp_timezone: "UTC",
          },
        ],
        total: 1,
      };
    if (path === "/api/wireless/stats")
      return {
        datasets: 1,
        devices: 1,
        observations: 4,
        company_links: 2,
        signal_types: { WIFI: 1 },
      };
    if (path === "/api/wireless/enrichment") return { status: "complete", updated_at: "prior" };
    if (path === "/api/wireless/devices") return { items: [device], total: 1 };
    if (path === "/api/wireless/devices/radio%3Afixture") return device;
    if (path === "/api/search")
      return { items: [{ id: "company:fixture", name: "Fixture Networks" }] };
    if (path === "/api/import/wigle") return { dataset_id: "dataset:fixture", status: "queued" };
    throw new Error(`Unexpected path ${path}`);
  });
});
afterEach(cleanup);

describe("wireless dataset interface", () => {
  it("requests a location-based business lookup only through its explicit control", async () => {
    mount(<WirelessView gen={11} onCompany={vi.fn()} />);
    await screen.findByLabelText("Wireless map test");
    expect(request.mock.calls.some(([, options]) => options?.method === "POST")).toBe(false);
    fireEvent.click(
      screen.getByRole("button", { name: "Find nearby businesses with OpenStreetMap" }),
    );
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith(
        "/api/wireless/enrichment",
        expect.objectContaining({
          method: "POST",
          body: {
            manufacturers: false,
            facilities: true,
            lookup_businesses: true,
            bbox: [-75, 40, -75, 40],
          },
        }),
      ),
    );
  });

  it("uses bounded map data rather than downloading the device inventory on mount", async () => {
    mount(<WirelessView gen={1} onCompany={vi.fn()} />);
    await screen.findByLabelText("Wireless map test");
    expect(screen.getByText("Distinct radios")).toBeInTheDocument();
    expect(request.mock.calls.some(([path]) => path === "/api/wireless/devices")).toBe(false);
    expect(screen.getAllByRole("button", { name: "Devices" })).toHaveLength(1);
  });

  it("applies dataset, radio, company and debounced text filters to map and paginated devices", async () => {
    mount(<WirelessView gen={2} onCompany={vi.fn()} />);
    await screen.findByLabelText("Wireless map test");
    await screen.findByRole("option", { name: "Fixture Networks" });
    fireEvent.change(screen.getByLabelText("Wireless dataset"), {
      target: { value: "dataset:fixture" },
    });
    fireEvent.change(screen.getByLabelText("Radio type"), { target: { value: "WIFI" } });
    fireEvent.change(screen.getByLabelText("Related company"), {
      target: { value: "company:fixture" },
    });
    fireEvent.change(screen.getByLabelText("Search wireless signals"), {
      target: { value: "radio query" },
    });
    await waitFor(() =>
      expect(screen.getByLabelText("Wireless map test")).toHaveTextContent('"q":"radio query"'),
    );
    fireEvent.click(screen.getByRole("button", { name: "Devices" }));
    await screen.findByRole("button", { name: "Test radio" });
    expect(request).toHaveBeenCalledWith(
      "/api/wireless/devices",
      expect.objectContaining({
        params: {
          dataset_id: "dataset:fixture",
          type: "WIFI",
          q: "radio query",
          company_id: "company:fixture",
          limit: "50",
          offset: "0",
        },
        signal: expect.any(AbortSignal),
      }),
    );
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("opens an actual mapped signal detail and navigates related companies", async () => {
    const onCompany = vi.fn();
    mount(<WirelessView gen={3} onCompany={onCompany} />);
    fireEvent.click(await screen.findByRole("button", { name: "Inspect mapped radio" }));
    const dialog = await screen.findByRole("dialog", { name: "Wireless signal evidence" });
    await within(dialog).findByText("Registered manufacturer");
    fireEvent.click(within(dialog).getByRole("button", { name: "Fixture Networks" }));
    expect(onCompany).toHaveBeenCalledWith("company:fixture");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("uploads original gzip bytes through the authenticated central client", async () => {
    mount(<WirelessView gen={4} onCompany={vi.fn()} />);
    const blob = new File([new Uint8Array([31, 139, 8, 0])], "export test.gz", {
      type: "application/gzip",
    });
    fireEvent.change(screen.getByLabelText("WiGLE CSV or gzip export"), {
      target: { files: [blob] },
    });
    await screen.findByText("Export received. Import progress appears below.");
    expect(request).toHaveBeenCalledWith(
      "/api/import/wigle",
      expect.objectContaining({
        method: "POST",
        rawBody: blob,
        filename: "export test.gz",
        contentType: "application/gzip",
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("rejects oversized browser uploads before any request", async () => {
    mount(<WirelessView gen={5} onCompany={vi.fn()} />);
    const blob = new File(["x"], "oversized.csv");
    Object.defineProperty(blob, "size", { value: 33 * 1024 * 1024 });
    fireEvent.change(screen.getByLabelText("WiGLE CSV or gzip export"), {
      target: { files: [blob] },
    });
    await screen.findByText(/exceeds the default 32 MiB limit/);
    expect(request.mock.calls.some(([path]) => path === "/api/import/wigle")).toBe(false);
  });
});

describe("wireless evidence semantics", () => {
  it("shows the nearest three business candidates with expansion and server bounds", () => {
    const links = [4, 2, 1, 3].map((distance) => ({
      company_id: `company:${distance}`,
      company_name: `Candidate ${distance}`,
      role: "candidate_business",
      distance_m: distance * 100,
    }));
    render(
      <WirelessCompanyLinks
        links={[
          ...links,
          {
            company_id: "company:maker",
            company_name: "Fixture maker",
            role: "manufacturer",
            distance_m: 0,
          },
        ]}
        onCompany={vi.fn()}
        total={120}
        truncated
      />,
    );
    expect(screen.getByRole("button", { name: "Fixture maker" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Candidate 1" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Candidate 4" })).not.toBeInTheDocument();
    expect(screen.getByText(/Showing 5 of 120 attribution records/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show 1 more nearby business candidates" }));
    expect(screen.getByRole("button", { name: "Candidate 4" })).toBeInTheDocument();
  });

  it("does not present rejected company associations as active device links", async () => {
    const previous = request.getMockImplementation()!;
    request.mockImplementation(async (path, options) =>
      path === "/api/wireless/devices"
        ? {
            items: [
              {
                ...device,
                company_links: [
                  {
                    company_id: "company:fixture",
                    company_name: "Fixture Networks",
                    role: "confirmed_operator",
                    status: "rejected",
                  },
                ],
              },
            ],
            total: 1,
          }
        : previous(path, options),
    );
    mount(<WirelessView gen={10} onCompany={vi.fn()} />);
    await screen.findByLabelText("Wireless map test");
    fireEvent.click(screen.getByRole("button", { name: "Devices" }));
    await screen.findByRole("button", { name: "Test radio" });
    expect(screen.getByText("No supported company link")).toBeInTheDocument();
    expect(screen.queryByText("Confirmed operator")).not.toBeInTheDocument();
  });

  it.each(["confirmed", "rejected"])("persists a sourced %s operator decision", async (status) => {
    const previous = request.getMockImplementation()!;
    request.mockImplementation(async (path, options) =>
      path === "/api/wireless/devices/radio%3Afixture/company"
        ? {
            ...device,
            company_links: [
              {
                company_id: "company:fixture",
                company_name: "Fixture Networks",
                role: "confirmed_operator",
                status,
              },
            ],
          }
        : previous(path, options),
    );
    mount(<WirelessDetail id="radio:fixture" gen={7} onCompany={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Review operator relationship" }));
    await screen.findByRole("option", { name: "Fixture Networks" });
    const save = screen.getByRole("button", { name: "Save operator decision" });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Operator company"), {
      target: { value: "company:fixture" },
    });
    fireEvent.change(screen.getByLabelText("Operator decision"), { target: { value: status } });
    fireEvent.change(screen.getByLabelText("Evidence for operator decision"), {
      target: { value: "Verified inventory record" },
    });
    fireEvent.change(screen.getByLabelText("Operator evidence source URL"), {
      target: { value: "https://fixture.example/inventory" },
    });
    fireEvent.click(save);
    await screen.findByText(
      status === "confirmed" ? "Confirmed operator" : "Operator attribution rejected",
    );
    expect(request).toHaveBeenCalledWith(
      "/api/wireless/devices/radio%3Afixture/company",
      expect.objectContaining({
        method: "POST",
        body: {
          company_id: "company:fixture",
          status,
          evidence: "Verified inventory record",
          source_url: "https://fixture.example/inventory",
        },
        signal: expect.any(AbortSignal),
      }),
    );
    expect(
      screen.queryByRole("form", { name: "Review wireless operator" }),
    ).not.toBeInTheDocument();
  });

  it("starts company enrichment and updates controls after a fresh terminal status", async () => {
    const previous = request.getMockImplementation()!;
    let started = false;
    request.mockImplementation(async (path, options) => {
      if (path === "/api/wireless/enrichment" && options?.method === "POST") {
        started = true;
        return { status: "queued" };
      }
      if (path === "/api/wireless/enrichment" && started)
        return { status: "running", updated_at: "new-running" };
      return previous(path, options);
    });
    const { client } = mount(<WirelessView gen={8} onCompany={vi.fn()} />);
    await screen.findByLabelText("Wireless map test");
    fireEvent.click(screen.getByRole("button", { name: "Enrich companies" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Enriching companies…" })).toBeDisabled(),
    );
    expect(request).toHaveBeenCalledWith(
      "/api/wireless/enrichment",
      expect.objectContaining({
        method: "POST",
        body: { manufacturers: true, facilities: true, lookup_businesses: false },
        signal: expect.any(AbortSignal),
      }),
    );
    await act(async () => {
      client.setQueryData(["wireless-enrichment", 8], {
        status: "complete",
        updated_at: "new-complete",
      });
    });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Enrich companies" })).toBeEnabled(),
    );
  });

  it("preserves manufacturer and proximity roles, GPS accuracy, unknown epochs and source timezones", async () => {
    mount(<WirelessDetail id="radio:fixture" gen={1} onCompany={vi.fn()} />);
    await screen.findByText("Registered manufacturer");
    expect(screen.getByText("Nearby business candidate")).toBeInTheDocument();
    expect(screen.queryByText("Confirmed operator")).not.toBeInTheDocument();
    expect(screen.getByText("Unknown (source epoch sentinel)")).toBeInTheDocument();
    expect(screen.getByText("Earliest Observation time · UTC")).toBeInTheDocument();
    expect(screen.getByText(/Coordinates describe scan observations/)).toBeInTheDocument();
    expect(screen.getAllByText("120 m")).toHaveLength(2);
    expect(screen.getByText(/fixture-hash/)).toBeInTheDocument();
  });

  it("loads a company's related radios only after opening the relationship panel", async () => {
    mount(<CompanyWireless companyId="company:fixture" onCompany={vi.fn()} />);
    expect(request).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Wireless relationships" }));
    await screen.findByRole("button", { name: "Test radio · Wi-Fi" });
    expect(request).toHaveBeenCalledWith(
      "/api/wireless/devices",
      expect.objectContaining({
        params: { company_id: "company:fixture", limit: "20", offset: "0" },
        signal: expect.any(AbortSignal),
      }),
    );
  });
});
