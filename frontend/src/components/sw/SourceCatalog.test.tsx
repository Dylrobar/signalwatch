import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, connection } from "@/lib/api";
import type { SourceProvider } from "@/lib/sources";
import { Collectors } from "./Collectors";
import { SourceCatalog } from "./SourceCatalog";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  api: vi.fn(),
}));
const request = vi.mocked(api);
const clients: QueryClient[] = [];
const provider: SourceProvider = {
  id: "shodan",
  name: "Shodan",
  category: "Network edge",
  family: "exposure",
  access: "api_key",
  description: "Indexed public service observations",
  homepage: "https://www.shodan.io/",
  required: ["shodan_api_key"],
  status: "unconfigured",
  requirements: ["Configure Shodan API key", "Add company domains"],
  credential_configured: false,
  enabled: true,
};

function mount(content: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  return render(<QueryClientProvider client={client}>{content}</QueryClientProvider>);
}

beforeEach(() => {
  request.mockReset();
  connection.set("https://backend.example", "private-token", false);
});
afterEach(() => {
  cleanup();
  clients.splice(0).forEach((client) => client.clear());
  connection.clear();
});

describe("provider catalog", () => {
  it("fetches the runtime catalog and shows missing setup over a historical provider success", async () => {
    request.mockResolvedValue({
      items: [
        provider,
        {
          ...provider,
          id: "crtsh",
          name: "Certificate Transparency",
          access: "public",
          required: [],
          status: "ready",
          requirements: [],
          credential_configured: false,
        },
      ],
      total: 2,
    });
    const { container } = mount(
      <SourceCatalog
        families={[
          {
            name: "exposure",
            counts: {
              provider_health: {
                shodan: { status: "ok", records: 7, last_attempt: "2026-10-18T12:00:00Z" },
                crtsh: {
                  status: "error",
                  error: "HTTP 429: https://crt.sh/?q=example.test",
                  staged: 0,
                },
              },
            },
          },
        ]}
      />,
    );
    expect(await screen.findByText(/2 sources · 1 configured · 1 need setup/)).toBeInTheDocument();
    expect(request).toHaveBeenCalledWith(
      "/api/sources/catalog",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(container.querySelector("details")).not.toHaveAttribute("open");
    const shodan = screen.getByText("Shodan").closest("tr")!;
    expect(within(shodan).getByText("Needs setup")).toBeInTheDocument();
    expect(within(shodan).getByText("Configure Shodan API key")).toBeInTheDocument();
    expect(within(shodan).getByText("Add company domains")).toBeInTheDocument();
    expect(within(shodan).getByText("7")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Shodan" })).toHaveAttribute(
      "href",
      "https://www.shodan.io/",
    );
    expect(container).not.toHaveTextContent("private-token");
    const crt = screen.getByText("Certificate Transparency").closest("tr")!;
    expect(within(crt).getByText("Error")).toBeInTheDocument();
    expect(within(crt).getByText("Rate limited (HTTP 429)")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Filter providers" }), {
      target: { value: "Shodan" },
    });
    expect(screen.getByText("Shodan")).toBeInTheDocument();
    expect(screen.queryByText("Certificate Transparency")).not.toBeInTheDocument();
  });

  it("preserves unknown counts and disabled status rather than inventing a healthy run", async () => {
    request.mockResolvedValue({ items: [{ ...provider, enabled: false }], total: 1 });
    mount(<SourceCatalog families={[]} />);
    expect(await screen.findByText("Disabled")).toBeInTheDocument();
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(screen.queryByText("Healthy")).not.toBeInTheDocument();
    expect(screen.queryByText("Updated")).not.toBeInTheDocument();
  });

  it("uses catalog provider health and exact native family counts without combining unrelated providers", async () => {
    request.mockResolvedValue({
      items: [
        {
          ...provider,
          requirements: [],
          status: "ready",
          credential_configured: true,
          health: { status: "error", records: 4, errors: ["Provider request failed"] },
        },
        {
          ...provider,
          id: "nvd",
          name: "NVD",
          family: "nvd",
          access: "native",
          requirements: [],
          status: "ok",
        },
      ],
      total: 2,
    });
    mount(
      <SourceCatalog
        families={[
          {
            name: "exposure",
            counts: { provider_health: { shodan: { status: "ok", records: 20 } } },
          },
          { name: "nvd", status: "ok", counts: { records: 12 }, last_run: "2026-10-18T12:00:00Z" },
        ]}
      />,
    );
    const shodan = (await screen.findByText("Shodan")).closest("tr")!;
    expect(within(shodan).getByText("Error")).toBeInTheDocument();
    expect(within(shodan).getByText("4")).toBeInTheDocument();
    expect(
      within(shodan).getByText("Provider request failed", { selector: "p" }),
    ).toBeInTheDocument();
    expect(within(shodan).queryByText("20")).not.toBeInTheDocument();
    const native = screen.getByText("NVD").closest("tr")!;
    expect(within(native).getByText("12")).toBeInTheDocument();
    expect(within(native).getByText(/^Attempt:/)).not.toHaveTextContent("not reported");
  });

  it("does not resurrect stale family provider health when the catalog explicitly clears it", async () => {
    request.mockResolvedValue({
      items: [{ ...provider, status: "ready", requirements: [], health: {} }],
      total: 1,
    });
    mount(
      <SourceCatalog
        families={[
          {
            name: "exposure",
            counts: { provider_health: { shodan: { status: "ok", records: 20 } } },
          },
        ]}
      />,
    );
    const row = (await screen.findByText("Shodan")).closest("tr")!;
    expect(within(row).getByText("Ready")).toBeInTheDocument();
    expect(within(row).getByText("unknown")).toBeInTheDocument();
    expect(within(row).queryByText("Updated")).not.toBeInTheDocument();
    expect(within(row).queryByText("20")).not.toBeInTheDocument();
  });

  it("shows a catalog error and retries independently of the collector table", async () => {
    request
      .mockRejectedValueOnce(new ApiError("http", "HTTP 503: temporarily unavailable", 503))
      .mockResolvedValueOnce({ items: [], total: 0 });
    mount(<SourceCatalog families={[]} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Provider catalog unavailable");
    fireEvent.click(screen.getByRole("button", { name: "Retry catalog" }));
    expect(
      await screen.findByText("The backend returned no provider entries."),
    ).toBeInTheDocument();
  });

  it("cancels the catalog request when the collector surface unmounts", async () => {
    request.mockImplementation(() => new Promise(() => {}));
    const { unmount } = mount(<SourceCatalog families={[]} />);
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    const signal = request.mock.calls[0]?.[1]?.signal;
    expect(signal?.aborted).toBe(false);
    unmount();
    expect(signal?.aborted).toBe(true);
  });

  it("renders dynamic families and backend schedules without turning providers into family runs", async () => {
    request.mockResolvedValue({ items: [provider], total: 1 });
    mount(
      <Collectors
        refresh={vi.fn()}
        status={{
          config: {
            sources: { exposure: true, corporate: true, hardware: false },
            source_intervals: { exposure: 10080, corporate: 10080, hardware: 43200 },
          },
          sources: [
            {
              name: "exposure",
              status: "unconfigured",
              last_success: "2026-10-18T12:00:00Z",
              next_run: "2026-10-25T12:00:00Z",
              interval_minutes: 10080,
            },
          ],
        }}
      />,
    );
    const health = screen
      .getByRole("table", { name: "" })
      .closest("div[aria-label='Collector health']");
    expect(health).not.toBeNull();
    const row = screen.getByRole("button", { name: "Run exposure collector" }).closest("tr")!;
    expect(within(row).getByText("Needs setup")).toBeInTheDocument();
    expect(within(row).getByText("Every week")).toBeInTheDocument();
    expect(within(row).getByText(/^Next:/)).not.toHaveTextContent("not reported");
    expect(screen.getByRole("button", { name: "Run corporate collector" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run shodan collector" })).not.toBeInTheDocument();
    await screen.findByText(/^Provider coverage · 1 source/);
  });
});
