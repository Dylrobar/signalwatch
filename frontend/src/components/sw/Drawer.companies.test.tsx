import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import type { CompanyProfile } from "@/lib/companies";
import { Drawer } from "./Drawer";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  api: vi.fn(),
}));

const request = vi.mocked(api);
const company: CompanyProfile = {
  company_id: "company:example",
  name: "Example",
  legal_name: "Example LLC",
  aliases: [],
  brands: [],
  parent_company_id: "company:holding",
  parent_company: { id: "company:holding", name: "Holding Company" },
  subsidiaries: [],
  notes: "",
  source_url: "",
  updated_at: "",
  assets: [],
  assets_truncated: false,
};
const companyDetail = {
  id: company.company_id,
  kind: "company",
  name: company.name,
  company_profile: company,
};
const parentDetail = {
  id: "company:holding",
  kind: "company",
  name: "Holding Company",
  company_profile: {
    ...company,
    company_id: "company:holding",
    name: "Holding Company",
    parent_company_id: "",
    parent_company: null,
  },
};

beforeAll(() =>
  Object.defineProperty(HTMLElement.prototype, "scrollTo", { configurable: true, value: vi.fn() }),
);
beforeEach(() => request.mockReset());
afterEach(cleanup);

function openCompany() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <Drawer
        initial={{
          row: { id: company.company_id, name: company.name, kind: "company" },
          tab: "infrastructure",
        }}
        onClose={vi.fn()}
      />
    </QueryClientProvider>,
  );
  return { ...view, client };
}

describe("company drawer navigation", () => {
  it("opens parent profile details and restores the original company on back", async () => {
    request.mockImplementation(async (_path, options) =>
      options?.params?.["id"] === company.company_id ? companyDetail : parentDetail,
    );
    openCompany();
    await screen.findByRole("region", { name: "Company profile" });
    fireEvent.click(screen.getByRole("button", { name: "Holding Company" }));
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Holding Company" })).toBeInTheDocument(),
    );
    expect(request).toHaveBeenCalledWith(
      "/api/entity",
      expect.objectContaining({
        params: { id: "company:holding" },
        signal: expect.any(AbortSignal),
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Back to previous record" }));
    expect(screen.getByRole("heading", { name: "Example" })).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Back to previous record" }),
    ).not.toBeInTheDocument();
    expect(request).toHaveBeenCalledTimes(2);
  });

  it("aborts a pending profile mutation during navigation and ignores its late result", async () => {
    let completeSave!: (detail: typeof companyDetail) => void;
    let saveSignal: AbortSignal | undefined;
    const pending = new Promise<typeof companyDetail>((resolve) => {
      completeSave = resolve;
    });
    request.mockImplementation(async (path, options) => {
      if (path === "/api/companies/profile") {
        saveSignal = options?.signal;
        return pending;
      }
      return options?.params?.["id"] === company.company_id ? companyDetail : parentDetail;
    });
    const { client } = openCompany();
    const invalidate = vi.spyOn(client, "invalidateQueries");
    await screen.findByRole("region", { name: "Company profile" });
    fireEvent.click(screen.getByRole("button", { name: "Holding Company" }));
    await screen.findByRole("heading", { name: "Holding Company" });
    fireEvent.click(screen.getByRole("button", { name: "Edit profile" }));
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    expect(saveSignal?.aborted).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Back to previous record" }));
    expect(saveSignal?.aborted).toBe(true);
    await act(async () =>
      completeSave({ ...companyDetail, id: "company:holding", name: "Late saved parent" }),
    );
    expect(screen.getByRole("heading", { name: "Example" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Late saved parent" })).not.toBeInTheDocument();
    expect(invalidate).not.toHaveBeenCalled();
  });
});
