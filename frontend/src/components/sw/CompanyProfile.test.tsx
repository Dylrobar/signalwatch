import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "@/lib/api";
import type { CompanyAsset, CompanyProfile as Profile } from "@/lib/companies";
import { CompanyIdentityForm, CompanyProfile } from "./CompanyProfile";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  api: vi.fn(),
}));

const request = vi.mocked(api);
const asset: CompanyAsset = {
  id: "domain:login.example",
  name: "login.example",
  status: "candidate",
  role: "owned",
  included: false,
  confidence: 0.6,
  reasons: ["Cross-domain redirect requires review"],
  evidence: [],
  observation_count: 3,
  warning_count: 1,
};

function profile(overrides: Partial<Profile> = {}): Profile {
  return {
    company_id: "company:example",
    name: "Example",
    legal_name: "Example Incorporated",
    aliases: ["Example Co"],
    brands: ["Example Cloud"],
    parent_company_id: "company:parent",
    parent_company: { id: "company:parent", name: "Parent Company" },
    subsidiaries: [],
    notes: "Recorded identity",
    source_url: "https://example.test/about",
    updated_at: "2026-10-18T12:00:00Z",
    assets: [],
    assets_truncated: false,
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

beforeEach(() => request.mockReset());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("company identity", () => {
  it("posts identity fields, normalized name lists, and an explicitly cleared parent", async () => {
    const onSaved = vi.fn();
    const detail = { id: "company:example", kind: "company", company_profile: profile() };
    request.mockResolvedValueOnce(detail);
    render(<CompanyIdentityForm profile={profile()} onSaved={onSaved} />);
    fireEvent.change(screen.getByLabelText("Company name"), { target: { value: "Example Group" } });
    fireEvent.change(screen.getByLabelText("Legal name"), {
      target: { value: "Example Group LLC" },
    });
    fireEvent.change(screen.getByLabelText("Other names · one per line"), {
      target: { value: " Example Co \nExample Ltd\nExample Co\n\n" },
    });
    fireEvent.change(screen.getByLabelText("Brands · one per line"), {
      target: { value: "Example Cloud\n Example Edge \nExample Cloud" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Clear parent" }));
    fireEvent.change(screen.getByLabelText("Notes"), {
      target: { value: "Corporate registry review" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(detail));
    expect(request).toHaveBeenCalledWith(
      "/api/companies/profile",
      expect.objectContaining({
        method: "POST",
        signal: expect.any(AbortSignal),
        body: {
          company_id: "company:example",
          name: "Example Group",
          legal_name: "Example Group LLC",
          aliases: ["Example Co", "Example Ltd"],
          brands: ["Example Cloud", "Example Edge"],
          parent_company_id: "",
          notes: "Corporate registry review",
          source_url: "https://example.test/about",
        },
      }),
    );
  });

  it("searches existing parent companies, excludes the edited company, and submits the selected ID", async () => {
    request.mockImplementation(async (path) =>
      path === "/api/search"
        ? {
            items: [
              { id: "company:example", name: "Example" },
              { id: "company:holding", name: "Holding Company" },
            ],
          }
        : { id: "company:example" },
    );
    render(<CompanyIdentityForm profile={profile()} onSaved={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Choose parent company" }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search parent companies" }), {
      target: { value: "Holding" },
    });
    const parent = await screen.findByRole("button", { name: "Holding Company" });
    expect(screen.queryByRole("button", { name: "Example" })).not.toBeInTheDocument();
    fireEvent.click(parent);
    expect(request).toHaveBeenCalledWith(
      "/api/search",
      expect.objectContaining({ params: { q: "Holding", kind: "company", limit: "25" } }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith(
        "/api/companies/profile",
        expect.objectContaining({
          body: expect.objectContaining({ parent_company_id: "company:holding" }),
        }),
      ),
    );
  });

  it("does not publish a late save result after its form unmounts", async () => {
    const pending = deferred<{ id: string }>();
    const onSaved = vi.fn();
    request.mockReturnValueOnce(pending.promise);
    const { unmount } = render(<CompanyIdentityForm profile={profile()} onSaved={onSaved} />);
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    const signal = request.mock.calls[0]?.[1]?.signal;
    expect(signal?.aborted).toBe(false);
    unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () => pending.resolve({ id: "company:example" }));
    expect(onSaved).not.toHaveBeenCalled();
  });

  it("keeps the edited identity and displays a save failure", async () => {
    request.mockRejectedValueOnce(new ApiError("http", "Parent company would create a cycle", 400));
    render(<CompanyIdentityForm profile={profile()} onSaved={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Legal name"), {
      target: { value: "Updated Legal Name" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Parent company would create a cycle",
    );
    expect(screen.getByLabelText("Legal name")).toHaveValue("Updated Legal Name");
    expect(screen.getByRole("button", { name: "Save profile" })).toBeEnabled();
  });
});

describe("company attribution decisions", () => {
  it("requires both a written decision and its supporting URL before an asset can be saved", () => {
    render(<CompanyProfile profile={profile()} go={vi.fn()} onSaved={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Add asset" }));
    const form = screen.getByRole("form", { name: "Add company asset" });
    fireEvent.change(within(form).getByLabelText("Asset hostname or URL"), {
      target: { value: "portal.example" },
    });
    const evidence = within(form).getByLabelText("Evidence for this decision");
    const source = within(form).getByLabelText("Supporting source URL");
    expect(evidence).toBeRequired();
    expect(source).toBeRequired();
    fireEvent.click(within(form).getByRole("button", { name: "Save relationship" }));
    expect(request).not.toHaveBeenCalled();
    fireEvent.change(evidence, { target: { value: "Listed by company" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save relationship" }));
    expect(request).not.toHaveBeenCalled();
    expect((form as HTMLFormElement).checkValidity()).toBe(false);
  });

  it.each([
    ["confirmed", "owned"],
    ["candidate", "service"],
    ["rejected", "owned"],
  ])(
    "posts a %s / %s decision with source evidence without implying another role",
    async (status, role) => {
      const onSaved = vi.fn();
      request.mockResolvedValueOnce({ id: "company:example" });
      render(<CompanyProfile profile={profile()} go={vi.fn()} onSaved={onSaved} />);
      fireEvent.click(screen.getByRole("button", { name: "Add asset" }));
      const form = screen.getByRole("form", { name: "Add company asset" });
      fireEvent.change(within(form).getByLabelText("Asset hostname or URL"), {
        target: { value: "https://portal.example/login" },
      });
      fireEvent.change(within(form).getByLabelText("Decision"), { target: { value: status } });
      fireEvent.change(within(form).getByLabelText("Relationship"), { target: { value: role } });
      fireEvent.change(within(form).getByLabelText("Evidence for this decision"), {
        target: { value: "Listed in company documentation" },
      });
      fireEvent.change(within(form).getByLabelText("Supporting source URL"), {
        target: { value: "https://example.test/platform" },
      });
      fireEvent.click(within(form).getByRole("button", { name: "Save relationship" }));
      await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
      expect(request).toHaveBeenCalledWith(
        "/api/companies/assets",
        expect.objectContaining({
          method: "POST",
          body: {
            company_id: "company:example",
            asset_url: "https://portal.example/login",
            status,
            role,
            evidence: "Listed in company documentation",
            source_url: "https://example.test/platform",
          },
        }),
      );
      expect(screen.queryByRole("form", { name: "Add company asset" })).not.toBeInTheDocument();
    },
  );

  it("resets an existing decision with an explicit automatic payload and no invented evidence", async () => {
    request.mockResolvedValueOnce({ id: "company:example" });
    render(
      <CompanyProfile profile={profile({ assets: [asset] })} go={vi.fn()} onSaved={vi.fn()} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Review relationship for login.example" }));
    expect(screen.getByLabelText("Asset hostname or URL")).toHaveAttribute("readonly");
    fireEvent.click(screen.getByRole("button", { name: "Reset to automatic" }));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith(
        "/api/companies/assets",
        expect.objectContaining({
          method: "POST",
          body: {
            company_id: "company:example",
            asset_url: "login.example",
            status: "automatic",
            role: "owned",
            evidence: "",
            source_url: "",
          },
        }),
      ),
    );
  });

  it("reviews a named domain using its canonical hostname rather than its display name", async () => {
    request.mockResolvedValueOnce({ id: "company:example" });
    render(
      <CompanyProfile
        profile={profile({ assets: [{ ...asset, name: "Hosted portal display name" }] })}
        go={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Review relationship for Hosted portal display name" }),
    );
    expect(screen.getByLabelText("Asset hostname or URL")).toHaveValue("login.example");
    fireEvent.click(screen.getByRole("button", { name: "Reset to automatic" }));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith(
        "/api/companies/assets",
        expect.objectContaining({ body: expect.objectContaining({ asset_url: "login.example" }) }),
      ),
    );
  });

  it("aborts a cancelled review and ignores a later failure", async () => {
    const pending = deferred<{ id: string }>();
    const onSaved = vi.fn();
    request.mockReturnValueOnce(pending.promise);
    render(
      <CompanyProfile profile={profile({ assets: [asset] })} go={vi.fn()} onSaved={onSaved} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Review relationship for login.example" }));
    fireEvent.click(screen.getByRole("button", { name: "Reset to automatic" }));
    const signal = request.mock.calls[0]?.[1]?.signal;
    fireEvent.click(screen.getByRole("button", { name: "Add asset" }));
    expect(signal?.aborted).toBe(true);
    await act(async () => pending.reject(new ApiError("http", "Late failure", 500)));
    expect(onSaved).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Add company asset" })).toBeInTheDocument();
  });
});
