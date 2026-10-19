import { describe, expect, it } from "vitest";
import { compactView, parseView, TABS } from "./views";
import { mapParams, validBounds, wirelessTime, wirelessTimeLabel } from "./wireless";

describe("wireless routing and coordinates", () => {
  it("shares the wireless subview without introducing another main tab", () => {
    expect(TABS).toHaveLength(6);
    expect(compactView(parseView({ tab: "infrastructure", infra: "wireless" }))).toEqual({
      tab: "infrastructure",
      infra: "wireless",
    });
    expect(compactView(parseView({ tab: "news", infra: "wireless" }))).toEqual({ tab: "news" });
  });
  it("sends bounded viewport coordinates and supported zoom values", () => {
    expect(mapParams([-75.1234567, 39.1234567, -74.5, 40], 30, { type: "WIFI" })).toEqual({
      type: "WIFI",
      bbox: "-75.123457,39.123457,-74.500000,40.000000",
      zoom: "19",
    });
    expect(validBounds([-75, 40, -74, 41])).toBe(true);
    expect(validBounds([1, 40, -1, 41])).toBe(false);
    expect(validBounds([NaN, 40, -74, 41])).toBe(false);
  });
  it("preserves unspecified source times and distinguishes documented UTC exports", () => {
    expect(wirelessTime("2026-10-01T12:34:56")).toBe("2026-10-01 12:34:56");
    expect(wirelessTime("1970-01-01 00:00:00")).toBe("Unknown (source epoch sentinel)");
    expect(wirelessTimeLabel("UTC")).toBe("Observation time · UTC");
    expect(wirelessTimeLabel(undefined)).toContain("timezone unspecified");
  });
});
