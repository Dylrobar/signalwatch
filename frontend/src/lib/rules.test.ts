import { describe, expect, it } from "vitest";
import { ApiError, joinUrl, normalizeBaseUrl } from "./api";
import { phaseOf } from "../hooks/use-signalwatch";
import { percent } from "./format";
import { sourceHealth, sourceRecords } from "./sources";
import { clampOffset, exportParams, parseView } from "./views";

describe("rules", () => {
  it("keeps base path prefix", () => expect(joinUrl("https://h/signalwatch", "/api/status")).toBe("https://h/signalwatch/api/status"));
  it("rejects remote http", () => expect(() => normalizeBaseUrl("http://example.com")).toThrow());
  it("allows localhost http", () => expect(normalizeBaseUrl("http://localhost:8000/")).toBe("http://localhost:8000"));
  it("maps export kinds", () => {
    expect(exportParams(parseView({ tab: "infrastructure", kind: "domain" }))["entity_kind"]).toBe("domain");
    expect(exportParams(parseView({ tab: "changes", event_kind: "kev_added" }))["event_kind"]).toBe("kev_added");
  });
  it("errors are never healthy", () => expect(sourceHealth({ persisted: true, last_success: "x", counts: { errors: ["e"] } }, false)).toBe("partial"));
  it("prefers counts.records", () => expect(sourceRecords({ counts: { records: 5, advisories: 5 } })).toBe(5));
  it("epss fraction to percent", () => expect(percent(0.5)).toBe("50.0%"));
  it("clamps offset", () => expect(clampOffset(500, 120)).toBe(100));
  it("rejects inherited event names", () => {
    expect(parseView({ tab: "changes", event_kind: "__proto__" }).event_kind).toBe("");
    expect(parseView({ tab: "changes", event_kind: "toString" }).event_kind).toBe("");
  });
  it("reports a network failure when cached status exists", () => {
    expect(phaseOf("https://backend.example", { isPending: false, error: new ApiError("network", "Offline"), data: { stats: { advisories: 5 } } })).toBe("unreachable");
  });
  it("reports a backend failure when cached status exists", () => {
    expect(phaseOf("https://backend.example", { isPending: false, error: new ApiError("http", "Failed", 500), data: { stats: { advisories: 5 } } })).toBe("error");
  });
});
