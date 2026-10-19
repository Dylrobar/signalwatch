import { describe, expect, it } from "vitest";
import { mergeSources, providerRecords, providerStatus, sourceErrors, sourceHealth, sourceInterval, sourceIssues, type SourceProvider } from "./sources";

describe("collector issue presentation", () => {
  it("summarizes a persisted Wikidata 429 without exposing its giant query or HTML response", () => {
    const source = { persisted: true, status: "error", error: `HTTP 429: https://query.wikidata.org/sparql?query=SELECT+${"company+".repeat(2000)}&format=json <!DOCTYPE html><html><style>body { color: red; }</style><title>Wikimedia Error</title></html>` };
    const issues = sourceIssues(sourceErrors(source));
    expect(sourceHealth(source, false)).toBe("error");
    expect(issues.summary).toBe("Rate limited (HTTP 429)");
    expect(issues.details).toEqual(["HTTP 429: https://query.wikidata.org/sparql?… [response body omitted]"]);
  });

  it("preserves separate web failures and Partial health while stripping HTML between errors", () => {
    const source = { persisted: true, last_success: "2026-10-18", status: "partial", error: "Connection timeout to host http://example.com/robots.txt; Cannot connect to host missing.example:443 ssl:default [Name or service not known]; robots.txt disallows https://restricted.example/; HTTP 404: https://old.example/ <!DOCTYPE html><html><head><title>ConnectYourDomain Error</title></head></html>; HTTP 522: https://offline.example/robots.txt <!DOCTYPE html><html>unavailable</html>", counts: { records: 46 } };
    const issues = sourceIssues(sourceErrors(source));
    expect(sourceHealth(source, false)).toBe("partial");
    expect(issues.summary).toContain("Blocked by robots.txt");
    expect(issues.summary).toContain("robots.txt unavailable");
    expect(issues.details).toHaveLength(5);
    expect(issues.details.join(" ")).toContain("Name or service not known");
    expect(issues.details.join(" ")).toContain("HTTP 522: https://offline.example/robots.txt");
    expect(issues.details.join(" ")).not.toMatch(/<html|ConnectYourDomain/);
  });

  it("does not label permitted robots files unavailable because another page returned 404", () => {
    expect(sourceIssues(["robots.txt disallows https://restricted.example/; HTTP 404: https://old.example/"]).summary).not.toContain("robots.txt unavailable");
  });

  it("bounds the number and length of details while retaining omitted message counts", () => {
    const issues = sourceIssues(Array.from({ length: 20 }, (_, n) => `Failure ${n}: ${"x".repeat(900)}`));
    expect(issues.details).toHaveLength(12);
    expect(issues.omitted).toBe(8);
    expect(issues.details.every((detail) => detail.length <= 400)).toBe(true);
    expect(issues.summary.length).toBeLessThanOrEqual(151);
  });

  it("deduplicates sanitized errors and retains numeric source error counts", () => {
    const issues = sourceIssues(sourceErrors({ error: "HTTP 429: https://query.example/?query=first", counts: { errors: ["HTTP 429: https://query.example/?query=second", "3 errors reported"] } }));
    expect(issues.details).toEqual(["HTTP 429: https://query.example/?…", "3 errors reported"]);
  });
});

describe("expanded source health", () => {
  it("shows missing setup before considering a previous success or persisted record", () => {
    expect(sourceHealth({ persisted: true, status: "unconfigured", last_success: "2026-10-18" }, false)).toBe("unconfigured");
    expect(sourceHealth({ status: "unconfigured" }, false)).toBe("unconfigured");
    expect(sourceHealth({ persisted: true, status: "unconfigured" }, true)).toBe("collecting");
  });

  it("merges configured families once and prefers current configured schedules over stale state", () => {
    const { families, historical } = mergeSources({ config: { sources: { corporate: true, exposure: true, hardware: false }, source_intervals: { corporate: 10080, exposure: 1440, hardware: 43200 } }, sources: [
      { name: "corporate", status: "unconfigured", interval_minutes: 1440, last_run: "2026-10-18T12:00:00Z", next_run: "2026-10-19T12:00:00Z" },
      { name: "nvd:2025", status: "ok" },
    ] });
    expect(families.map((source) => source["name"])).toEqual(["corporate", "exposure", "hardware"]);
    expect(families[0]).toMatchObject({ persisted: true, interval_minutes: 10080, next_run: "2026-10-19T12:00:00Z" });
    expect(families[1]).toMatchObject({ persisted: false, interval_minutes: 1440 });
    expect(historical).toHaveLength(1);
  });

  it("preserves explicit partial and skipped outcomes without a previous successful collection", () => {
    expect(sourceHealth({ persisted: true, status: "partial", errors: ["Deferred providers"] }, false)).toBe("partial");
    expect(sourceHealth({ persisted: true, status: "skipped" }, false)).toBe("skipped");
    expect(sourceHealth({ persisted: true, status: "error" }, false)).toBe("error");
  });

  it("collects direct provider error arrays alongside family count errors", () => {
    expect(sourceErrors({ errors: ["Provider failed", { source: "https://provider.test/data", error: "HTTP 503" }], counts: { errors: ["Provider failed"] } })).toEqual(["Provider failed", "https://provider.test/data: HTTP 503"]);
  });

  it("formats reported schedules without inventing missing intervals", () => {
    expect(sourceInterval({ interval_minutes: 10080 })).toBe("Every week");
    expect(sourceInterval({ interval_minutes: 360 })).toBe("Every 6 hours");
    expect(sourceInterval({ interval_minutes: 15 })).toBe("Every 15 min");
    expect(sourceInterval({})).toBe("not reported");
    expect(sourceInterval({ interval_minutes: -1 })).toBe("not reported");
  });

  const provider: SourceProvider = { id: "test", name: "Test", category: "Network", family: "exposure", access: "api_key", description: "", homepage: "https://example.test", required: [], status: "ready", requirements: [], credential_configured: true, enabled: true };

  it("does not let old provider success hide disabled or missing configuration", () => {
    expect(providerStatus({ ...provider, requirements: ["Add API key"] }, { status: "ok" })).toBe("unconfigured");
    expect(providerStatus({ ...provider, status: "unconfigured" }, { status: "ok" })).toBe("unconfigured");
    expect(providerStatus({ ...provider, enabled: false }, { status: "ok" })).toBe("disabled");
    expect(providerStatus(provider, { status: "error" })).toBe("error");
    expect(providerStatus(provider, undefined)).toBe("ready");
  });

  it("only shows provider record counts explicitly reported by the backend", () => {
    expect(providerRecords(undefined)).toBeNull();
    expect(providerRecords({ status: "ok" })).toBeNull();
    expect(providerRecords({ records: 0 })).toBe(0);
    expect(providerRecords({ staged: 9 })).toBe(9);
    expect(providerRecords({ counts: { records: 3 } })).toBe(3);
  });
});
