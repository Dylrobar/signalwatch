import { describe, expect, it } from "vitest";
import { sourceErrors, sourceHealth, sourceIssues } from "./sources";

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
