import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useConnection } from "@/hooks/use-signalwatch";
import { api, ApiError } from "@/lib/api";
import { fmtDate, num, type R } from "@/lib/format";
import {
  providerRecords,
  providerStatus,
  sourceErrors,
  type SourceCatalog as Catalog,
  type SourceProvider,
} from "@/lib/sources";
import { Badge, ExtLink } from "./bits";
import { SourceIssues } from "./SourceIssues";

const ACCESS = {
  public: "Public feed",
  api_key: "API key",
  configured_url: "Configured URL",
  import: "File import",
  native: "Built in",
};
const STATES: Record<string, [string, string]> = {
  ready: ["Ready", ""],
  ok: ["Updated", "ok"],
  healthy: ["Healthy", "ok"],
  unchanged: ["Unchanged", "ok"],
  partial: ["Partial", "warn"],
  error: ["Error", "kev"],
  unconfigured: ["Needs setup", "warn"],
  disabled: ["Disabled", ""],
  running: ["Collecting…", "ok"],
  pending: ["Pending", ""],
  not_collected: ["Not collected", ""],
  interrupted: ["Interrupted", "warn"],
  unknown: ["Unknown", ""],
  skipped: ["Skipped", ""],
};

export function SourceCatalog({ families }: { families: R[] }) {
  const conn = useConnection();
  const [filter, setFilter] = useState("");
  const catalog = useQuery<Catalog, ApiError>({
    queryKey: ["source-catalog", conn.gen],
    queryFn: ({ signal }) => api<Catalog>("/api/sources/catalog", { signal }),
    enabled: Boolean(conn.baseUrl),
    retry: false,
    staleTime: 60_000,
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
  });
  const items = catalog.error ? [] : (catalog.data?.items ?? []);
  const byFamily = new Map(families.map((s) => [String(s["name"]), s]));
  const healthFor = (provider: SourceProvider): R | undefined => {
    const family = byFamily.get(provider.family);
    if (provider.health !== undefined) return provider.health;
    return (
      family?.["counts"]?.["provider_health"]?.[provider.id] ??
      (provider.access === "native" && provider.id === provider.family ? family : undefined)
    );
  };
  const ready = items.filter(
    (p) => p.enabled && providerStatus(p, healthFor(p)) !== "unconfigured",
  ).length;
  const setup = items.filter((p) => providerStatus(p, healthFor(p)) === "unconfigured").length;
  const needle = filter.trim().toLowerCase();
  const visible = items.filter((p) =>
    [p.name, p.category, p.family, p.description, ...p.requirements]
      .join(" ")
      .toLowerCase()
      .includes(needle),
  );

  return (
    <details className="sw-panel p-3">
      <summary className="cursor-pointer text-sm font-semibold">
        Provider coverage
        {catalog.data && !catalog.error
          ? ` · ${num(items.length)} ${items.length === 1 ? "source" : "sources"} · ${num(ready)} configured · ${num(setup)} need setup`
          : ""}
      </summary>
      {catalog.isPending && (
        <p role="status" className="mt-3 text-xs text-muted-foreground">
          Loading provider catalog…
        </p>
      )}
      {catalog.error && (
        <div role="alert" className="mt-3 text-xs">
          <p>Provider catalog unavailable: {catalog.error.message}</p>
          <button type="button" className="sw-btn mt-2" onClick={() => catalog.refetch()}>
            Retry catalog
          </button>
        </div>
      )}
      {!catalog.isPending && !catalog.error && (
        <>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <input
              type="search"
              aria-label="Filter providers"
              className="sw-input max-w-sm"
              placeholder="Filter by provider, family, or requirement"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <span className="text-xs text-muted-foreground">
              {num(visible.length)} of {num(items.length)} sources. Configured sources may still
              require a successful run.
            </span>
          </div>
          <div className="sw-scroll mt-3" tabIndex={0} aria-label="Provider coverage catalog">
            <table className="sw-table min-w-[850px]">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Access / setup</th>
                  <th>Status</th>
                  <th>Last reported records</th>
                  <th>Last attempt / success</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((provider) => {
                  const health = healthFor(provider);
                  const state = providerStatus(provider, health);
                  const badge = STATES[state] ?? [state.replaceAll("_", " "), ""];
                  const records = providerRecords(health);
                  return (
                    <tr key={provider.id}>
                      <td className="min-w-64 max-w-sm">
                        <ExtLink href={provider.homepage}>{provider.name}</ExtLink>
                        <div className="mt-1 font-mono text-[11px] text-muted-foreground">
                          {provider.family} · {provider.category}
                        </div>
                        <p className="mt-1 text-xs text-muted-foreground">{provider.description}</p>
                      </td>
                      <td className="max-w-sm text-xs">
                        <div>{ACCESS[provider.access]}</div>
                        {provider.requirements.length > 0 && (
                          <ul className="mt-1 list-inside list-disc text-warn">
                            {provider.requirements.map((requirement) => (
                              <li key={requirement}>{requirement}</li>
                            ))}
                          </ul>
                        )}
                        {provider.requirements.length === 0 && provider.access === "api_key" && (
                          <div className="mt-1 text-muted-foreground">
                            {provider.credential_configured
                              ? "Credential configured"
                              : "Credential status not reported"}
                          </div>
                        )}
                      </td>
                      <td>
                        <Badge tone={badge[1]}>{badge[0]}</Badge>
                        {health && (
                          <SourceIssues
                            errors={sourceErrors(health)}
                            retryAt={health["retry_at"]}
                          />
                        )}
                      </td>
                      <td className="text-xs">{records === null ? "unknown" : num(records)}</td>
                      <td className="text-xs">
                        <div>
                          Attempt:{" "}
                          {fmtDate(
                            health?.["last_attempt"] ?? health?.["last_run"],
                            true,
                            "not reported",
                          )}
                        </div>
                        <div className="mt-1">
                          Success: {fmtDate(health?.["last_success"], true, "not reported")}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {!visible.length && (
            <p className="mt-3 text-xs text-muted-foreground">
              {items.length
                ? "No providers match this filter."
                : "The backend returned no provider entries."}
            </p>
          )}
        </>
      )}
    </details>
  );
}
