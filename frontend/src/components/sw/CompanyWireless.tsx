import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useConnection } from "@/hooks/use-signalwatch";
import { api, ApiError } from "@/lib/api";
import { num } from "@/lib/format";
import {
  RADIO_LABELS,
  WIRELESS_ROLES,
  type CompanyWirelessSummary,
  type WirelessDevice,
} from "@/lib/wireless";
import { WirelessDetail } from "./WirelessDetail";

export function CompanyWireless({
  companyId,
  onCompany,
  summary,
}: {
  companyId: string;
  onCompany: (id: string) => void;
  summary?: CompanyWirelessSummary | undefined;
}) {
  const [open, setOpen] = useState(false);
  const total =
    summary?.distinct_device_count ??
    summary?.device_count ??
    (typeof summary?.devices === "number" ? summary.devices : undefined);
  return (
    <section className="mt-5 border-t border-border pt-4" aria-label="Company wireless evidence">
      <button
        type="button"
        className="sw-btn"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        Wireless relationships{total != null ? ` (${num(total)})` : ""}
      </button>
      {summary && (
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          {Object.entries(summary.counts_by_role ?? {})
            .filter(([, count]) => count > 0)
            .map(([role, count]) => (
              <span key={role}>
                {num(count)} {WIRELESS_ROLES[role] ?? role.replaceAll("_", " ")}
              </span>
            ))}
          {summary.facility_count ? (
            <span>{num(summary.facility_count)} recorded company locations</span>
          ) : null}
        </div>
      )}
      {open && <CompanyWirelessData companyId={companyId} onCompany={onCompany} />}
    </section>
  );
}

function CompanyWirelessData({
  companyId,
  onCompany,
}: {
  companyId: string;
  onCompany: (id: string) => void;
}) {
  const conn = useConnection();
  const [selected, setSelected] = useState("");
  const query = useQuery<{ items: WirelessDevice[]; total: number }, ApiError>({
    queryKey: ["wireless-company", conn.gen, companyId],
    queryFn: ({ signal }) =>
      api("/api/wireless/devices", {
        params: { company_id: companyId, limit: "20", offset: "0" },
        signal,
      }),
    retry: false,
  });
  return (
    <div className="mt-3 space-y-3">
      <p className="text-xs text-muted-foreground">
        Manufacturer registration, advertised service, proximity candidates and confirmed operation
        remain separate relationship roles.
      </p>
      {query.isPending ? (
        <p role="status" className="text-sm text-muted-foreground">
          Loading related signals…
        </p>
      ) : query.error ? (
        <p role="alert" className="text-sm text-destructive">
          {query.error.message}
        </p>
      ) : query.data?.items.length ? (
        <ul className="divide-y divide-border">
          {query.data.items.map((device) => (
            <li key={device.id} className="py-2">
              <button
                type="button"
                className="text-left text-sm text-primary hover:underline"
                onClick={() => setSelected((value) => (value === device.id ? "" : device.id))}
                aria-expanded={selected === device.id}
              >
                {device.name || device.identifier} · {RADIO_LABELS[device.type] ?? device.type}
              </button>
              <p className="mt-1 text-xs text-muted-foreground">
                {device.company_links
                  ?.filter((link) => link.company_id === companyId)
                  .map((link) => WIRELESS_ROLES[link.role] ?? link.role)
                  .join(" · ")}
              </p>
              {selected === device.id && (
                <div className="mt-4 border-l border-border pl-3">
                  <WirelessDetail id={device.id} gen={conn.gen} onCompany={onCompany} />
                </div>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted-foreground">
          No wireless evidence linked to this company.
        </p>
      )}
      {query.data && query.data.total > query.data.items.length && (
        <p className="text-xs text-muted-foreground">
          Showing the first {num(query.data.items.length)} of {num(query.data.total)} related
          radios. Use Infrastructure → Wireless to search the complete dataset.
        </p>
      )}
    </div>
  );
}
