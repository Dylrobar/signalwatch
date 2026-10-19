import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { confidence, describe, num } from "@/lib/format";
import {
  RADIO_LABELS,
  WIRELESS_ROLES,
  wirelessRssi,
  wirelessAccuracy,
  wirelessTime,
  wirelessTimeLabel,
  type WirelessCompanyLink,
  type WirelessDevice,
} from "@/lib/wireless";
import { Badge, ExtLink } from "./bits";
import { WirelessCompanyPicker } from "./WirelessCompanyPicker";

function OperatorReview({ device, gen }: { device: WirelessDevice; gen: number }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-3">
      <button
        type="button"
        className="sw-btn text-xs"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        {open ? "Close operator review" : "Review operator relationship"}
      </button>
      {open && <OperatorForm device={device} gen={gen} onClose={() => setOpen(false)} />}
    </div>
  );
}

function OperatorForm({
  device,
  gen,
  onClose,
}: {
  device: WirelessDevice;
  gen: number;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const prefix = useId();
  const [company, setCompany] = useState("");
  const [status, setStatus] = useState("confirmed");
  const [evidence, setEvidence] = useState("");
  const [source, setSource] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!company || !evidence.trim() || !source.trim()) return;
    controller.current?.abort();
    const c = new AbortController();
    controller.current = c;
    setBusy(true);
    setError("");
    try {
      const detail = await api<WirelessDevice>(
        `/api/wireless/devices/${encodeURIComponent(device.id)}/company`,
        {
          method: "POST",
          body: {
            company_id: company,
            status,
            evidence: evidence.trim(),
            source_url: source.trim(),
          },
          signal: c.signal,
        },
      );
      if (c.signal.aborted) return;
      qc.setQueryData(["wireless-detail", gen, device.id], detail);
      for (const key of ["wireless-stats", "wireless-devices", "wireless-company"])
        qc.invalidateQueries({ queryKey: [key, gen] });
      onClose();
    } catch (e) {
      if (!c.signal.aborted && (e as ApiError).kind !== "aborted") setError((e as Error).message);
    } finally {
      if (!c.signal.aborted) setBusy(false);
    }
  }
  return (
    <form
      className="mt-3 space-y-3 rounded border border-border bg-background/40 p-3"
      aria-label="Review wireless operator"
      onSubmit={submit}
    >
      <p className="text-xs text-muted-foreground">
        Record a sourced operator decision. A manufacturer assignment or nearby business point alone
        does not establish operation.
      </p>
      <fieldset disabled={busy} className="space-y-3">
        <WirelessCompanyPicker value={company} onChange={setCompany} gen={gen} operator />
        <div>
          <label htmlFor={`${prefix}-decision`} className="sw-label">
            Operator decision
          </label>
          <select
            id={`${prefix}-decision`}
            className="sw-input"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          >
            <option value="confirmed">Confirm operator</option>
            <option value="rejected">Reject company association</option>
          </select>
        </div>
        <div>
          <label htmlFor={`${prefix}-evidence`} className="sw-label">
            Evidence for operator decision
          </label>
          <textarea
            id={`${prefix}-evidence`}
            className="sw-input"
            rows={3}
            maxLength={10000}
            required
            value={evidence}
            onChange={(event) => setEvidence(event.target.value)}
          />
        </div>
        <div>
          <label htmlFor={`${prefix}-source`} className="sw-label">
            Operator evidence source URL
          </label>
          <input
            id={`${prefix}-source`}
            className="sw-input"
            type="url"
            maxLength={2000}
            required
            value={source}
            onChange={(event) => setSource(event.target.value)}
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="submit"
            className="sw-btn-primary text-xs"
            disabled={!company || !evidence.trim() || !source.trim()}
          >
            {busy ? "Saving…" : "Save operator decision"}
          </button>
          <button type="button" className="sw-btn text-xs" onClick={onClose}>
            Cancel
          </button>
        </div>
      </fieldset>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}

export function WirelessCompanyLinks({
  links,
  onCompany,
  total,
  truncated,
}: {
  links: WirelessCompanyLink[];
  onCompany: (id: string) => void;
  total?: number | undefined;
  truncated?: boolean | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  const candidate = (link: WirelessCompanyLink) =>
    ["candidate_business", "nearby_business_candidate"].includes(link.role);
  const nearby = links
    .filter(candidate)
    .sort((a, b) => (a.distance_m ?? Infinity) - (b.distance_m ?? Infinity));
  const visible = [
    ...links.filter((link) => !candidate(link)),
    ...(expanded ? nearby : nearby.slice(0, 3)),
  ];
  if (!links.length)
    return (
      <p className="text-sm text-muted-foreground">
        No company relationship supported by the imported evidence.
      </p>
    );
  return (
    <div>
      <ul className="space-y-3">
        {visible.map((link, index) => (
          <li
            key={`${link.company_id}:${link.role}:${index}`}
            className="min-w-0 border-l-2 border-border pl-3"
          >
            <button
              type="button"
              className="text-left text-sm font-medium text-primary hover:underline"
              onClick={() => onCompany(link.company_id)}
            >
              {link.company_name || link.company_id}
            </button>
            <div className="mt-1 flex flex-wrap gap-1.5">
              <Badge tone={link.role === "confirmed_operator" ? "ok" : ""}>
                {link.role === "confirmed_operator" && link.status === "rejected"
                  ? "Operator attribution rejected"
                  : (WIRELESS_ROLES[link.role] ?? link.role.replaceAll("_", " "))}
              </Badge>
              {link.role !== "confirmed_operator" &&
                (link.status === "rejected" || link.rejected_by_user) && (
                  <Badge tone="warn">Rejected company association</Badge>
                )}
              {typeof link.confidence === "number" && (
                <span className="text-xs text-muted-foreground">
                  {confidence(link.confidence)} evidence
                </span>
              )}
            </div>
            {link.evidence && (
              <p className="mt-1 break-words text-xs text-muted-foreground">
                {describe(link.evidence)}
              </p>
            )}
            {link.source_url && (
              <p className="mt-1 break-words text-xs">
                <ExtLink href={link.source_url}>Attribution source</ExtLink>
              </p>
            )}
            {link.facility_name && (
              <p className="mt-1 text-xs text-muted-foreground">
                Recorded facility: {link.facility_name}
              </p>
            )}
            {typeof link.distance_m === "number" && (
              <p className="mt-1 text-xs text-muted-foreground">
                {num(Math.round(link.distance_m))} m from recorded company location
              </p>
            )}
          </li>
        ))}
      </ul>
      {nearby.length > 3 && (
        <button
          type="button"
          className="sw-btn mt-3 text-xs"
          aria-expanded={expanded}
          onClick={() => setExpanded((value) => !value)}
        >
          {expanded
            ? "Show fewer nearby business candidates"
            : `Show ${num(nearby.length - 3)} more nearby business candidates`}
        </button>
      )}
      {truncated && (
        <p className="mt-3 text-xs text-warn">
          Showing {num(links.length)} of {num(total)} attribution records. Additional associations
          may be absent.
        </p>
      )}
    </div>
  );
}

export function WirelessDetail({
  id,
  gen,
  onCompany,
}: {
  id: string;
  gen: number;
  onCompany: (id: string) => void;
}) {
  const query = useQuery<WirelessDevice, ApiError>({
    queryKey: ["wireless-detail", gen, id],
    queryFn: ({ signal }) => api(`/api/wireless/devices/${encodeURIComponent(id)}`, { signal }),
    retry: false,
  });
  if (query.isPending)
    return (
      <p role="status" className="text-sm text-muted-foreground">
        Loading signal evidence…
      </p>
    );
  if (query.error)
    return (
      <div role="alert" className="text-sm text-destructive">
        {query.error.message}
        <button type="button" className="sw-btn ml-2" onClick={() => query.refetch()}>
          Retry
        </button>
      </div>
    );
  const d = query.data;
  const imported = d.metadata?.["imported_enrichment"] as
    { labels?: Record<string, unknown>; source_url?: string; version?: string } | undefined;
  return (
    <div className="space-y-5">
      <div>
        <h3 className="break-words text-lg font-semibold">{d.name || d.identifier}</h3>
        <p className="mt-1 break-all font-mono text-sm text-muted-foreground">{d.identifier}</p>
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
        <div>
          <dt className="text-xs text-muted-foreground">Radio type</dt>
          <dd>{RADIO_LABELS[d.type] ?? d.type}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Observations</dt>
          <dd>{num(d.observations)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Recorded RSSI</dt>
          <dd>{wirelessRssi(d.rssi)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">GPS accuracy</dt>
          <dd>{wirelessAccuracy(d.gps_accuracy)}</dd>
        </div>
        <div className="col-span-2">
          <dt className="text-xs text-muted-foreground">
            Earliest {wirelessTimeLabel(d.timestamp_timezone)}
          </dt>
          <dd>{wirelessTime(d.first_seen)}</dd>
        </div>
        <div className="col-span-2">
          <dt className="text-xs text-muted-foreground">
            Latest {wirelessTimeLabel(d.timestamp_timezone)}
          </dt>
          <dd>{wirelessTime(d.last_seen)}</dd>
        </div>
      </dl>
      <section aria-label="Related companies">
        <h4 className="mb-2 text-sm font-semibold">Related companies</h4>
        <WirelessCompanyLinks
          links={d.company_links ?? []}
          onCompany={onCompany}
          total={d.attribution?.total}
          truncated={d.attribution?.truncated}
        />
        <OperatorReview device={d} gen={gen} />
      </section>
      {imported?.labels && (
        <section aria-label="Imported source labels">
          <h4 className="text-sm font-semibold">Imported source labels · unverified</h4>
          <dl className="mt-2 grid min-w-0 grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-2 text-xs">
            {Object.entries(imported.labels)
              .filter(
                ([, value]) =>
                  value != null && value !== "" && !(Array.isArray(value) && !value.length),
              )
              .map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-muted-foreground">{key.replaceAll("_", " ")}</dt>
                  <dd className="min-w-0 break-words">{describe(value)}</dd>
                </div>
              ))}
          </dl>
          {imported.source_url && (
            <p className="mt-2 text-xs">
              <ExtLink href={imported.source_url}>Imported classification source</ExtLink>
            </p>
          )}
          {imported.version && (
            <p className="mt-1 break-all text-xs text-muted-foreground">
              Version: {imported.version}
            </p>
          )}
        </section>
      )}
      <section aria-label="Observed locations">
        <h4 className="text-sm font-semibold">Observed locations</h4>
        <p className="mt-1 text-xs text-muted-foreground">
          Coordinates describe scan observations and their GPS accuracy. They do not establish an
          exact device position or ownership.
        </p>
        {d.locations?.length ? (
          <div className="mt-3 max-h-64 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-card text-muted-foreground">
                <tr>
                  <th className="py-2 pr-3 font-medium">Latitude / longitude</th>
                  <th className="py-2 pr-3 font-medium">RSSI</th>
                  <th className="py-2 font-medium">GPS accuracy</th>
                </tr>
              </thead>
              <tbody>
                {d.locations.map((location, index) => (
                  <tr key={index} className="border-t border-border">
                    <td className="py-2 pr-3 font-mono">
                      {location.latitude.toFixed(6)}, {location.longitude.toFixed(6)}
                    </td>
                    <td className="py-2 pr-3">{wirelessRssi(location.rssi)}</td>
                    <td className="py-2">{wirelessAccuracy(location.gps_accuracy)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="mt-2 text-sm text-muted-foreground">No usable coordinates recorded.</p>
        )}
        {d.locations_truncated && (
          <p className="mt-2 text-xs text-warn">
            Showing a bounded sample of {num(d.locations_total)} observed locations.
          </p>
        )}
      </section>
      {d.provenance && (
        <section>
          <h4 className="text-sm font-semibold">Source and provenance</h4>
          <pre className="mt-2 max-h-48 overflow-auto rounded border border-border bg-background p-3 text-xs text-muted-foreground">
            {JSON.stringify(d.provenance, null, 2)}
          </pre>
        </section>
      )}
    </div>
  );
}
