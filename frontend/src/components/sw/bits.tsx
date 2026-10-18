import type { ReactNode } from "react";
import { percent, present, safeHref, severityLabel, type R } from "@/lib/format";
import { EVENT_KINDS } from "@/lib/views";

export function Badge({ tone = "", children }: { tone?: string; children: ReactNode }) {
  return <span className={`sw-badge ${tone ? `sw-badge-${tone}` : ""}`}>{children}</span>;
}

export function Severity({ value }: { value: unknown }) {
  const s = severityLabel(value);
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

export function Signals({ item }: { item: R }) {
  const kev = item["kev"] === true || item["kev"] === 1;
  const hasEpss = present(item["epss"]);
  if (!kev && !hasEpss) return <span className="text-muted-foreground">none</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {kev && <Badge tone="kev">KNOWN EXPLOITED</Badge>}
      {hasEpss && <Badge>EPSS {percent(item["epss"])}</Badge>}
    </div>
  );
}

export function EventBadge({ kind }: { kind: unknown }) {
  const k = String(kind ?? "");
  const tone = k === "kev_added" || k === "warning_opened" ? "warn" : k === "warning_resolved" ? "ok" : "";
  return <Badge tone={tone}>{EVENT_KINDS[k] ?? (k ? k.replaceAll("_", " ") : "unknown")}</Badge>;
}

export function ExtLink({ href, children }: { href: unknown; children?: ReactNode }) {
  const url = safeHref(href);
  if (!url) return <span className="break-all">{children ?? String(href ?? "")}</span>;
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" className="break-all underline-offset-2 hover:underline">
      {children ?? url}
    </a>
  );
}

export function Notice({ tone = "", title, children }: { tone?: "" | "warn" | "danger"; title: string; children?: ReactNode }) {
  const border = tone === "danger" ? "border-destructive/50" : tone === "warn" ? "border-warn/50" : "border-border";
  const color = tone === "danger" ? "text-destructive" : tone === "warn" ? "text-warn" : "text-foreground";
  return (
    <div role={tone ? "alert" : "status"} className={`rounded-md border ${border} bg-background/40 p-4`}>
      <div className={`text-sm font-semibold ${color}`}>{title}</div>
      {children && <div className="mt-1 text-sm text-muted-foreground">{children}</div>}
    </div>
  );
}
