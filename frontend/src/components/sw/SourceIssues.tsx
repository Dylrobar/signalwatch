import { sourceIssues } from "@/lib/sources";
import { fmtDate } from "@/lib/format";

export function SourceIssues({ errors, retryAt }: { errors: string[]; retryAt?: unknown }) {
  const issues = sourceIssues(errors);
  const retry = typeof retryAt === "string" && Date.parse(retryAt) > Date.now() ? retryAt : null;
  if (!issues.details.length && !retry) return null;
  return (
    <div className="mt-1 w-64 min-w-0 max-w-full text-xs [overflow-wrap:anywhere]">
      {issues.summary && <p className="text-destructive">{issues.summary}</p>}
      {retry && <p className="mt-1 text-muted-foreground">Retry after {fmtDate(retry, true)}</p>}
      {issues.details.length > 0 && <details className="mt-1">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Issue details</summary>
        <div className="mt-2 max-h-48 overflow-y-auto rounded border border-border bg-background p-2" tabIndex={0} role="region" aria-label="Collector issue details">
          <ul className="space-y-2 text-muted-foreground">
            {issues.details.map((detail) => <li key={detail}>{detail}</li>)}
          </ul>
          {issues.omitted > 0 && <p className="mt-2 text-muted-foreground">{issues.omitted} more messages omitted.</p>}
        </div>
      </details>}
    </div>
  );
}
