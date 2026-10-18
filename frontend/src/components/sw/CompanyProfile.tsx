import {
  cloneElement,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type ReactElement,
} from "react";
import { api, ApiError } from "@/lib/api";
import {
  ASSET_ROLE,
  ASSET_STATUS,
  companyAssetUrl,
  splitNames,
  type CompanyAsset,
  type CompanyIdentity,
  type CompanyProfile as Profile,
} from "@/lib/companies";
import { confidence, fmtDate, humanize, num, type R } from "@/lib/format";
import { Badge, ExtLink } from "./bits";

type Saved = (detail: R) => void;
type Go = (id: unknown) => void;

function useCompanySave(onSaved: Saved) {
  const ctrl = useRef<AbortController | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => () => ctrl.current?.abort(), []);
  async function save(path: string, body: unknown) {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    setBusy(true);
    setError("");
    try {
      const detail = await api<R>(path, { method: "POST", body, signal: c.signal });
      if (c.signal.aborted) return false;
      onSaved(detail);
      return true;
    } catch (e) {
      if (!c.signal.aborted && (e as ApiError).kind !== "aborted") setError((e as Error).message);
      return false;
    } finally {
      if (!c.signal.aborted) setBusy(false);
    }
  }
  return { save, busy, error };
}

function Field({ label, children }: { label: string; children: ReactElement<{ id?: string }> }) {
  const id = useId();
  return (
    <div className="min-w-0 space-y-1 text-xs text-muted-foreground">
      <label htmlFor={id}>{label}</label>
      {cloneElement(children, { id })}
    </div>
  );
}

function ParentCompanyPicker({
  value,
  name,
  excludeId,
  onChange,
}: {
  value: string;
  name?: string | undefined;
  excludeId?: string | undefined;
  onChange: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [selectedName, setSelectedName] = useState(name || value);
  const [items, setItems] = useState<R[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!open) return;
    const c = new AbortController();
    setLoading(true);
    setError("");
    const timer = setTimeout(() => {
      api<{ items: R[] }>("/api/search", {
        params: { q, kind: "company", limit: "25" },
        signal: c.signal,
      })
        .then((result) => {
          if (!c.signal.aborted) setItems(result.items.filter((item) => item["id"] !== excludeId));
        })
        .catch((e: ApiError) => {
          if (!c.signal.aborted && e.kind !== "aborted") setError(e.message);
        })
        .finally(() => {
          if (!c.signal.aborted) setLoading(false);
        });
    }, 200);
    return () => {
      clearTimeout(timer);
      c.abort();
    };
  }, [open, q, excludeId]);
  return (
    <div className="space-y-2 text-xs">
      <div className="text-muted-foreground">Parent company</div>
      <div className="flex flex-wrap items-center gap-2">
        <span>{value ? selectedName : "None recorded"}</span>
        <button type="button" className="sw-btn text-xs" onClick={() => setOpen((v) => !v)}>
          {open ? "Close search" : "Choose parent company"}
        </button>
        {value && (
          <button
            type="button"
            className="sw-btn text-xs"
            onClick={() => {
              onChange("");
              setSelectedName("");
            }}
          >
            Clear parent
          </button>
        )}
      </div>
      {open && (
        <div className="space-y-2 rounded border border-border p-2">
          <input
            type="search"
            className="sw-input"
            aria-label="Search parent companies"
            placeholder="Search existing companies"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          {loading ? (
            <p role="status" className="text-muted-foreground">
              Finding companies…
            </p>
          ) : error ? (
            <p role="alert" className="text-destructive">
              {error}
            </p>
          ) : (
            <ul className="max-h-40 space-y-1 overflow-y-auto">
              {items.map((item) => (
                <li key={item["id"]}>
                  <button
                    type="button"
                    className="sw-btn w-full justify-start text-left text-xs"
                    onClick={() => {
                      onChange(String(item["id"]));
                      setSelectedName(String(item["name"] || item["id"]));
                      setOpen(false);
                    }}
                  >
                    {item["name"] || item["id"]}
                  </button>
                </li>
              ))}
              {!items.length && (
                <li className="text-muted-foreground">
                  No matching companies. Create the parent profile first.
                </li>
              )}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

export function CompanyIdentityForm({
  profile,
  onSaved,
  onCancel,
}: {
  profile?: Profile;
  onSaved: Saved;
  onCancel?: () => void;
}) {
  const [form, setForm] = useState({
    name: profile?.name ?? "",
    legal_name: profile?.legal_name ?? "",
    aliases: profile?.aliases.join("\n") ?? "",
    brands: profile?.brands.join("\n") ?? "",
    parent_company_id: profile?.parent_company_id ?? "",
    notes: profile?.notes ?? "",
    source_url: profile?.source_url ?? "",
  });
  const { save, busy, error } = useCompanySave(onSaved);
  const field = (key: keyof typeof form) => ({
    value: form[key],
    onChange: (e: { target: { value: string } }) =>
      setForm((f) => ({ ...f, [key]: e.target.value })),
  });
  async function submit(e: FormEvent) {
    e.preventDefault();
    const body: CompanyIdentity & { company_id?: string } = {
      ...form,
      aliases: splitNames(form.aliases),
      brands: splitNames(form.brands),
    };
    if (profile) body.company_id = profile.company_id;
    await save("/api/companies/profile", body);
  }
  return (
    <form
      onSubmit={submit}
      className="space-y-3"
      aria-label={profile ? "Edit company profile" : "Add company"}
    >
      <h2 className="text-lg font-semibold">{profile ? "Edit company profile" : "Add company"}</h2>
      <p className="text-xs text-muted-foreground">
        Record company identity and a supporting source. Names and brands do not automatically
        assign asset ownership.
      </p>
      <fieldset disabled={busy} className="grid min-w-0 gap-3">
        <Field label="Company name">
          <input className="sw-input" required maxLength={200} {...field("name")} />
        </Field>
        <Field label="Legal name">
          <input className="sw-input" maxLength={300} {...field("legal_name")} />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Other names · one per line">
            <textarea className="sw-input min-h-20" {...field("aliases")} />
          </Field>
          <Field label="Brands · one per line">
            <textarea className="sw-input min-h-20" {...field("brands")} />
          </Field>
        </div>
        <ParentCompanyPicker
          value={form.parent_company_id}
          name={profile?.parent_company?.name}
          excludeId={profile?.company_id}
          onChange={(id) => setForm((f) => ({ ...f, parent_company_id: id }))}
        />
        <Field label="Supporting source URL">
          <input
            className="sw-input"
            type="url"
            maxLength={2000}
            placeholder="https://"
            {...field("source_url")}
          />
        </Field>
        <Field label="Notes">
          <textarea className="sw-input min-h-20" maxLength={10000} {...field("notes")} />
        </Field>
        <div className="flex flex-wrap gap-2">
          <button type="submit" className="sw-btn-primary">
            {busy ? "Saving…" : profile ? "Save profile" : "Create company"}
          </button>
          {onCancel && (
            <button type="button" className="sw-btn" onClick={onCancel}>
              Cancel
            </button>
          )}
        </div>
      </fieldset>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        {profile
          ? "Profile edits are retained when collectors refresh."
          : "Add asset relationships after saving the profile."}
      </p>
    </form>
  );
}

function AssetDecision({
  companyId,
  asset,
  onSaved,
  onCancel,
}: {
  companyId: string;
  asset?: CompanyAsset;
  onSaved: Saved;
  onCancel: () => void;
}) {
  const [assetUrl, setAssetUrl] = useState(asset ? companyAssetUrl(asset) : "");
  const [status, setStatus] = useState<"confirmed" | "candidate" | "rejected">(
    asset?.status === "rejected" || asset?.status === "candidate" ? asset.status : "confirmed",
  );
  const [role, setRole] = useState<"owned" | "service">(
    asset?.role === "service" ? "service" : "owned",
  );
  const [evidence, setEvidence] = useState("");
  const [sourceUrl, setSourceUrl] = useState("");
  const { save, busy, error } = useCompanySave(onSaved);
  async function submit(e: FormEvent) {
    e.preventDefault();
    await save("/api/companies/assets", {
      company_id: companyId,
      asset_url: assetUrl,
      status,
      role,
      evidence,
      source_url: sourceUrl,
    });
  }
  return (
    <form
      onSubmit={submit}
      aria-label={asset ? `Review ${asset.name}` : "Add company asset"}
      className="mt-3 space-y-3 rounded border border-border bg-background/40 p-3"
    >
      <h4 className="font-semibold">{asset ? "Review relationship" : "Add asset relationship"}</h4>
      <fieldset disabled={busy} className="grid min-w-0 gap-3">
        <Field label="Asset hostname or URL">
          <input
            className="sw-input"
            required
            readOnly={Boolean(asset)}
            value={assetUrl}
            onChange={(e) => setAssetUrl(e.target.value)}
            placeholder="company.example"
          />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Decision">
            <select
              className="sw-input"
              value={status}
              onChange={(e) => setStatus(e.target.value as typeof status)}
            >
              <option value="confirmed">Confirmed</option>
              <option value="candidate">Candidate · needs review</option>
              <option value="rejected">Rejected</option>
            </select>
          </Field>
          <Field label="Relationship">
            <select
              className="sw-input"
              value={role}
              onChange={(e) => setRole(e.target.value as typeof role)}
            >
              <option value="owned">Company asset</option>
              <option value="service">Third-party service</option>
            </select>
          </Field>
        </div>
        <p className="text-xs text-muted-foreground">
          Confirmed company assets are included in this company’s evidence and queued for
          collection. Candidates, rejected assets, and third-party services stay outside that
          rollup.
        </p>
        <Field label="Evidence for this decision">
          <textarea
            required
            className="sw-input min-h-20"
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            maxLength={4000}
          />
        </Field>
        <Field label="Supporting source URL">
          <input
            required
            type="url"
            className="sw-input"
            value={sourceUrl}
            onChange={(e) => setSourceUrl(e.target.value)}
            placeholder="https://"
          />
        </Field>
        <div className="flex flex-wrap gap-2">
          <button type="submit" className="sw-btn-primary">
            {busy ? "Saving…" : "Save relationship"}
          </button>
          <button type="button" className="sw-btn" onClick={onCancel}>
            Cancel
          </button>
          {asset && (
            <button
              type="button"
              className="sw-btn"
              onClick={() =>
                save("/api/companies/assets", {
                  company_id: companyId,
                  asset_url: companyAssetUrl(asset),
                  status: "automatic",
                  role: "owned",
                  evidence: "",
                  source_url: "",
                })
              }
            >
              Reset to automatic
            </button>
          )}
        </div>
      </fieldset>
      <p className="text-xs text-muted-foreground">
        Reset removes the saved decision and uses collected evidence. An asset without automatic
        evidence may disappear from this profile.
      </p>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}

function AssetCard({ asset, go, review }: { asset: CompanyAsset; go: Go; review: () => void }) {
  return (
    <div className="min-w-0 rounded border border-border p-3">
      <div className="flex flex-wrap items-start gap-2">
        <button
          type="button"
          className="min-w-0 text-left font-mono text-sm text-primary underline-offset-2 hover:underline [overflow-wrap:anywhere]"
          onClick={() => go(asset.id)}
        >
          {asset.name}
        </button>
        <Badge
          tone={asset.status === "rejected" ? "kev" : asset.status === "candidate" ? "warn" : "ok"}
        >
          {ASSET_STATUS[asset.status]}
        </Badge>
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        {ASSET_ROLE[asset.role]} ·{" "}
        {asset.included ? "Included in company rollup" : "Excluded from company rollup"}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        {num(asset.observation_count)} observations · {num(asset.warning_count)} warnings ·{" "}
        {confidence(asset.confidence)} evidence confidence
      </div>
      {asset.reasons?.length > 0 && (
        <ul className="mt-2 list-inside list-disc space-y-1 text-xs">
          {asset.reasons.map((reason, i) => (
            <li key={i}>{reason}</li>
          ))}
        </ul>
      )}
      {asset.evidence?.length > 0 && (
        <details className="mt-2 text-xs">
          <summary className="cursor-pointer text-muted-foreground">
            Relationship evidence ({num(asset.evidence.length)})
          </summary>
          <ul className="mt-2 space-y-2 border-l border-border pl-3">
            {asset.evidence.map((item, i) => (
              <li key={i} className="min-w-0">
                <div>
                  {humanize(item.relation)} · {confidence(item.confidence)} ·{" "}
                  {fmtDate(item.observed_at, true)}
                </div>
                <div className="font-mono text-[11px] text-muted-foreground">
                  {item.from_id} → {item.to_id}
                </div>
                {item.evidence && <p className="mt-0.5">Saved review: {item.evidence}</p>}
                {item.source_url && <ExtLink href={item.source_url} />}
              </li>
            ))}
          </ul>
        </details>
      )}
      <button
        type="button"
        className="sw-btn mt-3 text-xs"
        onClick={review}
        aria-label={`Review relationship for ${asset.name}`}
      >
        Review relationship
      </button>
    </div>
  );
}

export function CompanyProfile({
  profile,
  onSaved,
  go,
}: {
  profile: Profile;
  onSaved: Saved;
  go: Go;
}) {
  const [editing, setEditing] = useState(false);
  const [review, setReview] = useState<CompanyAsset | "new" | null>(null);
  const saved: Saved = (detail) => {
    setEditing(false);
    setReview(null);
    onSaved(detail);
  };
  return (
    <section className="mt-4 min-w-0" aria-label="Company profile">
      {editing ? (
        <CompanyIdentityForm
          key={profile.company_id}
          profile={profile}
          onSaved={saved}
          onCancel={() => setEditing(false)}
        />
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3>Company profile</h3>
            <button
              type="button"
              className="sw-btn text-xs"
              onClick={() => {
                setReview(null);
                setEditing(true);
              }}
            >
              Edit profile
            </button>
          </div>
          <dl className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-2 text-xs">
            <dt className="text-muted-foreground">Legal name</dt>
            <dd>{profile.legal_name || "Not recorded"}</dd>
            <dt className="text-muted-foreground">Other names</dt>
            <dd>{profile.aliases?.join(" · ") || "None recorded"}</dd>
            <dt className="text-muted-foreground">Brands</dt>
            <dd>{profile.brands?.join(" · ") || "None recorded"}</dd>
            <dt className="text-muted-foreground">Parent company</dt>
            <dd>
              {profile.parent_company ? (
                <button
                  type="button"
                  className="text-primary hover:underline"
                  onClick={() => go(profile.parent_company!.id)}
                >
                  {profile.parent_company.name}
                </button>
              ) : (
                "None recorded"
              )}
            </dd>
            <dt className="text-muted-foreground">Subsidiaries</dt>
            <dd className="space-y-1">
              {profile.subsidiaries?.length
                ? profile.subsidiaries.map((company) => (
                    <div key={company.id}>
                      <button
                        type="button"
                        className="text-primary hover:underline"
                        onClick={() => go(company.id)}
                      >
                        {company.name}
                      </button>
                    </div>
                  ))
                : "None recorded"}
            </dd>
            <dt className="text-muted-foreground">Supporting source</dt>
            <dd>{profile.source_url ? <ExtLink href={profile.source_url} /> : "Not recorded"}</dd>
            <dt className="text-muted-foreground">Profile updated</dt>
            <dd>{fmtDate(profile.updated_at, true, "Not edited")}</dd>
          </dl>
          {profile.notes && <p className="mt-3 whitespace-pre-wrap text-sm">{profile.notes}</p>}
        </>
      )}
      <div className="mt-5 flex flex-wrap items-center justify-between gap-2">
        <h3>Company assets ({num(profile.assets?.length ?? 0)})</h3>
        <button
          type="button"
          className="sw-btn text-xs"
          onClick={() => {
            setEditing(false);
            setReview("new");
          }}
        >
          Add asset
        </button>
      </div>
      <p className="mb-3 text-xs text-muted-foreground">
        Official websites, canonical website redirects, and confirmed company assets contribute
        observations and warnings below. Other redirects need review. Hosting and service
        relationships do not establish ownership.
      </p>
      {!profile.assets?.length && (
        <p className="text-sm text-muted-foreground">No asset relationships recorded.</p>
      )}
      <ul className="space-y-3">
        {profile.assets?.map((asset) => (
          <li key={asset.id} className="min-w-0">
            <AssetCard
              asset={asset}
              go={go}
              review={() => {
                setEditing(false);
                setReview(asset);
              }}
            />
            {review !== "new" && review?.id === asset.id && (
              <AssetDecision
                key={asset.id}
                companyId={profile.company_id}
                asset={asset}
                onSaved={saved}
                onCancel={() => setReview(null)}
              />
            )}
          </li>
        ))}
      </ul>
      {profile.assets_truncated && (
        <p className="mt-3 text-xs text-warn">
          This profile reached a relationship or evidence limit. Additional associations may be
          absent from this view.
        </p>
      )}
      {review === "new" && (
        <AssetDecision
          key="new"
          companyId={profile.company_id}
          onSaved={saved}
          onCancel={() => setReview(null)}
        />
      )}
    </section>
  );
}
