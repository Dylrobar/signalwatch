export type CompanyEvidence = {
  from_id: string;
  to_id: string;
  relation: string;
  source_url: string;
  observed_at: string;
  confidence: number;
  evidence?: string;
};

export type CompanyAsset = {
  id: string;
  name: string;
  status: "official" | "redirect" | "confirmed" | "candidate" | "rejected";
  role: "website" | "owned" | "service";
  included: boolean;
  confidence: number;
  reasons: string[];
  evidence: CompanyEvidence[];
  observation_count: number;
  warning_count: number;
};

export type CompanyProfile = {
  company_id: string;
  name: string;
  legal_name: string;
  aliases: string[];
  brands: string[];
  parent_company_id: string;
  parent_company: { id: string; name: string } | null;
  subsidiaries: { id: string; name: string }[];
  notes: string;
  source_url: string;
  updated_at: string;
  assets: CompanyAsset[];
  assets_truncated: boolean;
};

export type CompanyIdentity = Pick<
  CompanyProfile,
  "name" | "legal_name" | "aliases" | "brands" | "parent_company_id" | "notes" | "source_url"
>;

export function splitNames(value: string) {
  return [
    ...new Set(
      value
        .split("\n")
        .map((name) => name.trim())
        .filter(Boolean),
    ),
  ];
}

export const ASSET_STATUS: Record<CompanyAsset["status"], string> = {
  official: "Official website",
  redirect: "Redirect",
  confirmed: "Confirmed",
  candidate: "Candidate",
  rejected: "Rejected",
};

export const ASSET_ROLE: Record<CompanyAsset["role"], string> = {
  website: "Website association",
  owned: "Company asset",
  service: "Third-party service",
};

export function companyAssetUrl(asset: Pick<CompanyAsset, "id" | "name">) {
  const value = asset.id.startsWith("domain:") ? asset.id.slice(7) : asset.name;
  return value.includes(":") && !value.includes("://")
    ? `https://[${value.replace(/^\[|\]$/g, "")}]/`
    : value;
}
