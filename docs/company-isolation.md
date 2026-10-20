# Company identity and evidence isolation

SignalWatch resolves evidence to the existing canonical company ID. It keeps public source records separate from company attribution decisions, so changing a profile can correct derived fingerprints and alerts without rewriting the original evidence.

## Identity anchors

A company profile can record one unique primary domain, supporting evidence, and a source URL. Domains are normalized with IDNA, lowercase spelling, and removal of a trailing dot. Public suffixes, shared hosting suffixes, IP addresses, credentials, wildcard domains, and malformed hostnames cannot be primary domains. Public suffix checks use the packaged offline list rather than downloading a list during a scan.

These are operator-confirmed anchors. Saving an evidence note does not independently verify legal ownership. Existing official website evidence and explicit asset decisions remain available, and manual exclusions continue to apply.

Domain matching respects label boundaries and the most specific registered anchor: `api.acme.example.com` can match `acme.example.com`, while `acme.example.com.other.example.org` cannot. A separately anchored child organization takes precedence within its own namespace. Discovered subdomains can be associated with the profile without automatically entering its owned-asset risk calculation.

Verified ASN entries include an ASN number, evidence, and a source URL. They establish a recorded network affiliation. Sharing a cloud or hosting ASN never establishes ownership of every address on that network.

## Resolution funnel

1. Normalize the domain and locate an unambiguous primary-domain or existing asset association.
2. Check supplied company IDs and source context against that association. A conflicting ID cannot redirect evidence into a different company.
3. Normalize names and aliases for candidate matching. Legal suffixes and punctuation differences can produce candidates; a text mention alone cannot establish that the publishing company owns a domain or uses a product. Ambiguous names remain unresolved.
4. Persist the resolution status, method, reason, candidate IDs, and source URL alongside the source record. Only resolved evidence creates company-scoped technology projections.

Content hashes deduplicate within a company. Identical text belonging to different companies does not share a company-owned document. Projection integrity checks reject unknown company IDs and mismatched company/document/source/fingerprint combinations. Existing data is checked and reprojected during the versioned migration.

Company evidence queries include the organization ID, and company-focused graph traversal stops shared IP, vulnerability, and vendor nodes from pulling another company's evidence into the profile. Shared product nodes can still link to their vendor. Global infrastructure exploration remains available outside a company-focused graph.

## Evidence and risk

Technology relationships preserve the source and evidence classification: observed HTTP technology, asserted use, requirement, alternative, historical use, planned use, mention, CSP integration, or DNS verification. A DNS verification token records a verification artifact; it does not prove a current deployment or commercial contract. A job requirement does not prove deployment either.

Company risk continues to use included assets and existing reconciled alerts. Alias matches, shared vendors, shared IPs, and ASN affiliation do not create risk links by themselves.

## API

`POST /api/companies/profile` accepts the existing profile fields plus:

```json
{
  "primary_domain": "acme.example.com",
  "primary_domain_evidence": "Confirmed company website from the supplied source",
  "primary_domain_source_url": "https://acme.example.com/about",
  "verified_asns": [
    {
      "asn": 64496,
      "evidence": "Network affiliation recorded from the supplied source",
      "source_url": "https://acme.example.com/network"
    }
  ]
}
```

Omitting the new fields preserves existing anchors when an older client saves a profile. Explicit empty strings or an empty ASN list clear the corresponding anchors. Invalid updates roll back together.

`POST /api/companies/resolve` is an authenticated, read-only resolution check accepting optional `company_id`, `domain`, `name`, `asn`, `source_url`, and bounded `text`. It returns the resolution status and reasoning; it does not modify evidence or fetch the supplied URL.

Company detail responses include identity anchors and organization-scoped technology relationships and resolution decisions. The Lovable profile editor exposes anchors with provenance and presents unresolved candidates separately.

## Access boundary

This implements company data scoping within SignalWatch's existing authenticated workspace. It does not introduce separate customer accounts or PostgreSQL row-level security. Foreign keys and integrity triggers constrain relationships; authorization and organization-scoped queries control access. A true multi-user tenant boundary would require an account and permissions model in addition to these safeguards.
