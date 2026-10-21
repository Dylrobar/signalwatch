# Evidence-based correlation and bounded intelligence reads (0.21.0)

## Correlation changes

- `Store._reconcile_asset` requires a concrete vendor/ecosystem and product and
  `exact` or `affected_range` version evidence before opening a warning.
- Every `technographic:*` observation remains inventory context, including ATS
  assertions with explicit versions. It cannot establish a deployment or open a
  company-level warning. Generic mentions and requirements remain fingerprints.
- A shorter numeric version is not zero-padded into a longer affected bound.
  Unsupported native version comparators and distribution revisions remain
  unverified. They are not silently classified as unaffected.
- Existing CPE AND/OR platform checks and ecosystem-aware PURL matching remain.
  Configuration uncertainty cannot itself establish runtime reachability.
- CT descendants remain ownership candidates. Shared IP, ASN, DNS, CDN and vendor
  edges do not propagate company risk. Confirmed service dependencies stay out of
  owned-asset risk. Official-site evidence can surface a candidate, but does not
  qualify for the confirmed-owned priority tier.
- API warning and company-risk reads exclude legacy unknown-version/company-root
  warnings immediately. Full reconciliation removes their persisted projections;
  observations, source documents and review history remain available.

## Priority model

Priority is a triage ordering, not an exploitation probability:

| Evidence tier | Score band |
| --- | --- |
| Analyst-confirmed exposure on explicitly confirmed owned asset | 85–100 |
| Affected-version candidate on explicitly confirmed owned asset | 50–79 |
| Affected-version candidate without confirmed ownership | 20–49 |
| Inventory context (no warning generated) | 0–19 |

Within each band: base + CVSS (0–10) + KEV (8) + EPSS × 6, capped at
that band's ceiling. A KEV listing alone never invokes an 85-point floor.
Linked reporting stays searchable evidence and adds zero points. Removing its
per-alert COUNT DISTINCT query also removes an expensive polling amplification.
Company shortlists order verification and ownership before CVE signals, then
apply the same tier model; bounded/truncated coverage remains explicit.
Company graph alert nodes use the same company-scoped verification.

`risk.why_this_matters` and `risk.remediation` accompany company warnings. Known
PHP CVE-2025-14180 branch fixes cite the PHP security advisory. Arbitrary version
range endpoints are not assumed to be fixed releases. When no trusted fix is
available the response explicitly leaves `fixed_version` null; an analyst can
record exact remediation with verification evidence.

## Recording verification

Use the company warning's Analyst review form, select **Exposure verification
recorded**, and supply the installed version, evidence URL, runtime/package
attestation, exact remediation and an expiry within 30 days. This records an
analyst attestation; it does not run exploitation or DoS probes.

The equivalent authenticated `POST /api/reviews` body is:

```json
{
  "subject_id": "alert:<existing warning id>",
  "company_id": "company:<existing company id>",
  "state": "confirmed_exposure",
  "reason": "Authenticated package and runtime evidence reviewed",
  "expected_revision": 0,
  "verification": {
    "observed_version": "1.0",
    "evidence_url": "https://your-evidence-system.example/review/123",
    "runtime_verified": true,
    "package_affected": true,
    "expires_at": "<future ISO timestamp within 30 days>",
    "remediation": "<exact package update or mitigation from the reviewed advisory>"
  }
}
```

The backend rejects missing evidence, a mismatching version, unconfirmed
ownership, conflicting evidence and incompatible configurations. Editor/admin
roles and optimistic review revisions apply. Verification is company/asset/CVE
scoped, version/source/alert-instance bound, expires, and is revoked by changing review state.
Ownership changes remove its ranking immediately. Historical reviews are retained;
a historical confirmation is not a current risk determination.

## Render performance controls

- Graph, company-risk and intelligence HTTP reads share at most two expensive
  computations per API process. Identical in-flight reads coalesce. Excess work
  returns JSON 503 with Retry-After: 3, rather than creating an unbounded backlog.
- Response snapshots last three seconds and consume at most 4 MiB/16 entries.
  API mutations invalidate snapshots and prevent older in-flight work from
  repopulating them. Worker changes may take up to three seconds to appear.
- Read connections have a ten-second budget checked between statements; SQLite
  VM progress interrupts long statements, and PostgreSQL has a ten-second
  statement timeout. A PostgreSQL statement started near the deadline may finish
  up to one additional statement timeout later. Timeouts produce retryable 503s.
  Collection/write transactions do not inherit these polling deadlines.
- Staging claims select only an ID before fetching one payload, reducing duplicate
  payload copies. Lease reclamation is indexed and capped at 100 rows per claim.
- Collection drains yield between batches of 25 and stop after a 30-second soft
  budget checked between batches. An individual batch may exceed that time.
  Remaining records stay durable for subsequent drains; no records are discarded.
- Existing queue fencing, one prefork worker, prefetch=1, worker recycling, 8-MiB
  staging payload bounds, streamed matching candidates and per-asset commits remain.
  These are resource bounds, not a promise that arbitrary workloads cannot OOM.

No PostgreSQL/SQLite migration or database switch is required. The verification
schema is additive. `SIGNALWATCH_MIGRATE_SQLITE` must remain false in production.
