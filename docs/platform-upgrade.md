# SignalWatch 0.20 platform upgrade

This release adds company evidence history, analyst review, collection progress,
workspace roles, and a PostgreSQL storage option to the existing SignalWatch API.
The Lovable dashboard uses `/api/capabilities` to discover the available features.

## Evidence and review

Company evidence has server-side filters, cursor pagination, and complete CSV
export. Cursors bind to the company, filters, and evidence revision; a changed
revision returns 409 so the dashboard can restart from the first page. Export
reads a single database snapshot and escapes spreadsheet formula prefixes.

Published, checked, and observed times have different meanings. An HTTP 304 can
advance the source check time without claiming a fresh observation. Technology
transitions compare successful captures of the same source. Partial, failed, or
older captures cannot establish that a product disappeared. A transition means
the source changed, not that a company necessarily removed a deployed product.
Migration language remains classified as planned or reported.

Warning review states are open, investigating, not applicable, accepted risk,
and remediated. Each save requires a reason and records the actor and revision.
Existing reviews require the revision from the most recent read. Reviews and
history survive reconciliation and warning removal; collection never changes
an analyst decision to remediated. Historical decisions remain readable after a
warning disappears, but updates require an active warning in the selected
company's current scope.

Attribution previews run the actual profile or asset projection inside a
transaction that rolls back. They do not queue scans or save decisions. Counts
that reach existing graph/detail limits carry a warning. A later save applies
to the current data, so a preview is an estimate, not a reserved transaction.

## Workspace access

The configured master bearer token remains an administrator credential. Admins
can create named viewer, editor, or administrator credentials. Tokens are shown
once, stored only as SHA-256 hashes, and revoked immediately. Editors can manage
company evidence and reviews; workspace credential and source-settings changes
require an administrator. Viewers can use reads, resolution, and previews.

An installation without authentication allows local bootstrap until its first
credential is created. That first credential must be an administrator. Anonymous
access cannot return merely by revoking credentials, and the last administrator
cannot be revoked when no master token is configured.

These are roles within a single workspace. Company attribution is an evidence
boundary, not separate customer authorization or PostgreSQL row-level security.
The audit endpoint is administrator-only and does not record token secrets or
raw mutation request bodies.

## PostgreSQL activation

Install the `postgres` extra or the pinned deployment requirements. Keep the
original SQLite path in `config.json` and supply `SIGNALWATCH_DATABASE_URL` as
a secret environment variable. Setting `SIGNALWATCH_MIGRATE_SQLITE=true` makes
the runtime verify and migrate the SQLite snapshot before starting the API,
worker, or scheduler. A failed migration prevents activation. Standalone CLI
and API commands should run only after the explicit migration command succeeds.

Migration copies native relational tables, preserves identifiers and cursor
positions, verifies row counts and logical content digests, repairs sequences,
and commits a completion manifest atomically. It refuses a populated unrelated
target. A restart with the same source returns the completed manifest without
replacing live PostgreSQL data. The original SQLite file remains unchanged.
See the recovery runbook for backups, restore checks, and rollback constraints.

The PostgreSQL adapter supplies indexed text search and transaction/advisory
locks for the existing SQL contract. Writers remain serialized while the
application retains its current read/modify/write behavior. Raw staging payloads
live in the database; large wireless import archives remain on the persistent
service disk. Keep API and workers together until archives are available to all
worker hosts. PostgreSQL alone does not make the archive filesystem shared.

## Investigation and applicability

Graph expansion retains the original root and its company evidence fence. The
selected node must be reachable within the bounded root graph (five hops,
300 nodes, 800 edges). Shared vendor/product labels do not grant access to
another company's branch. Dashboard saved views store graph settings and
pinned IDs locally, keyed to the backend URL; they never store API credentials.

NVD configuration evaluation uses true/false/unknown logic for supported CPE
conditions. Missing environmental evidence stays unknown. Supporting and
contradicting observations explain a warning, and repeated source copies do
not count as independent corroboration. These are potential applicability
assessments, not confirmation that a deployment is exploitable.
