# Beta and pre-release notes

The `prerelease` source family polls every 60 minutes and is enabled by default. It uses the existing public HTTP cache, ingestion queue, SQLite graph, and authenticated API. Existing explicit operator disables and intervals are preserved when configuration is loaded.

The three public providers are `windows_insider`, `apple_developer`, and `mikrotik_testing`. No provider credentials are required. Windows Insider's official RSS contains both complete posts and announcements linking to public Microsoft Learn build notes; linked notes are fetched individually and retain their own channel and build. Apple's official developer release feed is followed through its public documentation redirect to the DocC JSON release note. RouterOS's official testing and development RSS includes complete changelogs; firmware binaries and download links are never fetched.

A provider reads at most 30 feed entries and stages at most four release notes per cycle. Microsoft's large official feed has a 4 MiB response allowance; other feeds and notes have a 2 MiB allowance. A persisted rotating note cursor prevents the first four announcements from permanently starving other recent notes. HTTP cache validators recheck previously seen notes, including a changed note whose announcement GUID remains unchanged. HTML note access checks vendor robots.txt; direct vendor-published RSS and documentation JSON are consumed as structured feeds. Fetch errors retain previously ingested notes and expose an error or partial provider status with a retry cooldown.

Raw feeds and fetched/extracted note payloads enter the existing queue as `public_source` envelopes. `payload_source_url` records where the note bytes originated when a canonical changelog URL differs from its syndicated RSS source. Unchanged payload/context combinations are deduplicated by the queue. Failed and dead envelopes retain the existing retry/dead-letter lifecycle.

Each `prerelease` node is identified by provider, official note URL, announced version/build, and stage. Its current metadata replaces the prior components and CVEs when a correction arrives; its first-seen timestamp is preserved. Content changes create immutable `prerelease_revision` nodes, each with its own quoted `component_change` nodes. A release's `current_revision_id` identifies its latest snapshot; historical revision edges remain available explicitly. Displayed component quotations are capped at 48, with security-related quotations prioritized, and clipping is exposed in per-note `coverage`. No file changes are inferred when a vendor does not name the file. Component classifications are `resolved`, `known_issue`, `changed`, or `mentioned`; negative or future fix statements are not classified as resolved.

Apple reuses documentation URLs across successive betas. A collected DocC overview must explicitly identify the announcement's beta/RC version. If it describes another beta or has become a final release note, that announcement is reported as incomplete rather than attaching the current document to the old beta. Public Apple documentation snapshots are not a historical archive of each beta's original notes.

These records are `unverified_prerelease_signal` evidence. Security relevance is a keyword/CVE signal, not confirmation of a vulnerability, exploit, installed version, fix availability, or affected company. The normalizer emits no installed observations, advisories, KEV entries, or exposure alerts.

## API

`GET /api/prereleases?q=&vendor=&stage=&security_only=false&limit=25&offset=0`

The existing bearer authentication applies. `q` is limited to 300 characters, `vendor` to 100; `stage` is empty or `beta`, `rc`, `dev`, `canary`, `release_preview`, or `preview`. `limit` is 1–100 and `offset` is 0–10000. Vendor matching is case-insensitive. `%` and `_` in a query are treated literally.

The response contains `items`, exact filtered `total`, and `coverage`. Each item includes `id`, `name`, `vendor`, `product`, `version`, `stage`, `source_url`, `published`, `observed_at`, `first_seen`, `security_relevant`, `components` (`name`, `kind`, `quote`), `cves`, `content_hash`, `current_revision_id`, `build`, `announcement_url`, `status`, and per-note `coverage`. Existing `/api/entity?id=…` and `/api/graph?root_id=…` provide detail and graph context.

Provider health is available through the existing source catalog and source status endpoints. Collection success means public notes were staged or unchanged; queue processing remains a separate visible step.
