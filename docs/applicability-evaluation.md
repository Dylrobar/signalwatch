# Exposure applicability and extraction evaluation

Potential exposure warnings retain the strongest original observation and its
confidence. `alerts.assessment` adds the reasons behind the decision and linked
supporting/contradicting evidence. Startup adds this JSON-text column to existing
databases automatically. Existing alert IDs and primary source links are preserved.

## Configuration evaluation

NVD configuration trees use three-valued `true`, `false`, and `unknown` logic for
AND, OR, and negation. A `vulnerable: false` CPE leaf is an environmental
prerequisite, such as Windows; it is not a negation. Observations must belong to
the same asset to satisfy a prerequisite. Company membership does not permit one
host's operating system to satisfy another host's requirement.
Company-level text also cannot establish co-location of two products, even when
both assertions are attached to the same organization; its environment stays
unknown until host-level observations are available.

Missing products, unsupported version order, unspecified CPE attributes, malformed
trees, and work-limit exhaustion retain an `unknown` potential warning. An
observed Linux product alone cannot prove that Windows is absent. Explicit
same-product versions/attributes outside a supported prerequisite can make a
configuration false; those matches are suppressed. OR branches concerning a
different vulnerable product cannot satisfy the current product's configuration.
The evaluator supports NVD `nodes`/`cpeMatch` and older `children`/`cpe_match` forms,
with a 512-node, 20-level budget and at most 40 displayed conditions.

`true` means the published conditions match available same-asset observations.
All warnings remain **potential**: public text, an HTTP header, or an inventory
entry does not prove exploitability or complete deployment context.

## Corroboration

The assessment exposes `supporting`, `contradicting`, `independent_sources`,
`confidence_factors`, and `truncated` under `evidence`. Each retained entry links
its source, snippet, observation time, version, and evidence class. Supporting
and contradicting lists each display at most 20 entries. Different affected-range
alternatives for one observation cannot create a contradiction when one matches.

Syndicated text shares its organization-scoped document content hash and counts
once. HTTP observations from the same origin also count once. This count is an
explainable source-diversity heuristic, not statistically calibrated independence.
It never inflates the original observation confidence. Historical/negated text
for the same organization and product is linked for review; it does not by itself
prove a current host deployment has disappeared. Missing environment information
and stale evidence are not silently converted to “unaffected.”

## Supported version and identity additions

OSV SEMVER ranges support SemVer 2.0 prerelease ordering and ignore build metadata
for precedence. PyPI ECOSYSTEM ranges use PEP 440 ordering, including epochs,
development and post releases. GitHub's explicit comparator conjunctions support
these version forms; PyPI comparisons preserve PEP 440 specifier semantics.
GitHub prerelease matching requires an explicit bound for that release's
prerelease. Wildcard/tilde/caret/disjunction syntax and unsupported ecosystem
orderings remain unverified. Debian/RPM/Git native ordering is not guessed.

Three direct HTTP signatures have reviewed vendor/product mappings:

| Signature | Vendor / product | Version behavior |
| --- | --- | --- |
| `Server: Jetty(12.0.7)` | `eclipse / jetty` | Extracts the complete header version; legacy `.vYYYYMMDD` suffixes remain conservatively unverified for ordering. |
| `Server: Caddy/v2.8.4` | `caddyserver / caddy` | Extracts the supplied version; plain `Caddy` remains unknown-version. |
| `X-Jenkins: 2.479.1` | `jenkins / jenkins` | Requires a valid version in the dedicated header; never maps Jenkins plugins. |

Plain prose, lookalike names and malformed header values do not qualify. The
broad ProjectDiscovery catalog continues to use unknown vendor identities and
cannot promote its arbitrary CPE strings to affected-product observations.

## Reproducible extraction holdout

Run from the repository root:

```sh
python -m signalwatch.extraction_evaluation tests/fixtures/extraction_holdout_v1.json
```

The frozen v1 editorial corpus has 34 independently labeled snippets covering
asserted use, negation, history, requirements, alternatives, plans, mentions, and
negative controls. Exact product/evidence-class pairs determine precision and
recall. It is separate from the extractor's rule definitions. Version the corpus
when revising labels or examples; use additional unseen material when improving
rules rather than tuning only against this holdout.

The current report is 38 true positives, 0 false positives, and 0 false negatives:
100% precision and recall on this small corpus. Explicit physical noun phrases
for windows and individual snowflakes are filtered; lowercase software names,
Windows controlling ventilation, and Snowflake weather-data pipelines remain
eligible. Separate word-sense regression cases exercise those boundaries.

The corpus exposed two ambiguity defects and was subsequently used diagnostically
to address them, so its current score is a regression baseline, not an unseen
accuracy estimate. Labels and snippets were not changed to improve the score.
These small synthetic/editorial results do not establish production accuracy or
confidence calibration. Company
attribution, source freshness, version extraction, and CVE applicability have
separate tests and are not measured by this score.
