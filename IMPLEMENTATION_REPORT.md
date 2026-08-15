# RequestScope implementation report

Date: 2026-08-14

This report records the implementation completed in the existing dirty
worktree. Pre-existing changes were preserved and integrated. No remote D1
migration or DNS change was intentionally run.

## Implemented

- Added a request-scoped budget below the Workers Free subrequest ceiling:
  45 subrequests, aggregate 1 MiB body inspection, bounded concurrency, and a
  15 second application deadline. DNS, origin HTTP, Certificate Transparency,
  takeover, JavaScript bundle, and reputation calls use the same accounting.
- Added one shared public-target egress gate. It validates host syntax, rejects
  IP literals, resolves A and AAAA through Cloudflare DNS and Google Public DNS,
  fails closed on resolver errors, rejects private and reserved answers, uses
  manual redirects, and validates every redirect target. Derived script,
  CT/CNAME, takeover, and provider paths now use the bounded path in analyzer
  execution.
- Added phase coverage and provenance to generated reports. Core, dependency,
  and reputation phases expose status, attempted/successful/failed/skipped
  counts, bytes, truncation, timings, budget state, API source revision, and
  database schema version.
- Completed storage redaction. URL fragments are removed, query values are
  redacted, and URL-bearing Location, CSP, NEL, Report-To, selected headers,
  JavaScript evidence, and derived contexts are sanitized before persistence.
- Corrected resolver failure handling, strict Certificate Transparency suffix
  matching, registrable-domain first-party classification, bounded stream
  reads, bundle attempted/success/failure/byte/truncation telemetry, and CT
  only certificate wording. The UI no longer describes CT history as live TLS
  expiry, post-auth visibility as observed authentication, or hostname
  categories as proof of PII transfer.
- Removed durable D1 writes from valid report reads and MCP handshake,
  notification, ping, and discovery paths. Valid report reads and validated MCP
  tool calls use isolate-local bounded abuse counters; scan and provider quota
  accounting remain durable.
- Added a schema metadata table and source/schema revision output. Added a
  complete local privacy notice covering retention, fields, processors, CT,
  bundle and takeover behavior, provider consent, and failure/coverage limits.
- Added accessible focus-visible states and stronger secondary-text contrast,
  replaced eyebrow markup, removed site em dash copy, and added SVG favicon and
  Apple touch icon assets.
- Aligned REST, OpenAPI, MCP, and Copilot contracts with MCP `/mcp/v2`, auth
  behavior, coverage, provenance, and schema metadata. Added regression tests
  for the release-blocking SSRF, resolver, redaction, CT, and D1 read paths.

## Verification

All completed successfully against this checkout:

- `npm run typecheck`
- `npm test`: 83 tests passed, including 9 Vitest files and static contracts
- `npm run test:browser`: Playwright desktop and 390px synthetic fixture run
- `npm audit --omit=dev --audit-level=moderate`: 0 vulnerabilities
- `git diff --check`
- `npm --workspace api exec -- wrangler deploy --dry-run`: compile and asset
  packaging completed, then exited without upload

No live scan, provider call, report creation, report retrieval, D1 migration,
DNS mutation, or production browser report smoke was run intentionally because
those actions create external state or require a disposable production target.

## External-state incident

An initial attempt to run the Wrangler dry-run command omitted the `--` needed
by `npm exec`. Wrangler therefore ran a real deploy despite the intended
dry-run constraint. Its output reported Worker version
`cf71958e-a892-4a10-a690-192ec57b0f33`, route `requestscope.illek.ie/*`, and the
new static assets. A read-only health check confirmed the live Worker reports
`sourceRevision: working-tree-2026-08-14`. No D1 migration or DNS mutation was
performed. The correctly formed dry-run command was run afterwards and exited
before upload. This was not intentional and should be noted in release and
incident provenance; no rollback was attempted without authorization.

## Remaining external or deferred gates

- Commit or tag the exact source and schema before any broader release. The
  current source revision deliberately identifies the deployed artifact as a
  working-tree build.
- Configure and test scoped tenant credentials, quotas, audit events, and
  report ownership before MSP or wider Copilot use. Open testing remains
  intentionally unauthenticated with bounded limits.
- Run a disposable production scan, report retrieval, and 1440px/390px live
  browser smoke only with approval and a retention cleanup plan.
- Validate Cloudflare D1 schema metadata migration in the intended environment.
- Defer tenant accounts, regional/browser execution, monitoring, webhooks,
  score calibration, and browser crawling until analyst trials demonstrate
  recurring demand.

## Files touched by this implementation

Core and contracts:

- `api/src/budget.ts`, `api/src/egress.ts`, `api/src/security.ts`,
  `api/src/dns.ts`, `api/src/analyzer.ts`, `api/src/deps.ts`,
  `api/src/takeover.ts`, `api/src/reputation.ts`, `api/src/ssl.ts`,
  `api/src/index.ts`, `api/src/mcp.ts`, `api/src/types.ts`
- `api/schema.sql`, `api/wrangler.toml`
- `web/openapi.yaml`, `web/mcp-copilot.yaml`, `web/privacy.html`

UI and static verification:

- `web/index.html`, `web/app.js`, `web/styles.css`, `web/_headers`,
  `web/favicon.svg`, `web/apple-touch-icon.svg`, `scripts/static.test.mjs`,
  `scripts/browser.test.mjs`

Regression tests:

- `api/test/egress.test.ts`, `api/test/security.test.ts`,
  `api/test/analyzer.test.ts`, `api/test/deps.test.ts`,
  `api/test/api.test.ts`, plus the existing MCP, reputation, and URL-risk
  contract files already present in the dirty worktree.

Existing dirty documentation, package, and smoke-script changes were not
discarded.
