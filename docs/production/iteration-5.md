# Production Iteration 5 Plan (2026-08-22)

Branch: `production/iteration-5` (from `production/iteration-4`). Scope decided after re-reading every
API/web source file, the four prior logs, and probing the live service read-only: HTML/CSP headers,
`/api/health` (still the stale pre-round-2 build: returns `"environment":"production"`, raw DNS type
`46`, `style-src 'unsafe-inline'`), MCP `tools/list`, and one canonical example.com stream trace
(report `27LPyGRmy29cFent`, complete, low, 85 ms).

## Current release risks (confirmed findings)

1. **"Start a new trace" leaves stale advanced-option state** (`web/app.js` `reset()`). Reproduced in
   Chromium: after running a trace with a claimed organisation and dependency mapping selected,
   reset clears the organisation and reputation checkbox but leaves `#map-deps` checked and the
   `#trace-options-state` summary stuck on "2 selected" while every field it counts is now empty.
   `reset()` never calls `updateAdvancedOptionState()` and never resets the mapping checkbox, so the
   next trace silently re-runs the optional dependency phase under a label claiming otherwise.
2. **Published OpenAPI contract drifted from responses.** `web/openapi.yaml` `HealthResponse` still
   lists `environment` as required (line 164) and as a property (line 171); round 2 removed the
   field from `/api/health` output, so every real response violates the published schema.
   `POST /api/scans/stream` documents HTTP `403` "Disallowed or non-public target" and `429`
   "Request limit reached", but blocked targets and quota failures are produced inside
   `createScan` and arrive in-band as NDJSON `{type:"error"}` events with HTTP 200; only input
   validation (400) and origin rejection (403) happen before the stream starts.
3. **Privacy notice understates its own currency.** `web/privacy.html` says "Last updated
   14 August 2026", but the quota-metering wording ("report reads use bounded daily counters")
   was revised on 22 August; the notice claims it has not changed since the 14th.
4. **Dead configuration discloses deployment intent and invites drift.** `ENVIRONMENT = "production"`
   remains in `api/wrangler.toml` `[vars]`, `Env.ENVIRONMENT` in `api/src/types.ts`, and a test env
   literal, although no code has read it since round 2 removed it from the health payload.
5. **Dead artifacts mislead maintenance.** `scripts/browser-smoke.mjs` is referenced by nothing
   (superseded by `scripts/browser.test.mjs` and `scripts/production-smoke.mjs`). Six stylesheet
   declarations set text colors that are always overridden by the readable-text group
   (`styles.css` line ~659 sets `.dns-empty`, `.risk-context > p`, `.risk-boundary`, `.dep-src`,
   `.dependency .party`, `.takeover-detail span` to `#89a99b`), so editing the early rules has no
   effect. Rendered contrast was computed at 4.41–7.49:1 across surfaces and passes AA; this is
   dead-code removal, not a contrast change.

## Intended changes

| # | Change | Files | User impact | Risk |
|---|--------|-------|-------------|------|
| 1 | `reset()` clears the mapping checkbox and refreshes the advanced-options state label | `web/app.js`, `scripts/browser.test.mjs` | New-trace form matches its summary; optional phases only run when actually selected | Low |
| 2 | Drop `environment` from `HealthResponse`; correct the stream endpoint's response documentation to describe in-band NDJSON errors | `web/openapi.yaml`, `scripts/static.test.mjs` | Integrators see a schema that matches reality | Minimal |
| 3 | Bump privacy "Last updated" to 22 August 2026 | `web/privacy.html` | Notice no longer understates its revision date | Minimal |
| 4 | Delete the unused `ENVIRONMENT` variable, type field, and test literal | `api/wrangler.toml`, `api/src/types.ts`, `api/test/api.test.ts` | Less deployed-config drift surface | Minimal |
| 5 | Delete `scripts/browser-smoke.mjs`; prune the six overridden color declarations (keep layout/font properties) | `scripts/browser-smoke.mjs`, `web/styles.css` | Stylesheet rules behave as written | None (no rendered change) |

## Verification

- `npm run typecheck`
- `npm test` (static tripwires incl. new ones + vitest suite)
- `npm run test:browser` (1440/768/390 px, axe, overflow, strict-CSP phase; extended for the reset regression)
- Ad-hoc Playwright repro of finding 1 before and after the fix
- `node scripts/production-smoke.mjs 27LPyGRmy29cFent` against live (read-only)
- Contrast recomputation for the affected selectors (evidence for finding 5's no-op claim)

## Explicit non-goals

- Deploying/publishing (forbidden); the stale live build remains the top release blocker from iteration 4.
- `SOURCE_REVISION` deploy-time injection; observability head sampling (deploy tooling; carried decision rounds 1–4).
- Redirect-engine cap unification (6 vs 3; separate documented policies).
- Parsing JSON error bodies on non-200 stream responses in `app.js`: unreachable from the shipped client
  (input length caps and same-origin requests cannot produce them today).
- Consolidating historical root planning docs (`PLAN.md`, `PRODUCT_REVIEW.md`, `IMPLEMENTATION_REPORT.md`,
  `IMPROVE-PLAN.md`): they hold provenance, and README links PLAN.md.
- Classifier data-table pruning and takeover platform-list tuning (carried decisions; churn without evidence).
