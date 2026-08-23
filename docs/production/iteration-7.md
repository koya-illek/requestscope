# Production Iteration 7 Plan (2026-08-22)

Branch `production/iteration-7` (from `production/iteration-6`). Repo: /home/koya/requestscope.
Live URL https://requestscope.illek.ie re-probed this pass: `/api/health` still returns
`"environment":"production"`, the HTML CSP still carries `style-src 'unsafe-inline'`, and DNS
evidence still shows raw type `"46"`. The public Worker remains the stale pre-round-2 build; that
release blocker stands and deploying stays forbidden this pass.

## Audience and core job

Anyone (people, developers, Copilot/MCP agents) who needs evidence about what really happens when a
URL is requested. Primary path: paste URL -> streamed trace -> shareable redacted report. Trust
boundary: one public Cloudflare Worker whose only outbound reach is validated public targets plus
consented reputation providers. Product identity: every claim traces to captured, honestly-labelled
evidence; a low score never certifies safety.

Baseline confirmed this pass: typecheck clean, 131 unit/static tests green, browser suite green,
live example.com trace complete (report `kMCnwZUpMubnVhXY`, low verdict, score 0), local
`wrangler dev` end-to-end reproduced quota, cache, CORS, MCP, and export behaviour exactly as
documented.

## Confirmed findings (re-verified against current source and the running Worker)

1. **Read endpoints answer HEAD with 404** (`api/src/index.ts` route conditions require
   `request.method === "GET"`). Reproduced against the branch under `wrangler dev`:
   `HEAD /api/health` -> 404 and `HEAD /api/scans/:id` -> 404 while GET returns 200. Uptime
   monitors and link checkers commonly probe with HEAD (`curl -I` is the default health-check
   idiom), so an operational monitor would report a healthy deployment as down. The four read-only
   endpoints (`/api`, `/api/health`, `/api/scans/:id`, `/api/scans/:id/export`) should answer HEAD
   with the GET headers and no body. Write routes keep their current behaviour.
2. **Published security model drifts from the code** (`SECURITY.md`): the layered-controls list
   claims "GET requests only", but the consented PhishTank adapter POSTs to
   `checkurl.phishtank.com/checkurl/` (`api/src/reputation.ts`). The sentence is meant to describe
   fetches to inspected targets; as written it contradicts the reputation flow it also describes
   later in the same document.
3. **The committed browser suite never exercises the cancel path**: iteration 2 shipped the Cancel
   button and the 45-second stall watchdog (`web/app.js`), but `scripts/browser.test.mjs` has no
   phase that cancels a trace, so a refactor could silently break the escape hatch.
4. **The honest provider-unavailable state is untested**: when `/api/health` reports zero configured
   reputation providers, the UI disables the checkbox and replaces its copy
   (`web/app.js configureProviderAvailability`). The deep-link suite phase already routes such a
   health payload but asserts nothing about it.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Route HEAD through the same handlers as GET on the four read endpoints; strip the response body once at top-level dispatch so headers match GET exactly | `api/src/index.ts`, `api/test/api.test.ts` | Operational HEAD probes see a healthy service with correct status and caching headers | Low: read-only paths only; responses become header-only, bodies unchanged for GET/OPTIONS/POST |
| 2 | Correct the SECURITY.md controls line to "GET-only fetches to inspected targets"; note providers receive their documented API calls | `SECURITY.md` | Published model matches behaviour | None |
| 3 | Browser-suite regression phase: stalled stream + Cancel button surfaces "Trace cancelled.", restores controls, and allows a fresh trace; deep-link phase additionally asserts the reputation checkbox is disabled with replaced copy when no provider is configured | `scripts/browser.test.mjs` | Protects the shipped cancel/watchdog UX and the honest consent state | None |

## Explicit non-goals

- Deploying or pushing anything (forbidden). The stale-live-build blocker is recorded again.
- `SOURCE_REVISION` deploy-time injection and observability head-sampling changes (deploy tooling;
  carried decisions from rounds 1-6).
- Redirect-engine cap unification (6 vs 3): separate intentional policies, documented.
- Classifier table pruning and takeover platform-list tuning: churn without behavioural effect
  (carried).
- `readBodyLimited` unbounded `.text()` fallback in takeover.ts: unreachable in Workers (carried).
- Bounded reads for trusted DoH/provider JSON payloads (resolvers are the trust anchor; carried
  reasoning from the crt.sh decision, which capped an untrusted community service).
- Takeover CNAME-lookup failure rows carrying generic "No CNAME record found" evidence: those rows
  are filtered out by `probeTakeover` before storage, so the string never reaches a report
  (carried near-dead-path decision).
- Wrong-method requests returning 404 instead of 405 on POST routes: out of scope; no client or
  contract depends on it.
- No new features; no dependency additions/removals (tldts 7.4.9 current, `npm audit` clean).

## Verification

1. `npm run typecheck` - clean.
2. `npm test` - all unit + static tests including new HEAD coverage.
3. `npm run test:browser` - existing matrix plus the cancel phase and provider-disabled assertions,
   axe-clean at 1440/768/390.
4. Local end-to-end under `wrangler dev` (not committed): `GET /api/scans/:id` keeps
   `Cache-Control: private`; export attachment header intact; `HEAD /api/health`,
   `HEAD /api/scans/:id`, and `HEAD .../export` return 200 with matching headers and empty bodies;
   in-band NDJSON 429 at the scan limit; MCP initialize/tools/list unchanged.
5. Read-only live probes to reconfirm the standing stale-deployment evidence.
6. Illek `audit-html.mjs` plus Lighthouse accessibility/SEO/best-practices against a locally served
   shell; 200% zoom Playwright probe.
