# Production Iteration 6 Plan (2026-08-22)

Branch `production/iteration-6` (from `production/iteration-5`). Repo: /home/koya/requestscope.
Live URL https://requestscope.illek.ie re-probed this pass; the public Worker still runs the stale
pre-round-2 build (`/api/health` returns `"environment":"production"`, DNS evidence shows raw type
`"46"`, HTML CSP still carries `style-src 'unsafe-inline'`). That release blocker stands; deploying
remains forbidden this pass.

## Audience and core job

Anyone (people, developers, Copilot/MCP agents) who needs evidence about what really happens when a
URL is requested: DNS answers, redirect chain, edge HTTP behaviour, page signals, dependencies, and
an explainable low/medium/high risk verdict. Primary path: paste URL -> streamed trace -> shareable
redacted report. Trust boundary: a public Cloudflare Worker whose only outbound reach is validated
public targets plus consented reputation providers. Product identity: every claim traces to captured,
honestly-labelled evidence; a low score never certifies safety.

## Confirmed findings (re-verified against current source)

1. **README misstates the MCP surface** (`README.md:117-119`): "Both URLs expose one tool,
   `assess_url_risk`". The server publishes three tools (`api/src/mcp.ts:72,133,149,176`), and
   ARCHITECTURE.md:69,99, `web/index.html:285` ("MCP - 3 tools"), and `web/mcp-copilot.yaml:20` all
   say three. Developer-facing doc bug that understates the integration.
2. **Unbounded crt.sh response parse** (`api/src/deps.ts:379`, `queryCertTransparency`):
   `response.json()` reads the whole body with no cap. Every other body read in the pipeline is
   bounded (256 KiB page, 512 KiB per JS bundle, 100 KiB takeover probe, 8/16 KiB request bodies).
   crt.sh is community-run and returns arrays that can reach tens of MB for busy domains; this is the
   last unbounded input in the scan path and a Worker-isolate memory risk.
3. **Brand-owned services always categorised "functional"** (`api/src/url-risk.ts:148-154`): a traced
   `paypal.com` or `stripe.com` appears in `urlRisk.services` with `category:"functional"` because the
   brand branch hardcodes it. REST/MCP consumers get misleading service classes for payment and social
   brands that the classifier already knows how to label.
4. **Version constants duplicated** (`package.json` x2, `api/package.json`,
   `api/src/index.ts:12` `API_VERSION`, `api/src/analyzer.ts:297` hardcoded `"1.4.0"` provenance,
   `api/src/mcp.ts:6` `MCP_SERVER_VERSION`): drift risk on the next bump; nothing ties them together.
5. **Dead constants** `TAKEOVER_TIMEOUT` / `MAX_TAKEOVER_PROBES` in `api/src/deps.ts:27-28`: the
   takeover stage owns identical constants in `takeover.ts`; the deps copies are referenced nowhere.
6. **Browser suite never exercises the saved-report deep link**: no routed `GET /api/scans/:id`, no
   `#<id>` load, no invalid-hash notice, even though share links are the product's primary output.
   Only the live smoke script touches deep links against the stale deployment.
7. **Verification gaps this pass should close**: local end-to-end run of the actual branch under
   `wrangler dev` (all prior rounds verified mocks + a stale live site), a 200% zoom layout check,
   Lighthouse, and the Illek audit-html script.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Correct the README MCP section to the real three-tool contract; add a static tripwire | `README.md`, `scripts/static.test.mjs` | Accurate developer docs | None |
| 2 | Bound the CT response with a 4 MiB reader; overflow or invalid JSON becomes an honest failed analysis with `truncated:true`; export the cap for tests | `api/src/deps.ts`, `api/test/deps.test.ts`, `ARCHITECTURE.md` (resource line) | No behavioural change for normal sites; huge/pathological crt.sh responses can no longer balloon isolate memory | Low: CT still parses normally below the cap; failure mode is explicit coverage, not silent success |
| 3 | Give each `BRANDS` entry an explicit `category` and use it for brand-owned `services` rows (PayPal/Stripe/AIB/BoI -> payment, Meta/LinkedIn -> social, Cloudflare -> cdn, rest functional) | `api/src/url-risk.ts`, `api/test/url-risk.test.ts` | Truthier `urlRisk.services` for REST/MCP consumers | Low: display-only field; no scoring change |
| 4 | New `api/src/version.ts` exporting `API_VERSION` and `MCP_SERVER_VERSION`; `index.ts`, `analyzer.ts`, `mcp.ts` import them; static test asserts `api/package.json` version equals `API_VERSION` and that the old literals are gone | `api/src/version.ts`, `api/src/index.ts`, `api/src/analyzer.ts`, `api/src/mcp.ts`, `scripts/static.test.mjs` | None; maintainability | None |
| 5 | Delete the dead `TAKEOVER_TIMEOUT` / `MAX_TAKEOVER_PROBES` constants | `api/src/deps.ts` | None | None |
| 6 | Browser-suite regression phase: routed saved-report deep link renders with focus on the report heading and updated title; invalid hash shows the INVALID_LINK notice; dismissal clears the hash | `scripts/browser.test.mjs` | Protects the share flow | None |

## Explicit non-goals

- Deploying or pushing anything (forbidden). The live-stale-build blocker is recorded again.
- `SOURCE_REVISION` deploy-time injection and observability head-sampling changes (deploy tooling;
  carried decisions from rounds 1-5).
- Redirect-engine cap unification (6 vs 3): separate intentional policies, documented.
- Classifier table pruning and takeover platform-list tuning: churn without behavioural effect
  (carried).
- `readBodyLimited` unbounded `.text()` fallback in takeover.ts: unreachable in Workers (carried).
- No new features; no dependency additions/removals (tldts 7.4.9 current, `npm audit` clean).

## Verification

1. `npm run typecheck` - clean.
2. `npm test` - all unit + static tests incl. new CT-bound, services-category, and tripwire tests.
3. `npm run test:browser` - existing matrix plus the new deep-link phase, axe-clean at 1440/768/390.
4. Local end-to-end of the branch under `wrangler dev` (not committed): health payload matches the
   corrected contract; NDJSON stream trace of example.com completes with `RRSIG` labels; report GET +
   export work with `Cache-Control: private`; MCP initialize/tools-list negotiate `2025-11-25` with
   three tools; repeat scan serves the recent-cache event; `DAILY_SCAN_LIMIT:2` override yields 429 +
   `Retry-After` on the third scan.
5. Ad-hoc Playwright zoom probe (not committed): 720x450 effective CSS pixels (200% of 1440x900),
   full mocked flow, no horizontal overflow, axe violations none.
6. Illek `audit-html.mjs` on `web/index.html` and `web/privacy.html`; Lighthouse accessibility/SEO
   best-practices run against a locally served shell if tooling cooperates.
7. Read-only live probes to document the standing stale-deployment evidence.
