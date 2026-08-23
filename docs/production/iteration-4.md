# Production Iteration 4 Plan (2026-08-22)

Branch: `production/iteration-4` (from `ox-round3-baseline`). Scope decided after re-reading every
API/web source file, all three prior review logs, and probing the live service read-only plus one
canonical example.com trace (report ID KCEnGGoQruBHZ3mE).

## Current release risks (confirmed findings)

1. **CSP still allows `style-src 'unsafe-inline'`** (`web/_headers:7`, confirmed live). This is the
   last standing finding from round 1, deferred three times as risky. The app injects exactly one
   inline `style="animation-delay:…"` attribute (`web/app.js:397`, timeline stagger); everything else
   uses stylesheets or CSSOM. Removing the allowance eliminates an XSS escalation path on the
   innerHTML-rendered report surface.
2. **Round-3 regression: short exact brand claims stopped resolving** (`api/src/url-risk.ts:196-211`).
   `resolveClaimedBrand` applies the 4-character prefix guard to *equality* as well as prefix
   matching, so `claimedOrganisation: "AIB"` (and aliases "AWS", "BOI" for Amazon/Bank of Ireland)
   resolves to no brand and silently disables focused lookalike scanning instead of narrowing it.
3. **Claimed-brand impersonation misses short aliases** (`api/src/url-risk.ts:237-239`). Token
   containment requires the alias to be ≥5 characters, so `boi-secure.com` is never flagged even when
   the caller explicitly claims "Bank of Ireland" and the label carries the risk token "secure".
   The explicit claim is itself sufficient disambiguation context.
4. **Canonical privacy URL redirects** (verified live): `/privacy.html` answers 307 → `/privacy`
   (Workers Assets HTML handling), yet `web/privacy.html:8` declares the redirecting form as
   canonical, `web/sitemap.xml` lists `/privacy.html`, and the index footer links `./privacy.html`.
   Every privacy-page visit pays a redirect; search engines get mixed signals.
5. **`probeTakeover` violates its own result contract** (`api/src/takeover.ts:395-404`): the outer
   catch pushes `{cname: null}` rows although the documented contract (and the success-path filter,
   line 394) says only CNAME-bearing rows are returned. The UI then renders misleading
   "CNAME → none" takeover rows for budget-blocked probes.

Deployment-state observation (not fixable here, no deploys allowed): the live Worker predates round 2
(health still returns `"environment":"production"`; DNS panel still shows raw type "46"), so the
branch carries multiple unreleased fixes. Recorded as the top release action.

## Intended changes

| # | Change | Files | User impact | Risk |
|---|--------|-------|-------------|------|
| 1 | Drop `'unsafe-inline'` from `style-src`; set the timeline stagger via CSSOM instead of a style attribute | `web/_headers`, `web/app.js`, `scripts/static.test.mjs`, `scripts/browser.test.mjs` | Same visuals; stronger CSP against injected markup | Low: single producer of inline styles; reduced-motion `!important` rules already override inline delays |
| 2 | Exact brand/alias equality always resolves a claim; prefix absorption stays ≥4 chars | `api/src/url-risk.ts`, `api/test/url-risk.test.ts` | Claims like "AIB"/"AWS"/"BOI" focus the assessment again | Low: strict superset of round-3 behaviour; existing non-absorption test kept |
| 3 | When a brand is explicitly claimed, containment matching drops the ≥5-char alias gate (risk-token gate stays) | `api/src/url-risk.ts`, `api/test/url-risk.test.ts` | `boi-secure.com` flagged under a Bank of Ireland claim; unchanged unclaimed | Low-med: FP surface grows only for explicitly claimed brands |
| 4 | Canonicalize privacy URLs to `/privacy` (canonical tag, sitemap entry, footer link) | `web/privacy.html`, `web/sitemap.xml`, `web/index.html`, `scripts/static.test.mjs` | One fewer redirect; consistent SEO signals | Minimal |
| 5 | Outer catch in `probeTakeover` stops emitting `cname: null` rows | `api/src/takeover.ts` | No misleading "CNAME → none" rows; contract honoured | Minimal: diagnostics remain in phase coverage counters |

## Verification

- `npm run typecheck`
- `npm test` (static tripwires + vitest incl. new claimed-brand cases)
- `npm run test:browser` (1440 px and 390 px, axe, no horizontal overflow; extended to serve the
  shell with the production CSP header and fail on any console CSP violation)
- Live re-check limited to read-only GETs; no deploy.

## Explicit non-goals

- Deploying/publishing (forbidden); the stale live build is recorded as a release blocker instead.
- `SOURCE_REVISION` deploy-time injection and observability sampling (deploy tooling; carried decision).
- Redirect-engine cap unification (6 vs 3; separate documented policies).
- Classifier data-table dead alternatives and takeover platform-list tuning (churn without evidence).
- Removing the no-budget fallback paths used by unit tests in reputation/deps/takeover.
