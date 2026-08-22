# Improvement Plan — Round 3 (2026-08-22)

Fresh review on top of the round-1 fixes (`fix/review-2026-08-22`) and round-2 improvements
(`improve/review-2026-08-22`). Every item below was re-verified against current source before
planning. Branch: `rerun3/review-2026-08-22`.

## Technical

### T1 · P1 · JS-bundle mapper fetches storage-redacted URLs
- **What:** The analyzer redacts every dependency URL before storage, then hands those *redacted*
  URLs to `mapDependencies`, which fetches them. Outbound bundle requests go out with literal
  `?v=%5Bredacted%5D` query values, and bundles that need their real query string (cache-busting,
  versioned bundles) can fail to fetch or serve different content — silently degrading the
  optional dependency phase.
- **Where:** `api/src/analyzer.ts:200,252` (redaction map + `mapDependencies` script list).
- **Why:** Redaction is a *storage* concern; derived fetches should use the observed URL. The
  round-2 reputation fix made exactly this distinction for provider targets.
- **How:** Pass the pre-redaction `dependenciesRaw` script entries into `mapDependencies`.
  Storage stays redacted (the report still stores mapped deps from the redacted array, and
  `deps.ts` already re-redacts stored evidence contexts via `redactTextForStorage`). Add an
  analyzer test asserting the fetched bundle URL keeps its query value while the stored
  dependency URL is redacted.

### T2 · P1 · Stale quota claims in living privacy/security docs
- **What:** Round 1 moved report retrieval onto durable D1 metering (`index.ts:113`), but two
  living docs still claim report reads do not write D1 rate-limit rows.
- **Where:** `web/privacy.html:35`; `SECURITY.md:78-80`. (Correct reference:
  `ARCHITECTURE.md:123`.)
- **Why:** Privacy honesty — the notice must match actual data processing.
- **How:** Reword both to: validated scans, MCP tool calls, report reads, and provider quota
  accounting are bounded and durable in D1; only MCP handshake/discovery messages avoid D1
  writes.

### T3 · P2 · Saved-report loading has no stall watchdog
- **What:** `runTrace` arms a 45-second idle timer and cancels with distinct stall copy;
  `loadReport` arms no timer at all, so a hung `GET /api/scans/:id` spins the progress panel
  until the user thinks to press Cancel.
- **Where:** `web/app.js:163-202` (`loadReport` vs `runTrace`'s watchdog).
- **How:** Reuse the same idle-watchdog pattern in `loadReport` (arm/reset per chunk is
  unnecessary for a single JSON body — arm once per attempt) with load-specific timeout copy.

### T4 · P2 · Verbose claimed organisations silently disable brand mode
- **What:** `resolveClaimedBrand` requires exact normalized equality, so common real-world
  claims ("Microsoft Corporation", "Google LLC", "Bank of Ireland Group") never match a brand —
  claimed-brand lookalike boosting and brand-scoped matching silently do nothing.
- **Where:** `api/src/url-risk.ts:196-200`.
- **How:** Match when the normalized claim starts with a normalized organisation or alias
  (prefix direction prevents short claims from matching long brands). Tests for verbose-match
  and non-match sides.

## UI / UX

### U1 · P1 · Main URL input regressed below the iOS focus-zoom threshold
- **What:** At ≤620 px the primary URL input is set to `font-size: 14px`
  (`web/styles.css:679`). Safari zooms the viewport when focusing inputs under 16 px — round 2
  fixed `.risk-context` inputs for this exact issue but left the main input behind (it was
  reduced from 17px desktop to 14px mobile).
- **Where:** `web/styles.css` mobile block.
- **How:** Raise the mobile font-size to 16px.

### U2 · P2 · Dependency filter state is visual-only
- **What:** Filter buttons ("All / First-party / Third-party") toggle an `active` class only;
  screen readers get no indication of which filter is applied.
- **Where:** `web/index.html:203-207`; `web/app.js:63-66`.
- **How:** Add `aria-pressed="false"` initially and keep it in sync in the click handler.

### U3 · P2 · Contrast miss on `.dependency .party`
- **What:** `#61786e` ≈ 3.9:1 on the panel surface for 10px mono text — the one dim label class
  round 2's override sweep (`styles.css:659-660`) did not include (siblings `.dep-src`,
  `.takeover-detail span`, `.dep-svc` were fixed).
- **Where:** `web/styles.css:352` → join the `#89a99b` group.

## Other

### O1 · Lock the new states in static tests
- **Where:** `scripts/static.test.mjs`.
- **How:** Assert filters carry `aria-pressed` and the corrected privacy wording; keep existing
  assertions green.

## Skipped this round (with reasons)

- **CSP `style-src 'unsafe-inline'`** — carried from rounds 1-2: needs build-time hash
  computation plus visual regression coverage beyond this pass.
- **`SOURCE_REVISION` deploy-time injection; observability head sampling** — deploy tooling out
  of scope; sampling deferred until volume grows.
- **Redirect-engine cap unification (6 vs 3)** — intentional separate policies documented in
  ARCHITECTURE.md.
- **`takeover.ts readBodyLimited` unbounded `response.text()` fallback** — effectively
  unreachable in Workers (a null-body response yields ""), churn outweighs benefit.
- **`probeTakeover` outer-catch rows carrying `cname: null`** despite its doc comment — nearly
  dead path, cosmetic accounting nit.
