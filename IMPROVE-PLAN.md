# Improvement Plan — Round 2 (2026-08-22)

Round 1 findings are fixed on `fix/review-2026-08-22`. This plan covers fresh round-2
review findings. Each item lists what, where, why, how. Priority: P1 = do first,
P3 = nice to have. Branch: `improve/review-2026-08-22`.

## Technical

### T1 · P1 · Classifier suffix patterns match mid-label, misclassifying legitimate domains
- **What:** `netflix.com`, `box.com`, `citrix.com` classify as Twitter/X (`x\.com$`
  matches the tail of any host ending in those letters); `medical.com` as Cal.com;
  same defect hits `heap.io`, `media.net`, `tawk.to`, `arc.io`, `yahoo.com`,
  `/turnstile\.site/i` (matches `evil-turnstile.site`) and friends. Verified live.
- **Where:** `api/src/classifier.ts` (`classifyDomain` line ~541, `isKnownDomain`,
  `PII_FALLBACK` line 584).
- **Why:** Categories flow into report services, dependency-map names, PII flags, and
  SDK context. A URL-risk tool that says "netflix.com is Twitter/X" destroys evidence
  credibility and fires wrong PII flags (social/advertising are PII categories).
- **How:** Add a boundary-aware matcher: a pattern match is valid only when
  `match.index === 0 || host[match.index - 1] === "."`. Use it in `classifyDomain`
  and `isKnownDomain` (compile `(?:^|\.)` + source once at module load so top-level
  alternations like `a$|b$` stay correct). Replace the substring `PII_FALLBACK` regex
  with exact-token matching over labels split on `.` `-` `_` against a conservative
  set (analytics, tracker, tracking, telemetry, beacon, pixel). Add tests
  (`netflix.com` → unknown, `x.com`/`www.x.com` → Twitter/X, `evil-x.com` → unknown,
  `trackandfield.ie`/`soundtrack-cdn.example.com` → no PII fallback).

### T2 · P1 · MCP endpoint flattens rate limits into HTTP 200 results and leaks raw internal errors
- **What:** In `callTool` (`api/src/mcp.ts:85-96`) `beforeToolCall` runs inside the
  `try`, so `RateLimitError` becomes an `isError:true` result with HTTP 200 — the 429
  documented in `web/openapi.yaml:134` and `web/mcp-copilot.yaml` is unreachable, and
  clients get no transport signal to back off. The same catch returns
  `error.message` verbatim for any failure (D1 driver text, TypeErrors), bypassing the
  sanitising `normalizeError` used by REST (`index.ts:454-459`). Also
  `readMcpMessage` maps oversize bodies and non-object/array envelopes to `-32700`
  Parse error when JSON-RPC reserves that for syntax failures (-32600 Invalid Request
  is correct). And `rpc()` never applies CORS headers even though the route admits
  allow-listed origins.
- **Where:** `api/src/mcp.ts`, wiring in `api/src/index.ts:83-106`.
- **Why:** Contract drift on both published specs; retry-storm pressure on the very
  limit being enforced; info-disclosure asymmetry between the two API surfaces;
  broken browser-client interop.
- **How:** Move `beforeToolCall` before the `try`; wrap `callTool` dispatch in a catch
  that maps `RateLimitError` → JSON-RPC error with HTTP 429 (+`Retry-After`); inside
  the existing catch pass through `InputError`/`BlockedTargetError` messages as
  `isError` results (tool-execution failures per MCP spec) but log-and-genericise
  everything else. Split read errors: `JSON.parse` failure → `-32700`; oversize,
  non-object, or array envelope → `-32600`. Thread the router's computed CORS headers
  through `handleMcp` options into every response. Tests: rate-limited call → 429;
  array body → -32600; internal error masked.

### T3 · P1 · Takeover `vulnerable: true` can fire on HTTP 200 pages
- **What:** The signature branch (`api/src/takeover.ts:306-316`) ignores status, so a
  live site serving "There's nothing here" or "domain not found" anywhere in a 200
  body (soft-404 themes, footers) yields `vulnerable: true` — an actionable false
  accusation. The code already treats bare 404/410 as merely *potential*.
- **Where:** `api/src/takeover.ts` (`probeSubdomain` step 4).
- **How:** Require a failure status (4xx/5xx) for `vulnerable: true`; a signature hit
  on 2xx/3xx returns `vulnerable: false` with evidence "signature observed on active
  response — manual verification recommended". Extract the decision into a small pure
  function and unit-test both paths (no takeover test file exists today).

### T4 · P2 · Containment lookalike tier flags benign compound words; `incomplete-observation` claims high confidence
- **What:** Round 1's containment tier matches aliases like `office`, `apple`,
  `amazon`, `adobe`, `stripe`, `revenue` (all ≥5 chars), so `apple-orchard.com`,
  `office-supplies.ie`, `amazon-river-tours.com` earn medium/16 impersonation
  findings. Separately, `url-risk.ts:123-125` labels the "could not be fully
  inspected" finding confidence "high" while its own detail says absence of findings
  proves nothing.
- **Where:** `api/src/url-risk.ts`.
- **Why:** Crying wolf on ordinary compound domains degrades triage signal; a failed
  trace should not carry the strongest confidence label.
- **How:** Keep containment only when at least one *other* token in the first label
  belongs to a risk lexicon (login, signin, verify, secure, account, billing,
  payment, update, confirm, recovery, wallet, mail, alert, notice, support, helpdesk,
  auth, id). So `microsoft-login.com` still flags; `apple-orchard.com` does not.
  Change the incomplete-observation confidence to `"medium"`. Extend
  `test/url-risk.test.ts`.

### T5 · P2 · Reputation skips the final URL when redirects change only query values
- **What:** `uniqueTargets` (`api/src/reputation.ts:364-370`) deduplicates on
  *redacted* URLs; two URLs differing only in query values collapse, so the final URL
  never reaches providers even though providers receive full URLs by consent.
- **Where:** `api/src/reputation.ts`.
- **How:** Deduplicate on the exact URL strings (they are equal only if genuinely
  identical). Redaction remains a storage/display concern. Test via existing
  reputation test harness pattern.

### T6 · P2 · Derived-fetch paths don't reuse the per-request DNS-validation memo
- **What:** Round 1 added a memo to redirect revalidation, but `fetchPublicUrl`
  (`api/src/egress.ts`) calls `assertPublicTarget` without a map, so dependency-map
  bundle fetches and takeover probes pay 4 DNS subrequests per hop/host again, and a
  chain revisiting the origin host re-pays because the analyzer never seeds its
  initial resolution (`analyzer.ts:73-85`).
- **Where:** `api/src/egress.ts`, `api/src/deps.ts`, `api/src/takeover.ts`,
  `api/src/analyzer.ts`.
- **How:** Accept optional `validatedHosts` in `fetchPublicUrl` and pass through;
  create one map per request in `mapDependencies` and one in `probeTakeover`; seed the
  analyzer's map with the initial hostname's resolution (compose initial + secondary
  queries). Memo stays request-scoped, success-only (unchanged invariant).

### T7 · P2 · Router reliability and consistency batch (`api/src/index.ts`)
1. **Stream disconnect safety** (`streamScan` ~298-331): after client disconnect,
   `send()` throws in `start`, again in the `catch`'s own `send`, and `close()` throws
   in `finally` → unhandled rejection and lost report. Track a `closed` flag set in
   `cancel()`, make `send` a no-op once closed, guard `close()`.
2. **Report GET origin check** (~108-126): POST routes reject unallowed `Origin`
   headers; GETs don't, so cross-site pages can burn victims' report-retrieval quota.
   Apply the same 403.
3. **Health endpoint** (~47-63): drop the `environment` field from the public payload
   (free recon signal; provider booleans stay because the web UI depends on them).
4. **Cron cleanup** (`scheduled`, 134-136): add `.catch(console.error)` so a transient
   D1 failure surfaces instead of silently forfeiting the cycle.
5. **MCP double quota** (`index.ts:101,104,255`): each MCP scan consumes both the
   `mcp` scope (200/day) and the inner anonymous `scan` scope (15/day), making
   `MCP_DAILY_LIMIT` unreachable per IP. Give `createScan` an option to skip the inner
   limiter for MCP-originated calls (the `mcp` scope still enforces abuse control);
   document in README.

### T8 · P3 · Regex defects in dependency extraction
- **Where:** `api/src/deps.ts:31-32`.
- **What:** `WS_PATTERN` has a stray literal `]` outside its character class
  (`[^\s"'<>\`)]]*`), degenerating path capture; `FETCH_CALL_PATTERN`'s `.open`
  alternative matches substrings (`window.open(`, `db.open(` labelled XHR).
- **How:** Remove the duplicated bracket; require `\b` boundaries and drop `.open`
  from the fetch-call pattern (it never reliably means XHR).

### T9 · P3 · Delete dead `ssl.ts`
- **What:** `api/src/ssl.ts` has zero importers (CT data builds `SslDetail` inline in
  `deps.ts`); if ever wired up it would bypass the request budget and store unsanitised
  header-derived issuer strings.
- **How:** Delete the file (subtract-before-you-add); typecheck confirms nothing
  breaks.

## UI-UX

### U1 · P1 · A stalled scan locks the primary control with no escape
- **What:** No `AbortController`, no timeout, infinite `reader.read()` loop; the Trace
  button disables until page reload. A stalled edge stream (common on mobile) hangs
  forever.
- **Where:** `web/app.js` (`runTrace`, `readTraceStream`), `web/index.html`
  (progress panel), `web/styles.css`.
- **How:** Create an `AbortController` per run; add a Cancel button in the progress
  panel wired to `abort()`; handle `AbortError` ("Trace cancelled", no scary error);
  arm an idle watchdog reset on each chunk (45 s silence → abort with a clear
  message). Re-enable controls in `finally`.

### U2 · P1 · Completion and failure never move focus or announce outcome
- **What:** After render/failure, focus stays on the Trace button; `#report` and the
  error heading aren't focusable, so screen-reader users get no confirmation and
  keyboard users lose their place after the scroll jump.
- **Where:** `web/app.js` (`displayReport`, `showError`), `web/index.html`.
- **How:** `tabindex="-1"` on `#report-host` (h2) and the error panel `h2`; call
  `.focus({ preventScroll: true })` after unhide; let the existing smooth scroll
  position the content.

### U3 · P1 · Second submit races the first (Enter bypasses the disabled button)
- **What:** Form submit fires `runTrace` unconditionally; two concurrent streams
  interleave progress writes and burn quota twice.
- **Where:** `web/app.js`.
- **How:** Module-level `inFlight` guard checked/set in `runTrace` and `loadReport`,
  cleared in `finally`; also ignore submits while restoring reports from popstate.

### U4 · P2 · Reduced-motion gaps (JS scrolls not gated; CSS delay/transition resets missing)
- **What:** Four `scrollIntoView/scrollTo({behavior:"smooth"})` calls run regardless of
  `prefers-reduced-motion` (explicit option overrides CSS `scroll-behavior`). The CSS
  reduced-motion block resets duration but not `animation-delay`, so timeline hops
  stay invisible for up to 780 ms then pop; transitions are untouched.
- **Where:** `web/app.js` (138, 174, 200, 365), `web/styles.css` (689-691).
- **How:** One `prefersReducedMotion` media query at module scope feeding a shared
  `scrollToEl` helper (`behavior: "auto" | "smooth"`); add `animation-delay: -1ms;
  transition-duration: .01ms` resets to the media query.

### U5 · P2 · Fragile response handling surfaces parser garbage to users
- **What:** `loadReport` parses JSON before checking `response.ok` (edge HTML error
  pages become SyntaxError text); network failures show raw "Failed to fetch";
  malformed NDJSON lines throw raw JSON.parse errors into the UI.
- **Where:** `web/app.js` (`loadReport`, `runTrace`, `readTraceStream`).
- **How:** Check `ok` first, fall back to `text()`+safe-parse for error bodies; map
  fetch `TypeError` to a friendly offline message; wrap stream-line parsing so a bad
  line becomes "Received an invalid response from the server."

### U6 · P2 · Browser back/forward desyncs from the report view
- **What:** History entries are pushed but no `popstate` handling exists: Back clears
  the hash while the report stays visible; Forward does nothing.
- **Where:** `web/app.js`.
- **How:** `hashchange` listener (covers Back/Forward/manual edits): valid ID →
  `loadReport`; empty hash with a visible report → return to the form view; guarded by
  U3's `inFlight`.

### U7 · P2 · Rendered hrefs lack a scheme allowlist; enum class slots interpolate raw
- **What:** Dependency links come from inspected third-party HTML; `escapeAttr`
  prevents breakout but a surviving `javascript:`/`data:` URL would execute on click.
  Same class of issue for advisory URLs and `#report-url`. Enum-driven `class`
  attributes (`risk-verdict ${verdict}`, severity classes) interpolate server values
  unescaped.
- **Where:** `web/app.js` (181, 228, 232, 252, 300, 319).
- **How:** `safeHref(url)` returning the URL only when `/^https?:\/\//i` matches
  (otherwise render plain text/no link); whitelist-map enums to class names with an
  `unknown` fallback.

### U8 · P2 · Contrast failures on dim labels
- **What:** Skipped route-node text `#354940` at opacity .62 (≈1.45:1 effective), idle
  route-node labels `#50675e` (≈3.0:1), progress-step labels `#526a60` (≈3.1:1),
  input placeholder `#53675f` (≈3.0:1) — all fail WCAG AA; round 1 brightened eight
  other tokens but missed these.
- **Where:** `web/styles.css` (158, 220, 226, 238).
- **How:** Move all four to `#6f887d`+ range (≥4.5:1 on the dark surfaces); remove the
  `.62` opacity from skipped nodes and rely on the dashed border for de-emphasis.

### U9 · P2 · No `<noscript>` fallback
- **What:** With JS off, the form submits natively to the current URL and silently
  discards input; social scrapers see nothing actionable.
- **Where:** `web/index.html` `<main>`.
- **How:** Styled `<noscript>` notice explaining traces need JavaScript; give the form
  `action="./"` `method="get"` hygiene.

### U10 · P3 · Smaller accessibility/UX polish batch
1. `#query-warning` gets `role="status"` (consent-adjacent info is announced).
2. Findings severity currently colour-dot only: add visually-hidden severity text
   beside the dot.
3. Methodology `<dialog>` gets `aria-labelledby` → its `h2`.
4. Copy-link flash: put `aria-live="polite"` on the button, store/clear the timeout so
   rapid clicks don't restore labels early; reuse flash for Export JSON feedback.
5. Error-close and dialog-close buttons reach 44×44 px targets.
6. `.risk-context` inputs jump to 16px under 620px (prevents iOS focus zoom).
7. Long traced/reference URLs become readable on touch: allow wrapping
   (`overflow-wrap:anywhere`) for hop and dependency rows at narrow widths instead of
   ellipsis-only.
8. Status pill reflects health: amber "Status unavailable" when `/api/health` fails.
9. Malformed deep-link hash (non-empty but not a report ID) shows a gentle notice
   instead of being ignored; error panel gains a "Start a new trace" action and
   dismissal clears a stale hash; saved-report loading shows a minimal indeterminate
   panel instead of the fake seven-stage pipeline.
10. Rename "Public deep scan" → "Scan on Cloudflare Radar" (names the third party);
    extend its confirm copy to mention query values; sync `scripts/static.test.mjs`.

## Other

### O1 · P3 · Sitemap includes only the home page
- Add `https://requestscope.illek.ie/privacy.html` to `web/sitemap.xml` (real
  indexable content, standards say documentation pages stay indexable).

### O2 · P3 · Documentation sync
- README: MCP scans enforce the dedicated `MCP_DAILY_LIMIT` rather than consuming the
  anonymous scan quota (T7.5); note the 409-free behaviour changes where visible.

## Explicitly skipped (with reasons)

- **Budget-exhaustion during initial DNS surfacing as 403 "inconclusive"**: real but
  reachable only under tiny budgets/deadlines; fixing requires rethrowing across
  `queryDns` observation-collection semantics used by several phases — risk outweighs
  benefit this pass.
- **Takeover probe skip-counting in phase coverage**: cosmetic accounting gap;
  budget-delta counters already capture truncation at phase level.
- **CSP `style-src 'unsafe-inline'` removal**: needs build-time hash computation and
  visual regression beyond this pass (carried from round 1).
- **`SOURCE_REVISION` deploy-time injection, observability sampling**: deploy tooling
  out of scope; sampling deferred until volume grows (round 1 decision stands).
- **Redirect-engine cap unification (6 vs 3)**: separate intentional policies.
