# Production Iteration 8 Plan (2026-08-22)

> **Historical plan.** The findings listed below (Turnstile suffix, CSP
> wildcards, CT truncation, takeover signatures, public-target derived
> fetches, request budget) were implemented on later `main` commits. Do not
> treat this file as a current defect list. The note that the live Worker was
> a stale pre-round-2 build described that pass only.

Branch `production/iteration-8` (from `production/iteration-7`). Repo: /home/koya/requestscope.
Live URL https://requestscope.illek.ie re-probed this pass: `/api/health` still returns
`"environment":"production"`, the HTML CSP still carries `style-src 'unsafe-inline'`, and
`HEAD /api/health` still answers 404. The public Worker remains the stale pre-round-2 build; that
release blocker stands and deploying stays forbidden this pass. Baseline on the branch: typecheck
clean, 134 tests green, live example.com stream trace complete (report `2gqnkHfpPJ-PFu7N`,
complete status, 69 ms).

## Audience and core job

Anyone (people, developers, Copilot/MCP agents) who needs evidence about what really happens when a
URL is requested. Primary path: paste URL -> streamed trace -> shareable redacted report. Trust
boundary: one public Cloudflare Worker whose only outbound reach is validated public targets plus
consented reputation providers. Product identity: every claim traces to captured, honestly-labelled
evidence; a low score never certifies safety. This pass protects that identity where it was quietly
eroding: mislabeled attacker infrastructure, dropped CSP evidence, wrong truncation flags, and
takeover verdicts that could accuse live sites or miss real dangling hosts.

## Confirmed findings (re-verified against current source and live probes)

1. **Unanchored `turnstile\.site` classifier pattern mislabels attacker-shaped hosts**
   (`api/src/classifier.ts:144`). After label-boundary compilation the alternative matches without
   an end anchor, so `turnstile.sitedemo.com` and `evil.turnstile.site.attacker.com` classify as
   "Cloudflare Turnstile", category `security`, `piiRisk:false` — hostile infrastructure wearing a
   trusted vendor's label in reports. The correctly anchored twin at line 240 is shadowed dead code
   because line 144 wins first.
2. **Wildcard CSP sources never reach the dependency map** (`api/src/deps.ts:197`). The host capture
   class `([^:/\s*]+])` excludes `*`, so `*.cloudfront.net` or `https://*.example.com` return null;
   the "normalise wildcard subdomain" code below is unreachable. Wildcard sources are one of the
   most common real-world CSP shapes, so third parties allowed only via a wildcard vanish from the
   map.
3. **`startsWith("sha")` rejects legitimate hosts** (`api/src/deps.ts:189`). Intended to skip
   `sha256-…` hashes, it also rejects scheme-less CSP host sources such as `sharethis.com`.
4. **CT analysis `truncated`/`total` are wrong in both directions** (`api/src/deps.ts:405-415`).
   `truncated: data.length > MAX_CT_RESULTS` compares certificate count against the subdomain cap:
   5,000 certificates yielding 40 unique names flags truncated though nothing was cut, while an
   early loop break that cut names leaves `truncated:false`; `total` can exceed the returned list
   length.
5. **`postAuthOnly` exemption bypassed when CT contributed via a second source**
   (`api/src/deps.ts:87-89` with `addDomain` collapsing differing sources to `"multiple"`): a domain
   proven publicly visible by Certificate Transparency plus a JS bundle gets flagged
   post-auth-only despite the CT proof.
6. **Bundle accounting drift on the final chunk** (`api/src/deps.ts:259-265`): when the byte cap
   lands mid-chunk the code counts its own `remaining` estimate even if the body budget accepted
   fewer bytes, so decoded text can exceed accounted bytes by up to one chunk.
7. **Takeover signatures contradict empirically verified platform behaviour**
   (`api/src/takeover.ts`). Reproduced read-only against the live platforms this pass:
   - A genuinely unclaimed `*.webflow.io` host answers 404 with the full sentence "The page you are
     looking for doesn't exist **or has been moved**." The shipped Webflow signature is only the
     shorter generic prefix, so an active site's custom 404 using that common sentence plus a 404
     route yields `vulnerable:true` — a false accusation.
   - A genuinely unclaimed `*.ghost.io` host answers with a "Domain error" page. The shipped Ghost
     signature is the *Webflow* sentence, so real Ghost takeovers can never match (the copied
     string proves copy drift).
   - An unclaimed `*.squarespace.com` name answers with title "Squarespace - No Such Website";
     neither shipped Squarespace pattern (`No Such Site`, `domain not found`) matches that text.
   - Cargo and Azure carry generic unverified alternatives ("The page you were looking for doesn't
     exist", "The web site you have accessed is not available") with the same false-accusation
     shape as the old Webflow entry.
8. **Regional S3 REST endpoints escape the CNAME patterns** (`api/src/takeover.ts:15-16`):
   `bucket.s3.eu-west-1.amazonaws.com` matches neither `\.s3\.amazonaws\.com$` nor the website form,
   silently skipping a common dangling-bucket shape (false negative).
9. **`probeTakeover` contradicts its contract and fills reports with noise**
   (`api/src/takeover.ts:379-394`): the docstring promises "Only subdomains with a matching CNAME
   pattern are included", but the code pushes every row with a CNAME, including "no known takeover
   pattern" rows; the same collapse makes the resolver-failure branch indistinguishable from
   confirmed absence ("No CNAME record found").

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Anchor the Turnstile alternative with `$` and delete the shadowed duplicate entry | `api/src/classifier.ts`, `api/test/classifier.test.ts` | Attacker-shaped hosts stop inheriting Cloudflare's security label; genuine `*.turnstile.site` and `challenges.cloudflare.com` classification unchanged | Low |
| 2 | Rewrite `extractHostFromCspSource`: strip leading `*.` (bare and after scheme), gate hashes with `/^sha(?:256|384|512)-/i`, and validate the extracted host against a strict hostname shape so path-bearing junk cannot enter the map | `api/src/deps.ts`, `api/test/deps.test.ts` | Dependency maps include wildcard-CSP third parties and ShareThis-style hosts; no junk rows | Low: conservative shape check may skip exotic-but-real underscore hosts — acceptable, they classify unknown anyway |
| 3 | Simplify CT collection: gather all unique names within the parsed payload, then slice; `truncated` iff more names exist than shown; `total` always describes the full discovery | `api/src/deps.ts`, `api/test/deps.test.ts` | Truncation flag and counts become truthful in both directions | Low: pure CPU over the already-parsed ≤4 MiB payload |
| 4 | Track contributing sources per domain in a side set; CT presence exempts a domain from `postAuthOnly` regardless of source-string collapse | `api/src/deps.ts`, `api/test/deps.test.ts` | Post-auth-only summary stops contradicting stored CT evidence | None |
| 5 | Use the value returned by `budget.inspectBytes` when slicing the final bundle chunk | `api/src/deps.ts` | Byte accounting matches decoded text exactly | None |
| 6 | Replace/correct takeover signatures with the empirically verified fingerprints: Webflow tightened to the full verified phrase; Ghost corrected to "Domain error"; Squarespace gains the verified title marker; Cargo/Azure drop their generic unverified alternatives; add regional S3 REST endpoint pattern | `api/src/takeover.ts`, `api/test/takeover.test.ts` | No more false `vulnerable:true` from generic custom-404 copy; real Ghost/S3-regional dangling hosts become detectable | Medium-low: tightening relies on this pass's live probes of the true dangling pages; distinctive legacy patterns kept where service-specific, and the CNAME gate still scopes body checks per service |
| 7 | Make `probeSubdomain` return null unless the CNAME matches a known pattern; filter nulls in `probeTakeover`; export the two pure matchers for direct tests | `api/src/takeover.ts`, `api/test/takeover.test.ts` | Takeover panel shows only qualifying evidence; empty state becomes accurate; resolver failures no longer phrased as absence | None |

## Explicit non-goals

- Deploying or pushing anything (forbidden). The stale-live-build blocker is recorded again.
- Accounting Certificate Transparency bytes into the shared body budget: ARCHITECTURE.md documents
  a separate 4 MiB CT cap (updated iteration 6); merging would contradict the published resource
  model for no behavioural gain.
- Reputation budget-exhaustion wording nit and dead `not_configured` filter in `summarize()`:
  wording/dead-code churn with no observable effect.
- Classifier slash-bearing pattern pruning (e.g. `facebook\.com\/tr`): carried rounds 3-7 decision —
  harmless dead alternatives inside entries that also match bare hostnames.
- `readBodyLimited` unbounded `.text()` fallback: unreachable in Workers (carried).
- `SOURCE_REVISION` deploy-time injection and observability head sampling (deploy tooling; carried).
- Redirect-engine cap unification (6 vs 3): intentional separate policies, documented.
- No new features; no dependency changes (tldts current, `npm audit` clean).

## Verification

1. `npm run typecheck` — clean.
2. `npm test` — all unit + static tests including new classifier/deps/takeover coverage.
3. `npm run test:browser` — existing matrix stays green (UI untouched; confirms no regression).
4. Ad-hoc node probes (not committed): compiled-pattern behaviour for `turnstile.sitedemo.com`,
   `evil.turnstile.site.attacker.com`, `sub.turnstile.site`; CSP extraction table covering
   wildcards, schemes, hashes, paths.
5. Read-only live probes reconfirming the standing stale-deployment evidence.
