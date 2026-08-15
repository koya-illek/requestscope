# RequestScope product review

Review date: 2026-08-14  
Scope: `/home/koya/requestscope` and `https://requestscope.illek.ie`  
Review mode: read-only. This review does not change product code, configuration, deployment, DNS, databases, or other external state.

## Executive verdict

RequestScope has a clear and potentially useful core: a no-login, edge-vantage URL observer that records DNS, bounded manual redirects, selected HTTP evidence, deterministic findings, consented reputation checks, and a report that can be consumed by REST or MCP. The current site is polished, fast to understand, responsive at desktop and 390px, and unusually careful about describing a low risk score as non-certification.

The release is not ready for broader public or MSP/agent use. Two issues are release-blocking: derived dependency and takeover requests do not inherit the public-target SSRF boundary, and the optional dependency map can exceed the current Workers subrequest and CPU budget by a large margin. In addition, report redaction is incomplete, D1 is written for every MCP and report retrieval request, production provenance is currently uncommitted, and the privacy page does not describe all current processors and probes.

Recommended disposition: keep the trace and risk-assessment core available for controlled testing, disable dependency-map JavaScript and takeover fetching in production until it has an independent egress boundary, and make P0 security, budget, redaction, storage, and release-provenance fixes before marketing this as an MSP or Copilot service. The product should be positioned as a privacy-redacted edge evidence tool for agent-assisted triage, rather than as a general browser scanner or a binary safe/unsafe authority.

## Review boundaries and confidence

I inspected the current working tree, source, tests, schemas, documentation, Wrangler configuration, static assets, and the live custom domain. Local tests and synthetic browser fixtures were run. Live health, endpoint discovery, static contracts, MCP initialization, desktop rendering, mobile rendering, and report rendering with intercepted fixture data were checked.

I did not submit a live scan, invoke a live reputation provider, create a live report, or retrieve an existing production report. A live scan would create a retained D1 report and rate-limit state, and a report retrieval also writes rate-limit state in the current implementation. One live MCP `initialize` request was sent to verify the deployed protocol response. The router performs the MCP D1 rate-limit upsert before dispatching the method, so that request necessarily created or updated one `rate_limits` row. No target fetch, provider call, scan report, or external probe was invoked by that request. This side effect is included here for completeness.

## Evidence and tests run

### Repository and release state

- Current branch is `main`, HEAD is `d011c84` (`Vary hero copy - replace evidence-backed with proof-at-every-hop`).
- The checkout is dirty: 21 tracked files are modified and 10 files are untracked. The untracked set includes `api/src/mcp.ts`, `api/src/reputation.ts`, `api/src/url-risk.ts`, their tests, `web/openapi.yaml`, `web/mcp-copilot.yaml`, and production smoke/browser scripts. The modified set includes API code, schema, Wrangler variables, web code, headers, package manifests, and tests.
- The deployed static `index.html`, `app.js`, `styles.css`, `config.js`, `openapi.yaml`, and `mcp-copilot.yaml` matched the current working-tree web assets by the checks performed. The current API implementation cannot be reproduced from the commit alone because the API and configuration changes are uncommitted.
- `api/wrangler.toml:1-44` uses the custom route `requestscope.illek.ie/*`, with `workers_dev = false` and `preview_urls = false`. No `pages.dev` or `workers.dev` deployment is configured there.

### Local commands

All of the following completed successfully against the current checkout:

- `npm test`: 76 total tests passed, including one static test and 75 Vitest tests across eight files.
- `npm run typecheck`: TypeScript completed with no errors.
- `npm run test:browser`: Playwright synthetic fixture run passed at 1440px and 390px. This script has limited assertions and is not a production scan.
- `npm audit --omit=dev --audit-level=moderate`: zero reported vulnerabilities.
- `git diff --check`: no whitespace errors.

No Wrangler deploy, migration, or What-If equivalent was run because this is a review-only task.

### Live HTTP checks

The following returned successfully from the current custom domain:

- `/`: HTTP 200, current dark technical landing page, Cloudflare cache headers, HSTS, CSP, frame, referrer, permissions, and content-type protections.
- `/api/health`: HTTP 200, API version `1.4.0`, production environment, rate-limit protection, and configured-provider booleans.
- `/api`: HTTP 200 endpoint discovery for scans, reports, URL risk, and MCP.
- `/openapi.yaml`, `/mcp-copilot.yaml`, `/robots.txt`, and `/config.js`: HTTP 200.
- `/mcp/v2` JSON-RPC `initialize`: HTTP 200, protocol `2025-11-25`, server `requestscope` version `2.2.0`.
- `https://tools.illek.ie/privacy`: HTTP 200, but the content is materially less complete than the live consent text and implementation. See H5.
- `/favicon.ico` and `/apple-touch-icon.png`: HTTP 404.

### Browser and responsive checks

- Live homepage at 1440x1000: no horizontal overflow, 29 focusable elements, one console 404 caused by the missing favicon.
- Live homepage at 390x844: no horizontal overflow and no page or console errors.
- Deployed HTML, CSS, and JS rendered a locally intercepted report fixture at 1440px and 390px with no horizontal overflow, console errors, page errors, or HTTP errors. The fixture included high risk scoring, redirects, findings, CSP, JavaScript, Certificate Transparency, SSL, SDK, and takeover sections.
- The mobile layout stacks correctly. Dense monospace metadata, several low-contrast secondary labels, and default browser focus outlines still need accessibility refinement.

## Findings

Severity uses Critical for a direct security or availability release blocker, High for a serious security, privacy, operational, or release-integrity issue, Medium for correctness or maintainability work that can mislead users or constrain adoption, and Low for polish or lower-probability defects.

### C1 - Critical: dependency-map and takeover egress bypass the public-target SSRF boundary

Evidence:

- The primary URL path uses `normalizeUrl` and public DNS checks (`api/src/security.ts:11-40`, `api/src/analyzer.ts:286-312`).
- HTML dependency extraction instead constructs a `URL` directly and only checks the scheme (`api/src/analyzer.ts:385-424`). It does not reject IP literals, private hostnames, reserved ranges, or DNS failures.
- JavaScript bundle fetching uses the extracted URL directly, follows redirects, and does not validate the original or each redirect target (`api/src/deps.ts:171-207`). A page containing a script such as `http://127.0.0.1/foo.js`, a cloud metadata hostname, or a public bundle that redirects internally can reach an address outside the stated public-only boundary.
- Takeover probing gets hostnames from CT, queries CNAME, then fetches `https://${subdomain}` with `redirect: "follow"` and no public resolution or redirect validation (`api/src/takeover.ts:236-342`).
- `SECURITY.md:3-39` describes layered public-target SSRF protection and acknowledges a DNS rebinding window, but the derived-target paths do not implement the same controls.

Impact: attacker-controlled page HTML, script content, or CT data can turn an apparently public scan into an internal network or metadata probe. Cloudflare runtime restrictions may reduce practical reachability, but an application security boundary must be enforced by the application and tested explicitly. This also creates a route for redirects to escape a safe initial host.

Required direction: make every derived URL pass one shared validator that resolves A and AAAA through the configured resolvers, fails closed on resolver errors, rejects all private and special ranges, and validates every manual redirect. Use `redirect: "manual"` for derived requests. The safer immediate release choice is to disable JS bundle fetching and takeover HTTP probes until those checks run in an isolated, separately budgeted worker.

### C2 - Critical: optional dependency mapping can exceed Workers subrequest and CPU budgets

Evidence:

- The documented architecture claims at most 45 external subrequests and 10ms CPU (`ARCHITECTURE.md:39-57`).
- Core inspection can use five DoH requests for `inspectDns` (`api/src/dns.ts:70-80`), four more for secondary initial A/AAAA, up to six redirect hops with four resolver calls each, and up to seven main HTTP fetches including the initial and final requests.
- Mapping adds up to 15 JavaScript fetches, one CT request, one SSL CT request, up to 20 CNAME queries, and up to 20 takeover HTTP probes (`api/src/deps.ts:19-25`, `api/src/deps.ts:171-207`, `api/src/deps.ts:281-321`, `api/src/takeover.ts:344-379`). Consent-based reputation can add provider calls and quota writes.
- A high case is approximately 88 external requests before reputation and approximately 94 with three provider calls, before accounting for redirects in derived fetches. The current Cloudflare Workers platform limit is 50 subrequests per request on the Free plan. See [Cloudflare Workers limits](https://developers.cloudflare.com/workers/platform/limits/).
- The map can read up to 15 bundles at 512 KiB each. That is roughly 7.5 MiB of JavaScript parsing and concatenation before regex analysis, while the runtime has a 10ms Free-plan CPU budget. `api/src/deps.ts:195-241` also sets `truncated` but never reports it and hard-codes `totalBytes: 0`.

Impact: legitimate complex pages can fail, hit a 1102 CPU/subrequest error, or consume the worker budget before a report is saved. The architecture and UI claims become unreliable exactly on the pages where the map is most useful.

Required direction: set and enforce a whole-request budget, stop optional stages before the limit, count DNS and provider requests, and return explicit coverage. Keep map stages off the default path until measured on the deployed compatibility date and plan. Do not represent a theoretical per-stage cap as a whole-request cap.

### H1 - High: report redaction does not cover redirect fragments, selected headers, or raw CSP

Evidence:

- `api/src/security.ts:43-55` replaces URL query parameter values but preserves URL fragments.
- `api/src/analyzer.ts:328-335` applies that function to redirect `Location` values. A redirect fragment such as `#access_token=...` can therefore be persisted in `hops[].location` and in the duplicated selected header.
- Selected headers include `content-security-policy`, `nel`, `report-to`, and `location` (`api/src/analyzer.ts:19-45`). Values are copied raw by `selectHeaders` (`api/src/analyzer.ts:320-326`).
- CSP analysis stores up to 4096 characters of raw policy (`api/src/deps.ts:114-169`). CSP reporting endpoints and NEL or Report-To endpoints can contain token-like query material.
- The UI and methodology say reports redact query values before storage (`web/index.html:283-295`), while `SECURITY.md:41-47` describes redaction as a general report property.

Impact: public report IDs and JSON exports can expose credentials, signed URLs, or tracking identifiers embedded in fragments or header values. Query redaction is useful, but the current claim is broader than the implementation.

Required direction: define a URL-like redaction pass for every stored string, remove fragments before any storage, sanitize `Location`, CSP, NEL, Report-To, and any future URL-bearing headers, and test tokens in query, fragment, header, CSP, and JS contexts. Consider omitting raw policy and retaining structured directives only.

### H2 - High: DNS validation fails open when one resolver query errors

Evidence: `queryDns` represents HTTP errors, JSON errors, and timeouts as `status: -1`, empty answers, and `error` (`api/src/dns.ts:23-67`). `assertPublicResolution` only gathers addresses and rejects an empty set or blocked address; it never checks `status` or `error` (`api/src/analyzer.ts:303-312`).

Impact: a resolver timeout or error can be treated as a successful public observation when the other family has a public answer. This weakens the documented dual-resolver and rebinding boundary and makes behavior dependent on which DNS response arrives.

Required direction: distinguish `NOERROR` with no address from resolver failure, fail closed on resolver failures for every request that will be fetched, and record resolver agreement as an explicit coverage field. Add tests for A error plus public AAAA, AAAA error plus public A, CNAME failure, and contradictory answers.

### H3 - High: D1 write amplification on reads and protocol discovery creates an avoidable availability risk

Evidence:

- All MCP requests are rate-limited before `handleMcp`, including `initialize`, `ping`, `tools/list`, invalid messages, and report retrieval (`api/src/index.ts:83-104`).
- Every `GET /api/scans/...` is rate-limited before report ID validation and before Cache API or D1 lookup (`api/src/index.ts:107-114`).
- The limiter performs an `INSERT ... ON CONFLICT ... UPDATE ... RETURNING` against D1 for every request (`api/src/index.ts:347-366`).
- The configured limits are 200 MCP requests and 120 report requests per IP per day (`api/wrangler.toml:9-17`), but there is no global write cap and no cache before the limiter.

Impact: distributed read traffic, client retries, and MCP handshake polling can consume D1 write quota without creating useful reports. Invalid report IDs and unsupported requests also incur writes. The scan path has a recent Cache API lookup only after its scan limiter write (`api/src/index.ts:248-295`).

Required direction: use Cloudflare edge/WAF/Workers rate limiting or a cache-backed counter for read and handshake traffic, validate route and protocol before charging a counter, and reserve D1 for durable report/provider accounting. Add global abuse controls and an observed write budget.

### H4 - High: production source provenance is not reproducible from the current commit

Evidence: the working tree has 21 modified tracked files and 10 untracked files while HEAD remains `d011c84`. API implementation, schema, Wrangler variables, web behavior, API contracts, and tests are among the uncommitted changes. The deployed static assets match the working tree, which confirms deployment of the current web content but does not establish a committed API source revision.

Impact: an incident responder cannot identify the exact deployed API source, schema revision, or dependency contract from git. Review, rollback, migration auditing, and release approval are weakened. A passing local suite does not prove the live Worker is the same build.

Required direction: commit or tag the release artifact, include a build/source revision in `/api/health` and reports, record migration version, and make deploy output prove the revision, route, bindings, and asset hash. Keep review notes separate from product changes.

### H5 - High: live privacy policy omits current processors and observation surfaces

Evidence:

- The live UI consent text explicitly names Google Web Risk, PhishTank, Cloudflare malware-filtering DNS, complete original and final URLs, possible PhishTank source IP recording, and hostname-only Cloudflare DNS (`web/index.html:68`).
- The code performs CT queries, JS bundle fetches, CSP analysis, SSL CT lookups, and takeover probes when mapping is enabled (`api/src/deps.ts:36-109`, `api/src/takeover.ts:236-379`).
- `SECURITY.md:49-61` documents some provider behavior and a Radar handoff warning.
- The live `tools.illek.ie/privacy` page describes URL submission, 14-day report retention, and private/local blocking, but does not enumerate all optional processors, CT, bundle fetches, takeover probes, selected headers, or provider retention/processing.

Impact: consent and privacy disclosure do not cover the behavior a user can select. This is a trust and compliance risk for MSP and agent workflows, especially when a submitted URL contains identifiers or customer data.

Required direction: make the privacy notice the source of truth for each data field, recipient, purpose, retention, opt-in condition, and failure mode. State clearly that RequestScope does not submit page bodies to reputation providers, what is stored in reports, and what external services are contacted by each option.

### H6 - High: the SSL/TLS section presents historical CT data as a certificate observation

Evidence: `mapDependencies` calls `inspectSsl(hostname, null)` (`api/src/deps.ts:80-84`). `inspectSsl` only fills protocol, cipher, issuer, and subject when a `Response` is passed (`api/src/ssl.ts:23-50`), so those fields are always unknown from this call. Validity dates come from the newest `crt.sh` entry, not a live TLS handshake (`api/src/ssl.ts:52-117`). The UI labels the section SSL/TLS certificate (`web/app.js:499-510`) and methodology claims TLS metadata (`web/index.html:283-295`).

Impact: users can read historical certificate transparency dates as current edge certificate validity, while protocol and issuer appear as missing telemetry. This reduces trust in a security-focused report.

Required direction: either pass the actual final response and label the fields as edge metadata, or rename the panel to `Certificate Transparency history` and remove current-certificate language. Do not calculate expiry or `daysUntilExpiry` as a live warning from CT alone.

### H7 - Medium: total edge time excludes optional dependency mapping and reputation work

Evidence: `api/src/analyzer.ts:182-238` calculates `base.totalDurationMs` before dependency mapping and before `checkExternalReputation`. `web/app.js:185-195` presents this value as `Total edge time`.

Impact: a report that visibly spends seconds on mapping or external checks reports only the core trace duration. Users and operators cannot compare the actual request cost or diagnose budget failures.

Required direction: record stage timings and compute total duration immediately before returning the report. Keep core trace, map, and provider durations separate so partial coverage is visible.

### H8 - Medium: POST-AUTH and PII labels are inference-heavy and can be interpreted as facts

Evidence: `postAuthOnly` is set from absence in CSP domains and script hosts plus a source check (`api/src/deps.ts:68-77`). The UI renders the label with title `Only visible after authentication` (`web/app.js:475-488`). There is no authenticated browser session or visibility measurement. PII risk comes from hostname classification (`api/src/deps.ts:68-78`) rather than observed data collection.

Impact: a third-party service absent from the unauthenticated HTML can be labelled post-auth even when it is simply loaded dynamically, and a hostname category can be read as proof that PII is transmitted. This can create false alarm and contractual confusion.

Required direction: rename to `not observed in initial HTML` and `possible data-bearing service`, show the heuristic and source, or remove both labels until a browser/session observation exists.

### H9 - Medium: CT suffix filtering accepts unrelated domains

Evidence: CT entries are admitted when `clean.includes(apex) && clean !== apex` (`api/src/deps.ts:299-305`). For an apex such as `example.com`, `evil-example.com` also passes. The result can feed takeover probes (`api/src/deps.ts:87-88`).

Impact: unrelated historical certificate names can appear as dependencies and trigger unnecessary external requests. This increases noise, privacy exposure, and the SSRF/budget surface.

Required direction: require `clean === apex || clean.endsWith('.' + apex)` and use the same public-suffix library for the query and comparison. Keep wildcard normalization and IDN handling explicit.

### H10 - Medium: public URL risk and MCP access are open unless an optional secret is configured

Evidence: `authorizedRiskRequest` returns true when `COPILOT_API_KEY` is absent (`api/src/index.ts:157-170`). The current Wrangler vars list no `COPILOT_API_KEY` (`api/wrangler.toml:1-44`), and the README describes the open testing posture. This affects `/api/v1/url-risk` and MCP, while the public scan route is also intentionally open.

Impact: anyone can spend scan, D1, CT, takeover, or provider budget through the agent-facing interface, enumerate report IDs if obtained, and use the service as an unauthenticated scanning proxy. IP quotas are not tenancy, authorization, or audit.

Required direction: configure a secret before any wider MSP/Copilot rollout; add scoped tenant keys, quotas, audit events, and an explicit development mode. Keep report IDs unguessable but do not treat that as access control.

### H11 - Medium: URL risk coverage is useful as a heuristic but too shallow for a strong market promise

Evidence: `api/src/url-risk.ts:10-26` contains a small static brand and shortener set. The assessment uses hostname structure, edit distance, static HTML markers, redirects, and optional provider matches (`api/src/url-risk.ts:51-180`). It does not execute browser JavaScript, inspect runtime navigation, evaluate cookies, submit forms, or observe dynamic content. The code itself adds an incomplete-observation limitation (`api/src/url-risk.ts:118-122`).

Impact: common lookalike domains, new brands, Unicode/script tricks, dynamic phishing pages, and benign but complex flows can be missed or over-scored. A low result remains a useful absence-of-evidence signal, not a safety determination.

Product direction: keep the evidence-backed wording and expose the exact matched signals, corpus version, and coverage. Do not market the score as a phishing verdict until it is calibrated against a maintained corpus and measured false positives and false negatives.

### H12 - Medium: tests do not cover the highest-risk production paths

Evidence: the passing tests cover normal URL normalization, analyzer behavior, API contracts, reputation helpers, and synthetic UI. I found no regression tests for a private dependency script, a public script redirecting to a private target, CT suffix confusion, raw header or fragment redaction, resolver error plus public sibling-family response, D1 rate-limit writes on invalid report IDs, or an actual production disposable target. Browser tests use intercepted fixture data rather than a live scan.

Impact: the most important claims are not protected by automated tests, so a future refactor can reintroduce the boundary and privacy defects while the suite remains green.

Required direction: add focused unit tests first, then a Worker-level integration harness with fake DoH, fetch, D1, Cache API, and provider responses. Add a disposable production smoke target only with explicit approval and a cleanup/retention plan.

### H13 - Medium: dependency-map telemetry is internally inconsistent

Evidence: `scrapeJsBundles` sets `bundlesFetched` to the number of eligible bundles before any fetch succeeds, sets `totalBytes` to zero, and tracks `truncated` without returning it (`api/src/deps.ts:171-241`). Pattern contexts include a URL string after dependency redaction (`api/src/deps.ts:224-228`), which can drop useful signed-query context while still leaving other raw strings in the report.

Impact: operators cannot tell whether bundles were fetched, how much data was analyzed, or whether truncation changed the result. The map's apparent precision exceeds its measurement.

Required direction: return attempted, successful, failed, bytes inspected, and truncated counts. Store only sanitized host/path context. Add coverage fields to the report and UI.

### H14 - Medium: party classification is a naive hostname suffix test

Evidence: `sameSite` returns true when either hostname ends with the other (`api/src/analyzer.ts:436-438`).

Impact: sibling domains and deceptive suffixes can be classified as first-party or third-party incorrectly, especially around public suffixes and delegated subdomains. Dependency and security-signal summaries become less reliable.

Required direction: compare registrable domains using the existing `tldts` dependency, then separately label exact host, same registrable site, and cross-site. Do not infer organizational control solely from a registrable domain.

### L1 - Low: missing favicon creates avoidable 404 noise

Evidence: the live homepage requests `/favicon.ico` and direct probing also returns 404. The desktop console recorded the 404.

Impact: minor console noise and a less finished browser experience.

Required direction: add a small SVG/PNG favicon and apple-touch icon, or explicitly suppress the requests in the document.

### L2 - Low: duplicated type and contract drift increase maintenance cost

Evidence: `SslDetail` is declared twice in `api/src/types.ts:155-164` and `api/src/types.ts:268-277`. MCP output schemas are broad objects (`api/src/mcp.ts:122-129`), while the OpenAPI contract omits the MCP path and its URL-risk required list is incomplete (`web/openapi.yaml:1-170`). The MCP connector is an import description with generic response bodies (`web/mcp-copilot.yaml:1-25`).

Impact: generated clients and agent callers receive less validation than the TypeScript model promises, and duplicate types invite divergent edits.

Required direction: define types once, generate OpenAPI and MCP schemas from shared models or validate both in CI, and add contract tests for required fields, status codes, auth, and content negotiation.

### L3 - Low: takeover body cap can exceed its nominal limit by a stream chunk

Evidence: `readBodyLimited` increments `bytesRead` and appends the complete chunk before checking the loop condition (`api/src/takeover.ts:208-226`).

Impact: a large stream chunk can temporarily exceed the intended 100 KiB body bound. This is lower risk than the map budget issue but weakens resource guarantees.

Required direction: slice the final chunk to the remaining byte budget, cancel the reader, and expose a truncation flag.

### L4 - Low: reserved IPv4 coverage is incomplete

Evidence: `isPublicIPv4` blocks selected documentation and special ranges but does not model every IANA special-purpose range (`api/src/security.ts:81-95`). For example, the 192.0.0.0/24 handling only names two addresses.

Impact: unusual reserved addresses can be treated as public. This is defense-in-depth because the derived-target issue is the larger defect.

Required direction: use a maintained special-purpose address table or a well-tested range library and add IPv4/IPv6 boundary cases.

### Accessibility and UX observations

- The skip link exists (`web/styles.css:34-47`), dynamic content is escaped in `web/app.js`, consent text is explicit, and the responsive layout has no horizontal overflow at 390px.
- Tiny metadata and secondary text use colors such as `#53675f` and `#60766d` on the dark background. Measured contrast is approximately 3.19:1 and 3.96:1, below WCAG AA for normal text. Some larger muted text passes.
- There is no consistent `:focus-visible` treatment for links, buttons, and filter controls. The browser default black outline is difficult to see on the dark surface. Inputs use focus-within or border changes but do not provide a unified keyboard state (`web/styles.css:124-135`, `web/styles.css:347-347`).
- The mobile UI is structurally sound. The consent paragraph and route/dependency metadata are dense at 390px and should be tested with text zoom and screen-reader announcement order.
- The site copy is generally careful: it says evidence-backed, gives an observation boundary, asks for reputation consent, and warns that low risk never proves safety. Retain this discipline when adding features.

## Architecture and security assessment

The core pipeline in `ARCHITECTURE.md:19-35` is understandable: normalize, dual public DNS, manual redirect handling, bounded response body, dependency extraction, optional reputation, redaction, and D1 storage. The main fetch path does use `redirect: "manual"`, no cookies, no caller headers, a 10-second timeout, a six-hop cap, and a 256 KiB body cap (`api/src/analyzer.ts:80-171`). HTTP response headers and findings are escaped before web rendering, and the static site has a strong baseline CSP and frame/referrer/permissions policy in `web/_headers`.

The security model fails at composition. Controls on the initial URL do not automatically protect URLs discovered from HTML, JavaScript, CT, CNAME, or redirects. The optional map is also treated as a feature toggle rather than as a separate egress and budget domain. Fixing that composition boundary is more important than adding another provider or detection rule.

The data model retains reports for 14 days (`api/wrangler.toml:9-17`, `api/schema.sql`) and exposes public report retrieval by an unguessable 16-character ID. That is a reasonable prototype choice for shareable reports, but public IDs, raw selected headers, complete provider-submitted URLs, and open agent endpoints need a documented threat model before MSP use. Report retrieval should be cacheable without a D1 write and should have a clear owner/tenant model if reports contain customer URLs.

## Product and market assessment

### What is strong

- A focused edge observation contract is easier to explain and safer to operate than a pretend browser-security oracle.
- The UI communicates the difference between observation and certainty better than most URL tools. The route timeline, DNS records, response headers, findings, and report export form a coherent evidence packet.
- No login is a good first-use property for analysts and helpdesk staff. MCP and REST make the result useful inside an agent workflow.
- Explicit consent for full URL sharing to Google Web Risk and PhishTank is a strong trust decision. Hostname-only Cloudflare DNS handling is clearly called out.
- 14-day retention, query-value redaction intent, public-only input, bounded bodies, and a visible observation boundary are good foundations for a privacy-sensitive product.

### Where the market is already served

[Cloudflare Radar URL Scanner](https://radar.cloudflare.com/scan) and [Cloudflare's URL Scanner documentation](https://developers.cloudflare.com/radar/investigate/url-scanner/) already provide shareable URL reports with browser-oriented requests, redirects, screenshots, console/performance data, and security context. [urlscan.io's API](https://urlscan.io/docs/api/) provides public/private scans, screenshots, DOM/results, and search. [MDN Observatory](https://developer.mozilla.org/en-US/observatory) already covers security-header and hardening checks.

RequestScope should avoid a feature race with these products. A generic browser crawler, screenshot product, or large threat-intelligence aggregator would add cost and operational risk while removing the clearest current distinction.

### Best differentiation

The strongest position is: `privacy-redacted edge evidence for AI agents and MSP phishing triage`.

That position requires:

- a stable, documented evidence schema;
- honest coverage and timing fields;
- safe, fail-closed egress for every derived target;
- clear consent and processor disclosure;
- tenant or API-key boundaries for agent use;
- report annotations that explain why a signal exists and what it does not prove.

The dependency map, SSL panel, takeover probes, and PII/post-auth labels currently dilute that position because they imply browser, TLS, identity, or vulnerability evidence the implementation does not fully collect. Keep them only after their semantics and boundary are repaired.

### Likely users and value

The practical first users are MSP/helpdesk analysts triaging suspicious links, SOC or fraud teams needing a shareable first-pass evidence packet, developers investigating redirects/cache/header behavior, and Copilot-style agents that need a bounded URL observation tool. Ordinary site owners already have many scanner choices and will not pay for another dashboard without monitoring, ownership, or workflow integration.

Validate the workflow with real trials before building a team dashboard: measure time saved, analyst agreement with the report, false-positive handling, and whether redacted reports are accepted in incident tickets. The product's value is the evidence packet and agent integration, not the number of panels.

## Recommended implementation plan

### P0 - release blockers, highest impact

1. Disable dependency-map JS fetching and takeover HTTP probes in production, or move them to a separately isolated worker with a hard egress policy. Reuse one validator for initial, derived, CNAME, and every redirect target. Reject IP literals, private/reserved ranges, DNS errors, and ambiguous resolution. Use manual redirects and a whole-request subrequest/CPU budget.
2. Fix report redaction before retaining more reports. Remove URL fragments; sanitize every URL-bearing selected header and raw CSP/Report-To/NEL value; add regression tests for query, fragment, headers, CSP, and signed URLs.
3. Remove D1 writes from report reads and MCP handshake/discovery, or replace them with an edge rate-limit mechanism. Validate route and method before charging counters. Add global abuse controls and observed D1 write alarms.
4. Establish a reproducible release: commit/tag the source, schema, contracts, and Wrangler vars; add source revision to health/report metadata; capture deploy output and migration version.
5. Configure `COPILOT_API_KEY` and a documented development mode before sharing MCP or URL-risk endpoints outside controlled testing.

### P1 - correctness and trust, moderate effort

1. Rename SSL to CT history until a genuine TLS observation is passed. Remove current expiry claims from CT-only data.
2. Compute total time after all optional stages and add per-stage duration and coverage.
3. Replace `postAuthOnly` and PII assertions with clearly labelled heuristics, or remove them. Fix CT suffix matching and use registrable-domain comparison for party labels.
4. Correct bundle counters, byte totals, truncation reporting, strict chunk limits, and redacted context handling.
5. Bring the privacy page into line with the consent text and code. Document processors, retention, data fields, CT, bundle and takeover behavior, provider consent, and failure cases.
6. Add contract validation for OpenAPI and MCP, including `/mcp/v2`, content negotiation, protocol version handling, auth, error status behavior, and the complete URL-risk schema.

### P2 - product validation and adoption

1. Build a labelled suspicious-URL corpus and report score calibration, false positives, false negatives, and confidence by page type. Version the brand and shortener corpus.
2. Add tenant-scoped keys, quotas, audit records, report ownership, and configurable retention for MSP workflows.
3. Add a report diff or webhook only if real trials show repeated monitoring demand. Keep output evidence-first and privacy-redacted.
4. Fix contrast, focus-visible styles, favicon, screen-reader status announcements, and text-zoom behavior. Re-run desktop and 390px checks.

### P3 - defer until demand is proven

Consider regional observations or browser execution only after the edge evidence workflow demonstrates demand and a separate security/budget design exists. Browser execution would change the product's privacy, SSRF, cookie, JavaScript, cost, and consent model substantially.

## Explicit do-not-implement list

- Do not build a generic screenshot, cookie, DOM, or JavaScript crawler to compete with Radar or urlscan.
- Do not add broad vulnerability scanning, form submission, authentication bypass, credential testing, or arbitrary path probing.
- Do not issue a binary `safe` verdict or allow/block recommendation from a low score alone.
- Do not expand to unauthenticated multi-tenant MSP use. IP limits and report IDs are not tenant authorization.
- Do not add more paid reputation providers or a large generic brand database before consent, demand, budget, and calibration evidence exist.
- Do not weaken public-target checks, pin a private egress exception, or add a `YOLO` bypass for agent convenience.
- Do not build a generic team dashboard before agent/helpdesk trials show a recurring workflow and willingness to adopt.
- Do not automatically submit URLs to Cloudflare Radar or forward raw token-bearing URLs. Keep the current explicit user-triggered handoff and warning.
- Do not present takeover, live SSL expiry, PII transfer, or post-auth visibility as facts until the implementation observes the required evidence.

## Final release recommendation

The trace core is worth preserving and testing with real analysts. Treat the current release as an amber prototype with red security and operational gates. A small P0 release can make the product credible: harden or disable derived fetching, make budgets real, make redaction complete, remove D1 write amplification, disclose processors, and publish a reproducible artifact. After those changes, validate the narrow edge-evidence and agent-triage workflow before expanding the surface area.
