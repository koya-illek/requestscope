# RequestScope architecture

## Product boundary

RequestScope answers one question: what did an edge observer see while resolving
and requesting this public URL?

Every result is classified as one of:

- `dns_observation`: returned by a named DNS-over-HTTPS resolver.
- `edge_http_observation`: returned to a Cloudflare Worker fetch.
- `derived_finding`: deterministically inferred from stored evidence.
- `unavailable`: not measurable from the selected observation mode.

This prevents edge measurements from being presented as browser measurements.

## Scan pipeline

1. Normalize and validate the submitted URL.
2. Reject credentials, IP literals, unsupported ports, and non-HTTP schemes.
3. Resolve A and AAAA records through DNS-over-HTTPS.
4. Require both Cloudflare DNS and Google Public DNS to return only public
   addresses; reject private, loopback, link-local, documentation, benchmarking,
   multicast, or otherwise reserved address space.
5. Fetch with redirects disabled and a strict timeout.
6. Repeat dual-resolver validation for every redirect target, up to six hops.
7. Read at most 256 KiB from the final response.
8. Extract bounded HTML resource references, including `src`, `srcset`, link
   references, and static CSS `url()` values.
9. Generate findings only from captured evidence.
10. Redact every query value from request, redirect, and resource URLs.
11. Store the versioned report in D1 under an unguessable identifier.

## Free-tier budget

The production configuration deliberately stays below the Workers Free limits:

- at most 39 external subrequests per protected scan, versus the current limit of 50
- at most six redirects
- five displayed DNS queries plus dual-resolver validation for every target
- the Free plan's automatic 10 ms CPU ceiling
- 256 KiB maximum body inspection
- 100 dependency records maximum
- two foreground D1 statements for a new scan
- 15 anonymous scans per client fingerprint per UTC day
- 14-day report retention
- five-minute recent-scan caching to avoid duplicate work
- Turnstile validation on new scans
- one daily Cron Trigger for deterministic expiry cleanup
- no Pages Functions, Durable Objects, Queues, R2, or Browser Rendering in v1

Pages serves only static assets, so frontend traffic does not consume the
Workers request allowance. Optional paid or separately metered services remain
future enhancements rather than hidden runtime requirements.

## Data model

The canonical report is stored as versioned JSON. Selected columns provide
indexing and lifecycle management:

- public report identifier
- normalized URL and hostname
- scan state
- creation and expiry timestamps
- overall duration
- report schema version
- report JSON

Rate-limit counters store a one-way daily client fingerprint, never a raw IP.
Turnstile tokens are validated server-side and never stored. Expired reports and
old rate-limit rows are removed daily by a Cron Trigger.

## Failure model

- DNS and HTTP failures are returned as explicit observations.
- A failed redirect hop does not invent downstream results.
- D1 persistence failure fails the request instead of returning an unshareable
  identifier.
- Individual secondary DNS record failures do not erase successful observations.
- Report consumers must tolerate new fields and unknown finding codes.

## Evolution

The schema is designed for later additions:

- browser waterfall observations
- scheduled comparisons and regression detection
- geographically selected probes
- certificate transparency history
- authenticated workspaces
