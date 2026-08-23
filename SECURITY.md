# RequestScope security model

URL fetchers are exposed to server-side request forgery and abuse by design.
RequestScope applies layered controls:

- only `http:` and `https:` URLs
- only ports 80 and 443
- no URL credentials
- no IP-literal targets
- hostname syntax and length validation
- public A/AAAA resolution required before every request
- private and reserved IPv4/IPv6 ranges rejected
- redirects followed manually and revalidated
- six-hop redirect limit
- ten-second timeout per request
- bounded response reads
- one request-wide budget below the Workers Free subrequest ceiling, with
  aggregate body, concurrency, and elapsed-time limits
- dependency scripts, CT names, CNAME checks, takeover requests, and provider
  handoffs use the same public-target gate; optional phases report skipped or
  partial coverage when the budget is reached
- bounded JSON request reads, independent of `Content-Length`
- GET-only fetches to inspected targets; configured reputation providers
  receive only their documented API calls
- no cookies forwarded between hops
- no user-controlled request headers
- daily client rate limits without raw IP retention
- optional owner scan-limit bypass stored only as an encrypted Worker secret;
  bypass IPs are never written to source, responses, reports, or D1
- removal of URL fragments and redaction of every URL query value before
  persistence or sharing
- redaction of URL-bearing Location, CSP, NEL, Report-To, and selected header
  values, plus URL and token-shaped strings in derived evidence
- restrictive CORS and security headers
- external reputation disabled by default and enabled only by an explicit
  request boolean or UI checkbox
- at most the original and final URL sent to configured reputation providers
- only original and final hostnames sent to Cloudflare's malware-filtering DNS
- provider credentials stored only as Worker secrets
- raw provider responses and unredacted lookup URLs excluded from reports
- hard provider quotas and bounded provider timeouts

DNS rebinding cannot be eliminated perfectly when fetching by hostname on an
edge runtime. RequestScope narrows the window by requiring both Cloudflare DNS
and Google Public DNS to return only public addresses immediately before each
fetch, disabling fetch caching, and revalidating every redirect. Cloudflare's
fetch isolation remains part of the trust boundary. Deployments must retain the
multi-resolver checks, strict port allowlist, and low request limits.

RequestScope is a diagnostic observer, not a vulnerability scanner. It does not
probe paths, submit forms, bypass authentication, or attempt exploitation.

The scanner must use the original submitted query values to perform the requested
fetch. Those values exist only during that Worker invocation. Reports retain the
parameter names with `[redacted]` values so evidence remains understandable
without persisting signed URLs, reset tokens, OAuth codes, or session material.

If external reputation is enabled, the original and final URL, including query
values, are also sent to Google Web Risk and PhishTank because path and query
components can be material to a reputation match. The UI warns users not to
enable this for private, authenticated, password-reset, or token-bearing links.
Google Web Risk and PhishTank are separate processors under their own terms and
privacy policies.
PhishTank may record API request parameters and the source IP used for the
request. RequestScope therefore requires the same explicit opt-in for both URL
providers and never enables reputation automatically through REST or MCP.

The optional dependency map contacts crt.sh for Certificate Transparency history,
may inspect bounded public JavaScript bundles, and may check CT-discovered CNAME
records for known hosting signatures. It does not establish current TLS
certificate validity, authenticated visibility, PII transfer, or takeover
ownership. The report labels those signals as historical or heuristic and records
their coverage.

The optional Cloudflare URL Scanner action opens a pre-filled external page only
after a separate warning. RequestScope never submits that scan itself. Cloudflare
states that URL Scanner reports are retained and may be made public.

Reports are retained in D1 for the configured period, currently 14 days.
Validated scans, MCP tool calls, report reads, and provider quota accounting
are bounded and durable in D1 with hashed client keys. MCP handshake or
discovery messages do not write rate-limit rows.
