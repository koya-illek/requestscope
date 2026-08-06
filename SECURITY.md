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
- bounded JSON request reads, independent of `Content-Length`
- GET requests only
- no cookies forwarded between hops
- no user-controlled request headers
- daily client rate limits without raw IP retention
- redaction of every URL query value before persistence or sharing
- restrictive CORS and security headers

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
