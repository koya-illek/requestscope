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
- eight-hop redirect limit
- ten-second timeout per request
- bounded response reads
- GET requests only
- no cookies forwarded between hops
- no user-controlled request headers
- daily client rate limits without raw IP retention
- restrictive CORS and security headers

DNS rebinding cannot be eliminated perfectly when fetching by hostname on an
edge runtime. Cloudflare's fetch isolation is therefore part of the trust
boundary. Deployments should retain the public-address checks, strict port
allowlist, and low request limits.

RequestScope is a diagnostic observer, not a vulnerability scanner. It does not
probe paths, submit forms, bypass authentication, or attempt exploitation.
