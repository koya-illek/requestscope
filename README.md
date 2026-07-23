# RequestScope

RequestScope shows every observable step between a URL and the page it delivers.
It performs an evidence-labelled DNS and HTTP trace, follows redirects manually,
inspects response and cache behaviour, extracts bounded HTML resource references,
and creates a privacy-redacted shareable report.

## Architecture

```text
Cloudflare Pages                         Cloudflare Worker
┌───────────────────────┐               ┌─────────────────────────┐
│ Static application    │── HTTPS ─────▶│ Validation + rate limit │
│ Interactive timeline  │               │ DNS-over-HTTPS          │
│ Findings + raw data   │◀──────────────│ Manual HTTP trace       │
└───────────────────────┘               │ Evidence engine         │
                                        └────────────┬────────────┘
                                                     │
                                                     ▼
                                               Cloudflare D1
                                             shareable reports
```

The Worker never claims to measure browser DNS, TCP, or TLS timings. HTTP
timings are observations from Cloudflare's network. DNS results are separate
DNS-over-HTTPS observations. Browser rendering is a planned, separately
labelled observation mode.

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and
[PLAN.md](PLAN.md).

## Local development

```bash
npm install
npm run typecheck
npm test
cd api && npx wrangler dev --local --persist-to ../.wrangler/state
```

Serve `web/` with any static web server and set its API endpoint in
`web/config.js`.

## API

```text
GET  /api/health
GET  /api
POST /api/scans       {"url":"https://example.com","turnstileToken":"..."}
POST /api/scans/stream  NDJSON progress stream and final report
GET  /api/scans/:id
GET  /api/scans/:id/export
```

The Worker root redirects human visitors to the Pages application.

Reports expire after 14 days by default. No raw visitor IP address is stored.
Query parameter names are retained for evidence, but their values are redacted
before reports enter D1, responses, exports, or share links.
