# RequestScope

RequestScope shows every observable step between a URL and the page it delivers.
It performs an evidence-labelled DNS and HTTP trace, follows redirects manually,
inspects response and cache behaviour, extracts bounded HTML resource references,
creates a privacy-redacted shareable report, and produces an explainable URL
security risk assessment suitable for people or Copilot agents.

## Architecture

```text
Cloudflare Worker
┌─────────────────────────────────────────────┐
│ Static application assets                  │
│ Validation + privacy-preserving rate limit │
│ DNS-over-HTTPS + manual HTTP trace         │
│ Evidence + optional reputation adapters    │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
                 Cloudflare D1
               reports + quotas
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
POST /api/scans       {"url":"https://example.com","externalReputation":false}
POST /api/scans/stream  NDJSON progress stream and final report
POST /api/v1/url-risk {"url":"https://example.com","claimedOrganisation":"Microsoft","messageContext":"Password reset email"}
POST /mcp              Streamable HTTP MCP (also available at /mcp/v2)
GET  /api/scans/:id
GET  /api/scans/:id/export
```

Read endpoints also answer HEAD probes (`curl -I` health checks) with the GET
headers and no body.

`POST /api/v1/url-risk` is the stable, compact integration contract for
Microsoft Copilot custom connectors and other automation. It follows redirects
and returns a low, medium, or high assessment with scored evidence for URL
structure, shorteners, cross-domain redirects, Unicode and brand lookalikes,
known service ownership, password/forms, and sensitive-action language. Raw
HTML and raw message context are never returned to the agent. See
[`web/openapi.yaml`](web/openapi.yaml) for the connector definition.

For an authenticated Copilot deployment, set the Worker secret
`COPILOT_API_KEY` and configure the custom connector to send it as a Bearer
token. If the secret is absent, the endpoint remains available under the same
anonymous daily rate limit as normal scans.

A low assessment means that RequestScope did not observe strong indicators; it
does not certify that a URL is safe. External reputation is opt-in because the
original and final URL are sent to Google Web Risk and PhishTank. Only provider,
status, hostname, threat categories, timestamps, and attribution are retained;
raw provider responses and unredacted URLs are not stored in reports.

Cloudflare's 1.1.1.1 for Families malware resolver is also available as a
supplementary domain-level signal. It receives only the requested and final
hostnames over DNS-over-HTTPS, never the full URL or query string.

Configure providers as Worker secrets after accepting their terms:

```bash
cd api
npx wrangler d1 execute requestscope --remote --file schema.sql
npx wrangler secret put GOOGLE_WEB_RISK_API_KEY
npx wrangler secret put PHISHTANK_APP_KEY
cd ..
npm run deploy:api
```

The deploy command refuses a dirty working tree and binds the current 12-character
git revision as `SOURCE_REVISION`. Use `npm run deploy:api -- --dry-run` to inspect
the Worker bundle and bindings without publishing it.

PhishTank currently permits API calls without an application key, but assigns a
lower provider-side request limit. Set `PHISHTANK_KEYLESS_ENABLED = "true"` and
use a conservative `PHISHTANK_DAILY_LIMIT` when registration is unavailable.
An application key, when available, automatically replaces keyless mode.
Verify keyless access from the deployed Worker before leaving it enabled;
PhishTank may apply an automated browser challenge unless the request uses its
documented `phishtank/<identifier>` User-Agent form.

Google Web Risk Lookup has an application-enforced default ceiling of 90,000
requests per calendar month, below its 100,000-request free allowance.
PhishTank has a separate application-enforced daily ceiling. Provider results are
cached, and only the submitted and final URL are eligible for lookup.

The UI also offers a separate public deep-scan handoff to Cloudflare Radar. It
does not submit automatically and warns that Cloudflare retains scan reports
and may make them public.

## MCP for Copilot and ChatGPT agents

The Worker exposes a stateless Streamable HTTP MCP server at:

```text
https://requestscope.illek.ie/mcp
https://requestscope.illek.ie/mcp/v2
```

Both URLs expose `trace_request`, `assess_url_risk`, and
`get_requestscope_report`, all backed by exactly the same scan and scoring
engine as the REST endpoint. `/mcp/v2` is a versioned RequestScope alias; the
negotiated MCP protocol version is `2025-11-25`.

- Copilot Studio: import [`web/mcp-copilot.yaml`](web/mcp-copilot.yaml), or enter the
  `/mcp` URL through its MCP onboarding wizard.
- OpenAI Responses API: configure a remote MCP tool with `server_url` set to
  the `/mcp` URL and allow the `assess_url_risk` tool.
- OpenAPI agents/custom connectors: import [`web/openapi.yaml`](web/openapi.yaml) and
  call `/api/v1/url-risk` directly.

The REST endpoints intentionally remain open for initial testing and share the
anonymous daily scan limit; MCP tool calls are metered by their own durable
`MCP_DAILY_LIMIT` instead of consuming anonymous scan quota, so configuring one
limit does not require raising the other. Before wider MSP use, set
`COPILOT_API_KEY`; both interfaces then require `Authorization: Bearer ...`.

The static `web/` application is served directly from the same Worker through
Cloudflare Workers Assets; there is no separate Pages deployment and no root
redirect.

Reports expire after 14 days by default. No raw visitor IP address is stored.
Query parameter names are retained for evidence, but their values are redacted
before reports enter D1, responses, exports, or share links.

Anonymous daily limits (scans, MCP tool calls, and report retrievals) are
durable in D1 and keyed by a one-way hash of the calendar date and client IP,
so repeats cannot reset them by moving between edge locations. Each request
counts against exactly one scope: REST scans against the scan limit, MCP tool
calls against `MCP_DAILY_LIMIT`, report retrievals against
`REPORT_DAILY_LIMIT`. A repeat scan of a recently traced URL still counts
against the daily scan limit even when the cached result is returned.

The site owner can exempt trusted source IPs from scan and MCP scan limits by
setting the `RATE_LIMIT_BYPASS_IPS` Worker secret to a comma-separated list.
This value must never be placed in `wrangler.toml`; report retrieval limits and
all upstream provider quotas still apply.
