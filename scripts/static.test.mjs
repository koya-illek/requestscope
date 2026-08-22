import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const read = (name) => readFile(new URL(`../web/${name}`, import.meta.url), "utf8");

test("public shell exposes metadata, keyboard navigation and privacy", async () => {
  const [html, headers, robots, sitemap, openapi, mcpConnector, favicon, appleIcon, privacy] = await Promise.all([
    read("index.html"),
    read("_headers"),
    read("robots.txt"),
    read("sitemap.xml"),
    read("openapi.yaml"),
    read("mcp-copilot.yaml"),
    read("favicon.svg"),
    read("apple-touch-icon.svg"),
    read("privacy.html")
  ]);
  assert.match(html, /rel="canonical"/);
  assert.match(html, /property="og:image"/);
  assert.match(html, /<script type="application\/ld\+json">/);
  assert.match(html, /rel="icon"/);
  assert.doesNotMatch(html, /class="(?:eyebrow|section-kicker)"/);
  assert.doesNotMatch(html, /—/);
  assert.match(html, /Skip to URL trace/);
  assert.ok(html.includes("./privacy.html"));
  assert.ok(html.includes("Include external reputation"));
  assert.ok(html.includes("Advanced trace options"));
  assert.ok(html.includes("Cloudflare's malware-filtering DNS receives hostnames only"));
  assert.ok(html.includes("Google Web Risk and PhishTank receive the complete original and final URL"));
  assert.ok(html.includes("How RequestScope works"));
  assert.ok(html.includes("Check reputation with consent"));
  assert.ok(html.includes("Scan on Cloudflare Radar"));
  assert.ok(html.includes("<noscript>"));
  assert.ok(html.includes('id="query-warning" role="status"'));
  assert.ok(html.includes('aria-labelledby="method-dialog-title"'));
  assert.ok(html.includes('aria-pressed="true"'));
  assert.ok(html.includes('aria-pressed="false"'));
  assert.ok(headers.includes("static.cloudflareinsights.com"));
  assert.ok(!html.includes("challenges.cloudflare.com"));
  assert.ok(!html.includes("turnstile-widget"));
  assert.ok(!headers.includes("challenges.cloudflare.com"));
  assert.match(robots, /Sitemap:/);
  assert.ok(sitemap.includes("requestscope.illek.ie"));
  assert.ok(openapi.includes("/api/health:"));
  assert.ok(openapi.includes("application/x-ndjson"));
  assert.ok(openapi.includes("claimedOrganisation:"));
  assert.ok(openapi.includes("cloudflare_family_dns"));
  assert.ok(openapi.includes("/mcp/v2:"));
  assert.ok(openapi.includes("ScanCoverage"));
  assert.ok(!openapi.includes("text/event-stream"));
  assert.ok(mcpConnector.includes("version: 2.2.0"));
  assert.ok(mcpConnector.includes("trace_request, assess_url_risk, and get_requestscope_report"));
  assert.ok(!mcpConnector.includes("text/event-stream"));
  assert.ok(favicon.includes("RequestScope"));
  assert.ok(appleIcon.includes("RequestScope"));
  assert.ok(privacy.includes("Cloudflare's malware-filtering DNS"));
  assert.ok(privacy.includes("Certificate Transparency"));
  assert.ok(privacy.includes("Raw page bodies"));
  assert.match(privacy, /report reads use bounded daily counters/);
  assert.ok(!privacy.includes("report reads and MCP handshake or discovery requests do not write"));
  assert.doesNotMatch(privacy, /class="(?:eyebrow|section-kicker)"/);
  assert.doesNotMatch(privacy, /—/);
});
