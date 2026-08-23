import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
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
  assert.ok(html.includes("./privacy"));
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
  // Workers Assets redirects /privacy.html to /privacy, so every reference
  // must use the extensionless form that serves 200 directly.
  assert.ok(sitemap.includes("<loc>https://requestscope.illek.ie/privacy</loc>"));
  assert.ok(!sitemap.includes(".html</loc>"));
  assert.ok(openapi.includes("/api/health:"));
  assert.ok(openapi.includes("application/x-ndjson"));
  // Health responses have not exposed the deployment environment since the
  // payload change; the published schema must not require an absent field.
  assert.ok(!openapi.includes("environment: { type: string }"));
  assert.ok(!/required: \[[^\]]*environment/.test(openapi));
  // Streamed traces deliver blocked targets and rate limits as in-band NDJSON
  // error events; only validation and origin failures are HTTP-level.
  const streamSection = openapi.slice(openapi.indexOf("/api/scans/stream:"), openapi.indexOf("  /api/scans/{reportId}:"));
  assert.ok(streamSection.includes("in-band as error events"));
  assert.ok(!streamSection.includes("'429'"));
  assert.ok(openapi.includes("claimedOrganisation:"));
  assert.ok(openapi.includes("cloudflare_family_dns"));
  assert.ok(openapi.includes("/mcp/v2:"));
  assert.ok(openapi.includes("ScanCoverage"));
  assert.ok(!openapi.includes("text/event-stream"));
  // Read endpoints answer HEAD probes with the GET headers and no body; the
  // published contract documents the probe operations.
  for (const probe of ["probeRequestScopeApi", "probeRequestScopeHealth", "probeRequestScopeReport", "probeRequestScopeExport"]) {
    assert.ok(openapi.includes(`operationId: ${probe}`), `openapi must document ${probe}`);
  }
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
  // The privacy page is indexable and shareable: it must carry the same
  // metadata baseline as the shell (50-character description, OG/Twitter
  // card, and structured data).
  const privacyDescription = privacy.match(/name="description" content="([^"]+)"/)?.[1] || "";
  assert.ok(privacyDescription.length >= 50, "privacy meta description must be at least 50 characters");
  assert.ok(privacy.includes('property="og:title"'));
  assert.ok(privacy.includes('property="og:image"'));
  assert.ok(privacy.includes('name="twitter:card"'));
  assert.ok(privacy.includes('type="application/ld+json"'));
});

test("CSP forbids inline styles and no markup injects a style attribute", async () => {
  const [html, privacy, headers, app] = await Promise.all([
    read("index.html"),
    read("privacy.html"),
    read("_headers"),
    read("app.js"),
  ]);
  const csp = headers.match(/Content-Security-Policy: (.+)/)?.[1] || "";
  assert.match(csp, /style-src 'self'/);
  assert.ok(!csp.includes("unsafe-inline"), "style-src must not allow inline styles");
  assert.ok(!/<style[\s>]/i.test(html), "index.html must not carry a <style> element");
  assert.ok(!/<style[\s>]/i.test(privacy), "privacy.html must not carry a <style> element");
  // The timeline stagger is set via CSSOM; injected style=" attributes would
  // be blocked by the strict style-src policy.
  assert.ok(!app.includes('style="'), "app.js must not render inline style attributes");
});

test("consent-critical flows are designed dialogs, not blocking prompts", async () => {
  const [html, app] = await Promise.all([read("index.html"), read("app.js")]);
  assert.ok(html.includes('id="radar-dialog" aria-labelledby="radar-dialog-title"'), "Cloudflare Radar consent must be a labelled dialog");
  assert.ok(html.includes('id="link-dialog" aria-labelledby="link-dialog-title"'), "share-link fallback must be a labelled dialog");
  assert.ok(html.includes("may make them public"), "Radar dialog must retain the public-retention warning");
  assert.ok(app.includes("#radar-confirm") && app.includes("#radar-cancel"));
  assert.ok(!/\bconfirm\s*\(/.test(app), "app.js must not open blocking confirm() prompts");
  assert.ok(!/\bprompt\s*\(/.test(app), "app.js must not fall back to prompt()");
});

test("hash navigation only validates hashes that name no element on the page", async () => {
  const [app, html] = await Promise.all([read("app.js"), read("index.html")]);
  // The status pill and skip link change the hash to #status/#main-content;
  // treating every non-report hash as a broken report link would raise the
  // error panel on ordinary navigation. Both load paths must resolve element
  // ids first.
  const invalidLinkShows = app.split("\n").filter((line) => line.includes("looks incomplete or invalid"));
  assert.equal(invalidLinkShows.length, 2, "initial-load and hashchange paths must share the invalid-link copy");
  for (const line of invalidLinkShows) {
    const preceding = app.slice(0, app.indexOf(line));
    const branch = preceding.slice(preceding.lastIndexOf("} else if"));
    assert.match(
      branch,
      /document\.getElementById/,
      "every invalid-link branch must first rule out in-page anchors",
    );
  }
  assert.match(html, /<main id="main-content" tabindex="-1">/, "the main landmark must receive focus from the skip link");
});

test("the Inter variable font is self-hosted, preloaded, and CSP-allowed", async () => {
  const [html, privacy, headers, styles] = await Promise.all([
    read("index.html"),
    read("privacy.html"),
    read("_headers"),
    read("styles.css"),
  ]);
  await assert.doesNotReject(() => access(new URL("../web/fonts/inter-latin-wght-normal.woff2", import.meta.url)));
  for (const page of [html, privacy]) {
    assert.match(page, /rel="preload" href="\.\/fonts\/inter-latin-wght-normal\.woff2" as="font"/);
  }
  const csp = headers.match(/Content-Security-Policy: (.+)/)?.[1] || "";
  assert.match(csp, /font-src 'self'/);
  assert.match(styles, /@font-face/);
  assert.match(styles, /font-family: "Inter Variable";/);
  assert.ok(styles.indexOf("--sans: \"Inter Variable\"") !== -1, "Inter Variable must lead the sans stack");
});

test("the report UI renders each hop's captured response headers", async () => {
  const [app, styles] = await Promise.all([read("app.js"), read("styles.css")]);
  // Findings cite evidence paths like http.hops.1.responseHeaders.cache-control;
  // the shareable report must expose that evidence, not leave it in the export.
  assert.match(app, /function renderHopHeaders/);
  assert.ok(app.includes("hop-evidence"), "app.js must mark up the per-hop header evidence");
  assert.ok(app.includes("hop-header-list"), "app.js must render the header list");
  assert.ok(styles.includes(".hop-evidence"), "styles.css must style the hop evidence");
  assert.ok(styles.includes(".hop-header"), "styles.css must style individual header rows");
});

test("version identifiers live in one module and match package.json", async () => {
  const [pkg, version, index, analyzer, mcp] = await Promise.all([
    readFile(new URL("../api/package.json", import.meta.url), "utf8"),
    readFile(new URL("../api/src/version.ts", import.meta.url), "utf8"),
    readFile(new URL("../api/src/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../api/src/analyzer.ts", import.meta.url), "utf8"),
    readFile(new URL("../api/src/mcp.ts", import.meta.url), "utf8"),
  ]);
  const apiVersion = version.match(/export const API_VERSION = "([^"]+)"/)?.[1];
  const mcpVersion = version.match(/export const MCP_SERVER_VERSION = "([^"]+)"/)?.[1];
  assert.ok(apiVersion && mcpVersion, "version.ts must export both identifiers");
  assert.equal(JSON.parse(pkg).version, apiVersion);
  for (const source of [index, analyzer]) {
    assert.ok(!source.includes(`"${apiVersion}"`), "API version literal must only appear in version.ts");
  }
  assert.ok(!mcp.includes(`"${mcpVersion}"`), "MCP server version literal must only appear in version.ts");
});

test("README describes the published three-tool MCP server", async () => {
  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  assert.ok(readme.includes("`trace_request`, `assess_url_risk`, and"), "README must name all three tools");
  assert.ok(!/expose one tool/.test(readme), "README must not claim a single-tool MCP server");
});

test("release command derives provenance from a clean git revision", async () => {
  const [rootPackage, apiPackage, wrangler, deploy] = await Promise.all([
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../api/package.json", import.meta.url), "utf8"),
    readFile(new URL("../api/wrangler.toml", import.meta.url), "utf8"),
    readFile(new URL("../api/scripts/deploy.mjs", import.meta.url), "utf8"),
  ]);
  assert.equal(JSON.parse(rootPackage).scripts["deploy:api"], "npm --workspace api run deploy --");
  assert.equal(JSON.parse(apiPackage).scripts.deploy, "node scripts/deploy.mjs");
  assert.ok(!/^SOURCE_REVISION\s*=/m.test(wrangler), "wrangler.toml must not carry a stale source revision");
  assert.ok(deploy.includes('git(["status", "--porcelain=v1", "--untracked-files=all"])'));
  assert.ok(deploy.includes('git(["rev-parse", "--short=12", "HEAD"])'));
  assert.ok(deploy.includes("SOURCE_REVISION:${revision}"));
});
