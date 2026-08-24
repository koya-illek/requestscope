import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { access, readFile, stat } from "node:fs/promises";
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
  // Submission-time validation and metering are HTTP-level for streamed
  // traces: invalid input, disallowed targets, and exhausted quotas are
  // rejected with real status codes before any NDJSON byte; only failures
  // discovered after streaming starts are in-band error events.
  const streamSection = openapi.slice(openapi.indexOf("/api/scans/stream:"), openapi.indexOf("  /api/scans/{reportId}:"));
  assert.ok(streamSection.includes("in-band as error events"));
  for (const status of ["'400'", "'403'", "'429'"]) {
    assert.ok(streamSection.includes(status), `stream contract must document ${status} pre-stream rejection`);
  }
  assert.ok(openapi.includes("claimedOrganisation:"));
  assert.ok(openapi.includes("cloudflare_family_dns"));
  assert.ok(openapi.includes("/mcp/v2:"));
  assert.ok(openapi.includes("ScanCoverage"));
  // Tool calls that supply params._meta.progressToken receive MCP progress
  // notifications over an SSE stream; the contract must document both
  // response shapes for the /mcp/v2 endpoint.
  const mcpSection = openapi.slice(openapi.indexOf("/mcp/v2:"), openapi.indexOf("components:"));
  for (const marker of ["notifications/progress", "text/event-stream", "progressToken"]) {
    assert.ok(mcpSection.includes(marker), `the /mcp/v2 contract must document ${marker}`);
  }
  // The Copilot connector import surface stays single-response JSON.
  assert.ok(!mcpConnector.includes("text/event-stream"));
  // Read endpoints answer HEAD probes with the GET headers and no body; the
  // published contract documents the probe operations.
  for (const probe of ["probeRequestScopeApi", "probeRequestScopeHealth", "probeRequestScopeReport", "probeRequestScopeExport"]) {
    assert.ok(openapi.includes(`operationId: ${probe}`), `openapi must document ${probe}`);
  }
  assert.ok(mcpConnector.includes("version: 2.2.0"));
  assert.ok(mcpConnector.includes("trace_request, assess_url_risk, and get_requestscope_report"));
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

test("the evidence report copies as Markdown through a line-break-safe fallback", async () => {
  const [html, app] = await Promise.all([read("index.html"), read("app.js")]);
  assert.match(html, /id="copy-markdown"/, "the report actions must offer a Markdown copy");
  assert.match(app, /function buildReportMarkdown/, "app.js must render the markdown brief from the stored report");
  // The manual-copy field is a textarea because input assignment strips line
  // breaks, which would silently corrupt a pasted markdown report.
  const linkDialog = html.slice(html.indexOf('id="link-dialog"'));
  assert.match(linkDialog, /<textarea id="link-field"[^>]*readonly>/, "the manual-copy field must preserve line breaks");
});

test("a stored report discloses its storage expiry on screen and in the brief", async () => {
  // Share recipients must learn how long the evidence stays retrievable from
  // the artifact itself, not from a 404 after expiry.
  const [html, app] = await Promise.all([read("index.html"), read("app.js")]);
  assert.match(html, /id="report-stored"/);
  assert.match(app, /function storedUntilText/);
  assert.equal(app.split("\n").filter((line) => line.includes("then deleted automatically")).length, 2, "screen note and markdown brief must share the expiry copy");
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
  await assert.doesNotReject(() => access(new URL("../web/fonts/inter-latin-wght-normal-v5.3.0.woff2", import.meta.url)));
  for (const page of [html, privacy]) {
    assert.match(page, /rel="preload" href="\.\/fonts\/inter-latin-wght-normal-v5\.3\.0\.woff2" as="font"/);
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

test("the page-observation signals are visible in the report and the brief", async () => {
  // pageSecuritySignals drive the risk engine's page_observation findings;
  // a report that cites them without showing them would hide its own evidence.
  const [html, app, styles] = await Promise.all([read("index.html"), read("app.js"), read("styles.css")]);
  assert.match(html, /id="page-signals"/, "index.html must carry the page-observation block");
  assert.match(app, /function renderPageSignals/, "app.js must render the captured page-security signals");
  assert.match(app, /## Page observation/, "the markdown brief must carry the same observation layer");
  assert.ok(styles.includes(".signal-chip"), "styles.css must style the signal chips");
});

test("shipped asset weights stay inside the performance budget", async () => {
  // The product ships no build step by design, so the budget is the guard:
  // raw bytes bound what a maintainer may add, and the gzip numbers bound
  // what a visitor transfers (Cloudflare compresses text assets).
  const budgets = [
    { file: "app.js", maxBytes: 52 * 1024, maxGzipBytes: 15.5 * 1024 },
    { file: "styles.css", maxBytes: 42 * 1024, maxGzipBytes: 11 * 1024 },
    { file: "fonts/inter-latin-wght-normal-v5.3.0.woff2", maxBytes: 52 * 1024 },
  ];
  let totalRaw = 0;
  for (const { file, maxBytes, maxGzipBytes } of budgets) {
    const size = (await stat(new URL(`../web/${file}`, import.meta.url))).size;
    totalRaw += size;
    assert.ok(size <= maxBytes, `${file} is ${size} bytes; budget is ${maxBytes}`);
    if (maxGzipBytes) {
      const gzipped = gzipSync(await readFile(new URL(`../web/${file}`, import.meta.url))).length;
      assert.ok(gzipped <= maxGzipBytes, `${file} gzips to ${gzipped} bytes; transfer budget is ${maxGzipBytes}`);
    }
  }
  assert.ok(totalRaw <= 148 * 1024, `combined payload is ${totalRaw} bytes; total budget is ${148 * 1024}`);
});

test("the evidence report survives printing to paper", async () => {
  const styles = await read("styles.css");
  const printBlock = styles.slice(styles.indexOf("@media print"));
  assert.ok(printBlock.length > 1, "styles.css must carry a print stylesheet");
  // The report is the printable artifact; application chrome must not spend
  // toner, and the dark palette must remap for white paper.
  for (const hidden of [".site-header", ".hero", ".developer-access", "footer", ".report-actions"]) {
    assert.ok(printBlock.includes(hidden), `print styles must hide ${hidden}`);
  }
  assert.match(printBlock, /--bg: #ffffff/, "print must remap the palette tokens for white paper");
  assert.match(printBlock, /break-inside: avoid/, "evidence rows must not split across pages");
});

test("static assets ship a tiered caching policy", async () => {
  // The shell deploys under stable URLs without a build step, so it must
  // revalidate every time; the versioned font is immutable; icons and
  // published contracts sit between those extremes.
  const headers = await read("_headers");
  const rules = headers.split(/\n(?=\S)/).map((block) => block.trim());
  const cacheControlFor = (pathLine) =>
    rules.find((block) => block.startsWith(pathLine))?.match(/Cache-Control: (.+)/)?.[1] || "";
  assert.equal(cacheControlFor("/fonts/*"), "public, max-age=31536000, immutable", "the versioned font must be immutable");
  for (const path of ["/favicon.svg", "/apple-touch-icon.svg", "/social-card.png", "/social-card.svg"]) {
    assert.match(cacheControlFor(path), /max-age=604800/, `${path} should be cacheable for a week`);
  }
  for (const path of ["/robots.txt", "/sitemap.xml", "/openapi.yaml", "/mcp-copilot.yaml"]) {
    assert.match(cacheControlFor(path), /max-age=3600/, `${path} should be cacheable for an hour`);
  }
  assert.ok(!headers.includes("/app.js"), "the app shell must not gain long-lived freshness while it has unhashed URLs");
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
