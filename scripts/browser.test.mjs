import assert from "node:assert/strict";
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";
import { createServer } from "node:http";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";

const webRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "web");
const browser = await chromium.launch({ executablePath: "/snap/bin/chromium", headless: true });
const report = {
  schemaVersion: 1,
  id: "abcdefghijklmnop",
  requestedUrl: "https://micros0ft.example/login",
  normalizedUrl: "https://micros0ft.example/login",
  finalUrl: "https://micros0ft.example/login",
  hostname: "micros0ft.example",
  status: "complete",
  createdAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 86400000).toISOString(),
  totalDurationMs: 143,
  observation: { vantage: "cloudflare-edge", colo: "DUB", country: "IE", disclaimer: "Edge observation." },
  dns: { queries: [], addresses: ["93.184.216.34"], dnssecAuthenticated: false },
  http: {
    hops: [
      { index: 0, url: "https://micros0ft.example/login", hostname: "micros0ft.example", status: 302, statusText: "Found", elapsedMs: 41, location: "https://micros0ft.example/signin", responseHeaders: { location: "https://micros0ft.example/signin", server: "nginx", "cache-control": "private, max-age=0" }, cf: {}, evidenceKind: "edge_http_observation" },
      { index: 1, url: "https://micros0ft.example/signin", hostname: "micros0ft.example", status: 200, statusText: "OK", elapsedMs: 102, location: null, responseHeaders: { "content-type": "text/html; charset=utf-8", "strict-transport-security": "max-age=31536000", "x-frame-options": "DENY" }, cf: { colo: "DUB", tlsVersion: "TLSv1.3" }, evidenceKind: "edge_http_observation" },
    ],
    finalStatus: 200, contentType: "text/html", contentBytesInspected: 1200, truncated: false,
  },
  pageSecuritySignals: { passwordForm: true, forms: 1, externalFormAction: false, matchedLanguage: ["login"] },
  coverage: {
    status: "partial",
    budget: {},
    phases: {
      core: { status: "complete", attempted: 4, successful: 4, failed: 0, skipped: 0, bytesInspected: 1200, truncated: false, durationMs: 143 },
      dependencies: { status: "unavailable", attempted: 0, successful: 0, failed: 0, skipped: 0, bytesInspected: 0, truncated: false, durationMs: 0, detail: "dependencies: requested but the trace had no inspectable final response." },
      reputation: { status: "skipped", attempted: 0, successful: 0, failed: 0, skipped: 1, bytesInspected: 0, truncated: false, durationMs: 0, detail: "reputation: not requested." },
    },
  },
  dependencies: { total: 0, firstParty: 0, thirdParty: 0, uniqueHosts: [], items: [] },
  dependencyMap: {
    createdAt: new Date().toISOString(),
    durationMs: 210,
    sources: {
      csp: { present: false, directives: {}, domains: [] },
      jsBundles: { attempted: 1, successful: 1, failed: 0, skipped: 0, bundlesFetched: 1, totalBytes: 20480, truncated: false, domains: ["google-analytics.com"], patterns: [] },
      certTransparency: { subdomains: [], total: 0 },
    },
    domains: [
      { domain: "google-analytics.com", category: "analytics", serviceName: "Google Analytics", source: "multiple", piiRisk: true, postAuthOnly: false, occurrences: 2, evidence: ["js bundle"] },
    ],
    sdks: [{ name: "Google Analytics", domain: "google-analytics.com", category: "analytics", match: "ga('create'" }],
    ssl: { source: "certificate_transparency", protocol: null, cipher: null, issuer: null, subject: null, validFrom: "2024-01-01T00:00:00Z", validTo: "2026-01-01T00:00:00Z", daysUntilExpiry: null, authorityKeyIdentifier: null },
    takeover: [{ subdomain: "stale.micros0ft.example", cname: "ghost.io", resolvable: false, httpStatus: null, vulnerable: true, evidence: "CNAME points to an unclaimed hosting bucket." }],
    summary: { totalDomains: 2, byCategory: { analytics: 2 }, piiRisk: 1, postAuthOnly: 1 },
  },
  findings: [
    { code: "security-headers-present", severity: "positive", title: "Core response headers observed", detail: "The final response included HSTS.", evidencePath: "http.hops.1.responseHeaders.strict-transport-security", confidence: "high", evidenceKind: "derived_finding" },
  ],
  summary: { critical: 0, warning: 0, positive: 0, info: 1 },
  urlRisk: {
    schemaVersion: 1, verdict: "high", riskScore: 66, confidence: "high",
    summary: "Strong risk indicators were observed. Review the evidence before visiting or entering information.",
    requestedUrl: "https://micros0ft.example/login", finalUrl: "https://micros0ft.example/login",
    traceId: "abcdefghijklmnop", reportPath: "/api/scans/abcdefghijklmnop", claimedOrganisation: "Microsoft", services: [],
    findings: [
      { code: "brand-lookalike", severity: "high", score: 38, title: "Possible Microsoft lookalike", detail: "The hostname resembles Microsoft but is not a recognised domain.", evidence: {}, confidence: "high", source: "requestscope" },
      { code: "password-form", severity: "high", score: 28, title: "Password field observed", detail: "The page contains a password field on a deceptive hostname.", evidence: {}, confidence: "high", source: "page_observation" },
    ],
    reputation: {
      status: "matched",
      detail: "At least one provider identifies a checked URL as potentially unsafe.",
      consentRequired: true,
      providers: [{
        provider: "google_web_risk", target: "requested", hostname: "micros0ft.example", status: "matched",
        threatTypes: ["SOCIAL_ENGINEERING"], detail: "Google Web Risk lists this URL for social engineering.",
        checkedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 900000).toISOString(),
        advisoryUrl: "https://docs.cloud.google.com/web-risk/docs/advisory", attribution: "Advisory provided by Google",
      }],
    },
    limitations: ["A low rating is not proof that a URL is safe."],
  },
};

for (const viewport of [{ width: 1440, height: 1000 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
  const context = await browser.newContext({ viewport });
  const page = await context.newPage();
  let submittedExternalReputation = false;
  await page.route("**/api/scans/stream", async (route) => {
    submittedExternalReputation = route.request().postDataJSON().externalReputation === true;
    const events = ["accepted", "validated", "dns", "hop", "response", "deps-complete", "reputation", "complete"]
      .map((stage) => JSON.stringify({ type: "progress", stage, message: `Stage ${stage}` }));
    const body = `${events.join("\n")}\n${JSON.stringify({ type: "result", report })}\n`;
    await route.fulfill({ status: 200, contentType: "application/x-ndjson", body });
  });
  await page.goto(pathToFileURL(path.resolve(webRoot, "index.html")).href);
  await page.fill("#url-input", "https://micros0ft.example/login");
  await page.locator(".trace-options > summary").click();
  await page.locator(".risk-context > summary").click();
  await page.fill("#claimed-organisation", "Microsoft");
  await page.fill("#message-context", "Password reset email");
  await page.check("#map-deps");
  await page.check("#external-reputation");
  await page.click("#trace-button");
  await page.waitForSelector("#risk-verdict.high", { state: "visible" });
  assert.equal(await page.textContent("#risk-verdict"), "HIGH · 66/100");
  assert.equal(await page.locator(".risk-finding").count(), 2);
  assert.equal(submittedExternalReputation, true);
  assert.deepEqual(await page.locator("#progress-steps li").allTextContents(), [
    "Validate target", "Resolve DNS", "Follow redirects", "Inspect page", "Map dependencies", "Check reputation", "Build report"
  ]);
  assert.deepEqual(await page.locator("#live-route .route-node strong").allTextContents(), ["INPUT", "DNS", "EDGE", "PAGE", "MAP", "REP", "REPORT"]);
  assert.equal(await page.locator('#live-route .route-node[data-stage="reputation"]').getAttribute("class"), "route-node done");
  assert.equal(await page.textContent("#reputation-results a"), "Advisory provided by Google");
  // The replay stagger must be applied through CSSOM (the CSP forbids inline
  // style attributes), so the property is set while the markup stays clean.
  const stagger = await page.evaluate(() =>
    [...document.querySelectorAll("#timeline .hop.replay")].map((element) => element.style.animationDelay));
  assert.deepEqual(stagger, ["0ms", "130ms"]);
  // Every hop's captured response headers must be inspectable: findings cite
  // evidence paths into http.hops[].responseHeaders, so the UI has to show
  // that evidence rather than leaving it only in the JSON export.
  assert.equal(await page.locator("#timeline .hop-evidence").count(), 2);
  assert.equal(await page.textContent("#timeline .hop-evidence summary"), "Response headers 3 recorded");
  // The page-observation layer the risk engine consumed must be visible:
  // password field, form count, on-site submission, and matched language.
  await page.waitForSelector("#page-signals:not(.hidden)");
  const signals = await page.textContent("#page-signals");
  assert.match(signals, /Page observation/);
  assert.match(signals, /1 form detected/);
  assert.match(signals, /Password field observed/);
  assert.match(signals, /Forms submit on-site/);
  assert.match(signals, /Sign-in language/);
  // Coverage statuses are contract enums; the observation note must phrase
  // them for readers instead of surfacing raw tokens like "unavailable".
  const observationNote = await page.textContent("#observation-note");
  assert.match(observationNote, /Coverage: core trace complete, dependency map could not run, reputation checks not requested\./);
  // A derived finding's evidence citation must be a working link to the
  // captured evidence: activating it opens the cited hop's header list and
  // flashes the exact row, instead of leaving the path as inert text.
  await page.click("#findings .evidence-link");
  await page.waitForFunction(() =>
    Boolean(document.querySelector('#timeline [data-evidence="http.hops.1.responseHeaders.strict-transport-security"]')?.classList.contains("evidence-flash")));
  assert.equal(await page.locator('#timeline .hop:nth-child(2) .hop-evidence[open]').count(), 1,
    "the citation must open the cited hop's recorded headers");
  const flashClass = await page.getAttribute('#timeline [data-evidence="http.hops.1.responseHeaders.strict-transport-security"]', "class");
  assert.ok(flashClass.includes("evidence-flash"), "the cited header row must be flashed");
  await page.locator("#timeline .hop:first-child .hop-evidence summary").click();
  const redirectHeaders = await page.locator("#timeline .hop:first-child .hop-header dt").allTextContents();
  assert.deepEqual(redirectHeaders, ["location", "server", "cache-control"]);
  assert.equal(
    await page.locator("#timeline .hop:first-child .hop-header dd").first().textContent(),
    "https://micros0ft.example/signin",
  );
  await page.click("#footer-method-button");
  await page.waitForSelector("#method-dialog[open]");
  assert.equal(await page.textContent("#method-dialog h2"), "How RequestScope works");
  assert.match(await page.textContent("#method-dialog"), /Google Web Risk and PhishTank/);
  await page.click("#dialog-close");
  await page.waitForSelector("#cloudflare-scan", { state: "visible" });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert.equal(overflow, false, `${viewport.width}px layout has horizontal overflow`);
  const accessibility = await new AxeBuilder({ page }).analyze();
  assert.deepEqual(
    accessibility.violations.map(({ id, impact, nodes }) => ({
      id,
      impact,
      targets: nodes.map((node) => node.target),
    })),
    [],
    `${viewport.width}px layout has accessibility violations`,
  );
  await page.screenshot({ path: `/tmp/requestscope-risk-${viewport.width}.png`, fullPage: true });
  await context.close();
}

// The privacy notice is a canonical product page, so it receives the same
// responsive, keyboard, and automated accessibility checks as the trace UI.
for (const viewport of [{ width: 1440, height: 1000 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
  const context = await browser.newContext({ viewport });
  const page = await context.newPage();
  await page.goto(pathToFileURL(path.resolve(webRoot, "privacy.html")).href);
  assert.equal(await page.locator("h1").textContent(), "RequestScope privacy notice");
  await page.keyboard.press("Tab");
  assert.equal(await page.evaluate(() => document.activeElement?.classList.contains("skip-link")), true);
  assert.equal(await page.locator(".skip-link").textContent(), "Skip to privacy notice");
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert.equal(overflow, false, `${viewport.width}px privacy layout has horizontal overflow`);
  const accessibility = await new AxeBuilder({ page }).analyze();
  assert.deepEqual(accessibility.violations, [], `${viewport.width}px privacy layout has accessibility violations`);
  await page.screenshot({ path: `/tmp/requestscope-privacy-${viewport.width}.png`, fullPage: true });
  await context.close();
}

// Phase 3: serve the shell over HTTP with the production CSP header and fail
// on any console or page error, so a policy change cannot break the app
// unnoticed before deploy.
const headersFile = await readFile(path.join(webRoot, "_headers"), "utf8");
const csp = headersFile.match(/Content-Security-Policy: (.+)/)?.[1];
assert.ok(csp, "_headers must declare a Content-Security-Policy");
assert.ok(!csp.includes("unsafe-inline"));
const contentTypes = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".png": "image/png" };
const server = createServer(async (request, response) => {
  const urlPath = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  const filePath = path.join(webRoot, urlPath === "/" ? "index.html" : urlPath);
  try {
    const data = await readFile(filePath);
    response.writeHead(200, {
      "Content-Type": contentTypes[path.extname(filePath)] || "application/octet-stream",
      "Content-Security-Policy": csp,
    });
    response.end(data);
  } catch {
    response.writeHead(404);
    response.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const cspContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const cspPage = await cspContext.newPage();
const violations = [];
cspPage.on("console", (message) => {
  if (message.type() === "error") violations.push(message.text());
});
cspPage.on("pageerror", (error) => violations.push(String(error)));
await cspPage.route("**/api/**", async (route) => {
  const { pathname } = new URL(route.request().url());
  if (pathname === "/api/health") {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, reputationProviders: { googleWebRisk: true, phishTank: true, cloudflareFamilyDns: true } }) });
    return;
  }
  const events = ["accepted", "validated", "dns", "hop", "response", "complete"]
    .map((stage) => JSON.stringify({ type: "progress", stage, message: `Stage ${stage}` }));
  await route.fulfill({
    status: 200,
    contentType: "application/x-ndjson",
    body: `${events.join("\n")}\n${JSON.stringify({ type: "result", report })}\n`,
  });
});
await cspPage.goto(`http://127.0.0.1:${server.address().port}/`);
await cspPage.fill("#url-input", "https://micros0ft.example/login");
await cspPage.click("#trace-button");
await cspPage.waitForSelector("#risk-verdict.high", { state: "visible" });
const appliedDelay = await cspPage.evaluate(() =>
  document.querySelector("#timeline .hop.replay")?.style.animationDelay || "");
assert.equal(appliedDelay, "0ms");
assert.deepEqual(violations, [], `strict CSP run produced console/page errors: ${violations.join(" | ")}`);

// Regression: "Start a new trace" must clear every optional control and keep
// its selection summary in sync with what the next submission would send.
await cspPage.locator(".trace-options > summary").click();
await cspPage.locator(".risk-context > summary").click();
await cspPage.fill("#claimed-organisation", "Microsoft");
await cspPage.check("#map-deps");
await cspPage.click("#trace-button");
await cspPage.waitForSelector("#report:not(.hidden)");
await cspPage.click("#new-trace");
assert.equal(await cspPage.inputValue("#claimed-organisation"), "");
assert.equal(await cspPage.isChecked("#map-deps"), false);
assert.equal(await cspPage.isChecked("#external-reputation"), false);
assert.equal(await cspPage.textContent("#trace-options-state"), "Optional");

// With clipboard access granted, Copy as Markdown must write the brief
// directly and confirm on the button.
await cspPage.fill("#url-input", "https://micros0ft.example/login");
await cspPage.click("#trace-button");
await cspPage.waitForSelector("#risk-verdict.high", { state: "visible" });
await cspContext.grantPermissions(["clipboard-read", "clipboard-write"], { origin: `http://127.0.0.1:${server.address().port}` });
await cspPage.click("#copy-markdown");
await cspPage.waitForFunction(() => document.querySelector("#copy-markdown")?.textContent === "Copied");
const clipboardMarkdown = await cspPage.evaluate(() => navigator.clipboard.readText());
assert.match(clipboardMarkdown, /^# RequestScope report: micros0ft\.example/);
assert.match(clipboardMarkdown, /\*\*Verdict:\*\* HIGH · 66\/100 \(high confidence\)/);
assert.match(clipboardMarkdown, /## Request path/);
await cspContext.close();
server.close();

// Phase 4: the share flow. Loading #<reportId> must fetch and render the saved
// report without pushing history or losing focus discipline, an invalid hash
// must surface the INVALID_LINK notice, and dismissing it must clear the hash.
const linkContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const linkPage = await linkContext.newPage();
let savedReportFetches = 0;
let conditionalHits = 0;
await linkPage.route("**/api/health", async (route) => {
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, reputationProviders: {} }) });
});
await linkPage.route("**/api/scans/abcdefghijklmnop*", async (route) => {
  // Stored reports are immutable, so a repeat load that echoes the strong
  // ETag is answered with 304 and no evidence body.
  if (route.request().headers()["if-none-match"] === '"abcdefghijklmnop"') {
    conditionalHits += 1;
    await route.fulfill({ status: 304, headers: { ETag: '"abcdefghijklmnop"' } });
    return;
  }
  savedReportFetches += 1;
  await route.fulfill({ status: 200, contentType: "application/json", headers: { ETag: '"abcdefghijklmnop"' }, body: JSON.stringify(report) });
});
await linkPage.goto(`${pathToFileURL(path.resolve(webRoot, "index.html")).href}#abcdefghijklmnop`);
await linkPage.waitForSelector("#risk-verdict.high", { state: "visible" });
assert.equal(await linkPage.textContent("#risk-verdict"), "HIGH · 66/100");
// The saved report must disclose how long it stays retrievable.
assert.match(await linkPage.textContent("#report-stored"), /^Stored until .+, then deleted automatically\.$/);
assert.equal(savedReportFetches, 1);
assert.equal(await linkPage.title(), "micros0ft.example: RequestScope");
assert.equal(await linkPage.evaluate(() => document.activeElement?.id), "report-host");
assert.equal(await linkPage.evaluate(() => location.hash), "#abcdefghijklmnop");

// Leaving and returning to the same share link inside one session must
// revalidate the immutable report instead of downloading it twice.
await linkPage.evaluate(() => { location.hash = ""; });
await linkPage.waitForSelector("#report.hidden", { state: "attached" });
await linkPage.evaluate(() => { location.hash = "abcdefghijklmnop"; });
await linkPage.waitForSelector("#risk-verdict.high", { state: "visible" });
assert.equal(await linkPage.textContent("#risk-verdict"), "HIGH · 66/100", "the 304 path must still render the stored report");
assert.equal(conditionalHits, 1, "the repeat load must send If-None-Match and receive 304");
assert.equal(savedReportFetches, 1, "the evidence body must be downloaded once per session");

// Regression: with no reputation provider configured, the health check must
// disable the consent checkbox and replace its copy instead of letting the
// visitor enable a lookup that cannot run.
await linkPage.waitForFunction(() => document.querySelector("#external-reputation")?.disabled === true);
assert.equal(await linkPage.textContent("#reputation-toggle-text strong"), "External reputation unavailable");
assert.equal(
  await linkPage.textContent("#reputation-toggle-text small"),
  "Provider credentials are not configured on this deployment.",
);
await linkPage.evaluate(() => { location.hash = "not-a-report-id"; });
await linkPage.waitForSelector("#error-panel:not(.hidden)");
assert.equal(await linkPage.textContent("#error-code"), "INVALID_LINK");
await linkPage.click("#error-close");
assert.equal(await linkPage.locator("#error-panel.hidden").count(), 1);
await linkPage.evaluate(() => location.hash = "");

// In-page anchors (status pill, skip link, section targets) also change the
// hash; they are navigation, so they must never raise the invalid-link error.
await linkPage.click(".status-link");
await linkPage.waitForFunction(() => location.hash === "#status");
await linkPage.waitForTimeout(50);
assert.equal(await linkPage.locator("#error-panel:not(.hidden)").count(), 0, "the status pill must not raise the invalid-link error");
await linkPage.evaluate(() => location.hash = "#main-content");
await linkPage.waitForTimeout(50);
assert.equal(await linkPage.locator("#error-panel:not(.hidden)").count(), 0, "skip-link navigation must not raise the invalid-link error");
// The skip link must move sequential focus to the main landmark.
await linkPage.goto(pathToFileURL(path.resolve(webRoot, "index.html")).href);
await linkPage.keyboard.press("Tab");
await linkPage.keyboard.press("Enter");
await linkPage.waitForFunction(() => document.activeElement?.id === "main-content");
await linkContext.close();

// The submit control must agree with the inFlight guard while a shared
// report loads: runTrace bails silently during a load, so an enabled button
// would turn Enter into an invisible no-op.
const loadGuardContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const loadGuardPage = await loadGuardContext.newPage();
await loadGuardPage.route("**/api/health", async (route) => {
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, reputationProviders: {} }) });
});
let releaseSlowReport = () => {};
const slowReport = new Promise((resolve) => { releaseSlowReport = resolve; });
let slowReportServed = false;
await loadGuardPage.route("**/api/scans/abcdefghijklmnop", async (route) => {
  await slowReport.catch(() => {});
  slowReportServed = true;
  try {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(report) });
  } catch {
    // The context may already be gone.
  }
});
await loadGuardPage.goto(`${pathToFileURL(path.resolve(webRoot, "index.html")).href}#abcdefghijklmnop`);
await loadGuardPage.waitForFunction(() => document.querySelector("#trace-button")?.disabled === true);
assert.equal(slowReportServed, false, "report body must not arrive before the guard is observed");
releaseSlowReport();
await loadGuardPage.waitForSelector("#risk-verdict.high", { state: "visible" });
assert.equal(await loadGuardPage.locator("#trace-button[disabled]").count(), 0);
await loadGuardContext.close();

// The Cloudflare Radar handoff is consent-critical, so it is a designed
// dialog: cancel opens nothing, confirm hands the exact URL to Radar in a
// new browsing context.
const radarContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const radarPage = await radarContext.newPage();
await radarPage.route("**/api/health", async (route) => {
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, reputationProviders: {} }) });
});
await radarPage.route("**/api/scans/stream", async (route) => {
  const events = ["accepted", "validated", "dns", "hop", "response", "complete"]
    .map((stage) => JSON.stringify({ type: "progress", stage, message: `Stage ${stage}` }));
  await route.fulfill({
    status: 200,
    contentType: "application/x-ndjson",
    body: `${events.join("\n")}\n${JSON.stringify({ type: "result", report })}\n`,
  });
});
await radarPage.addInitScript(() => {
  window.__radarPopups = [];
  window.open = (url) => { window.__radarPopups.push(String(url)); return null; };
  Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
});
await radarPage.goto(pathToFileURL(path.resolve(webRoot, "index.html")).href);
await radarPage.fill("#url-input", "https://micros0ft.example/login");
await radarPage.click("#trace-button");
await radarPage.waitForSelector("#risk-verdict.high", { state: "visible" });
await radarPage.click("#cloudflare-scan");
await radarPage.waitForSelector("#radar-dialog[open]");
assert.match(await radarPage.textContent("#radar-dialog"), /may make them public/);
await radarPage.click("#radar-cancel");
await radarPage.waitForSelector("#radar-dialog", { state: "hidden" });
assert.deepEqual(await radarPage.evaluate(() => window.__radarPopups), []);
await radarPage.click("#cloudflare-scan");
await radarPage.waitForSelector("#radar-dialog[open]");
await radarPage.click("#radar-confirm");
await radarPage.waitForSelector("#radar-dialog", { state: "hidden" });
assert.deepEqual(
  await radarPage.evaluate(() => window.__radarPopups),
  ["https://radar.cloudflare.com/scan?url=https%3A%2F%2Fmicros0ft.example%2Flogin"],
);

// Without clipboard access the share flow surfaces the link as a selectable
// dialog field instead of a blocking prompt.
await radarPage.click("#copy-link");
await radarPage.waitForSelector("#link-dialog[open]");
assert.equal(
  await radarPage.inputValue("#link-field"),
  `${radarPage.url().split("#")[0]}#abcdefghijklmnop`,
  "fallback field must hold the canonical share link",
);
assert.equal(await radarPage.evaluate(() => document.activeElement?.id), "link-field");
await radarPage.keyboard.press("Escape");

// The Markdown copy reuses the same designed fallback surface, relabelled so
// it never misdescribes its contents, and the textarea must preserve the
// report's line structure for pasting into tickets or AI chats.
await radarPage.click("#copy-markdown");
await radarPage.waitForSelector("#link-dialog[open]");
assert.equal(await radarPage.textContent("#link-dialog-title"), "Copy this report as Markdown");
assert.equal(await radarPage.textContent("#link-dialog-label"), "Markdown report");
const markdown = await radarPage.inputValue("#link-field");
assert.match(markdown, /^# RequestScope report: micros0ft\.example\n/);
assert.match(markdown, /\*\*Verdict:\*\* HIGH · 66\/100/);
assert.match(markdown, /## External reputation/);
assert.match(markdown, /## Page observation/);
assert.match(markdown, /- Forms detected: 1/);
assert.match(markdown, /- Password input observed: yes/);
assert.match(markdown, /- Any form submits off-site: no/);
assert.match(markdown, /- Sensitive language: login/);
assert.match(markdown, /1\. HTTP 302 https:\/\/micros0ft\.example\/login -> https:\/\/micros0ft\.example\/signin \(41ms\)/);
// A mapped trace must carry its dependency-map evidence into the brief.
assert.match(markdown, /## External dependency map/);
assert.match(markdown, /2 external domains: 1 possible data-bearing, 1 not observed in the initial HTML\./);
assert.match(markdown, /Categories: analytics 2\./);
assert.match(markdown, /- Google Analytics \(google-analytics\.com\)/);
assert.match(markdown, /Potential subdomain takeover evidence:/);
assert.match(markdown, /- stale\.micros0ft\.example -> ghost\.io/);
assert.match(markdown, /Full evidence: .*#abcdefghijklmnop$/m);
assert.match(markdown, /Stored until .+, then deleted automatically/);
const markdownLines = markdown.split("\n").length;
assert.ok(markdownLines > 10, "the markdown brief must keep its line structure in the textarea field");
await radarPage.keyboard.press("Escape");
await radarContext.close();

// "/" focuses the primary field from anywhere that is not text entry.
const shortcutContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const shortcutPage = await shortcutContext.newPage();
await shortcutPage.goto(pathToFileURL(path.resolve(webRoot, "index.html")).href);
await shortcutPage.keyboard.press("/");
assert.equal(await shortcutPage.evaluate(() => document.activeElement?.id), "url-input");
// Inside the field the shortcut must yield to ordinary typing.
await shortcutPage.keyboard.type("example.com/");
assert.equal(await shortcutPage.inputValue("#url-input"), "example.com/");
await shortcutPage.fill("#url-input", "");
await shortcutPage.locator(".trace-options > summary").click();
await shortcutPage.check("#map-deps");
await shortcutPage.locator("#map-deps").focus();
await shortcutPage.keyboard.press("/");
assert.equal(await shortcutPage.evaluate(() => document.activeElement?.id), "map-deps", "text entry and focused controls must win over the shortcut");

// Whitespace-only input passes native :required, so it must get explicit
// validation feedback instead of a silent no-op submission.
let whitespaceSubmissions = 0;
await shortcutPage.route("**/api/scans/stream", async (route) => {
  whitespaceSubmissions += 1;
  await route.fulfill({ status: 200, contentType: "application/x-ndjson", body: "" });
});
await shortcutPage.fill("#url-input", "   ");
await shortcutPage.click("#trace-button");
assert.equal(whitespaceSubmissions, 0, "a whitespace-only submit must not reach the API");
assert.equal(
  await shortcutPage.evaluate(() => document.querySelector("#url-input")?.validity.customError),
  true,
  "the URL field must carry designed validation feedback",
);
await shortcutPage.fill("#url-input", "example.com");
assert.equal(
  await shortcutPage.evaluate(() => document.querySelector("#url-input")?.validity.customError),
  false,
  "typing again must clear the custom validation state",
);
await shortcutContext.close();

// Phase 5: the cancel path. A trace that stops delivering events must stay
// cancellable: the Cancel button aborts the fetch, surfaces the distinct
// user-cancel copy, restores the controls, and leaves the form usable.
const cancelContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const cancelPage = await cancelContext.newPage();
let stallStarted = 0;
let releaseStalledStream = () => {};
const stalledStream = new Promise((resolve) => { releaseStalledStream = resolve; });
await cancelPage.route("**/api/health", async (route) => {
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, reputationProviders: {} }) });
});
await cancelPage.route("**/api/scans/stream", async (route) => {
  stallStarted += 1;
  if (stallStarted === 1) {
    await stalledStream.catch(() => {});
    try {
      await route.fulfill({ status: 200, contentType: "application/x-ndjson", body: "" });
    } catch {
      // The aborted fetch no longer needs a response.
    }
    return;
  }
  const events = ["accepted", "validated", "dns", "hop", "response", "complete"]
    .map((stage) => JSON.stringify({ type: "progress", stage, message: `Stage ${stage}` }));
  await route.fulfill({
    status: 200,
    contentType: "application/x-ndjson",
    body: `${events.join("\n")}\n${JSON.stringify({ type: "result", report })}\n`,
  });
});
await cancelPage.goto(pathToFileURL(path.resolve(webRoot, "index.html")).href);
await cancelPage.fill("#url-input", "https://micros0ft.example/login");
await cancelPage.click("#trace-button");
await cancelPage.waitForSelector("#progress-panel:not(.hidden)");
await cancelPage.click("#cancel-trace");
await cancelPage.waitForSelector("#error-panel:not(.hidden)");
assert.equal(await cancelPage.textContent("#error-message"), "Trace cancelled.");
assert.equal(await cancelPage.locator("#progress-panel.hidden").count(), 1);
assert.equal(await cancelPage.locator("#trace-button[disabled]").count(), 0);
// The form must stay usable for a fresh trace without reloading.
await cancelPage.click("#trace-button");
await cancelPage.waitForSelector("#risk-verdict.high", { state: "visible" });
assert.equal(stallStarted, 2);
await cancelContext.close();

// Boundary rejections (invalid target, exhausted quota) now arrive as real
// HTTP statuses with a JSON body before any NDJSON byte; the UI must show
// that copy instead of a bare "Trace failed with HTTP 429".
const quotaContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const quotaPage = await quotaContext.newPage();
await quotaPage.route("**/api/health", async (route) => {
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, reputationProviders: {} }) });
});
await quotaPage.route("**/api/scans/stream", async (route) => {
  await route.fulfill({
    status: 429,
    contentType: "application/json",
    headers: { "Retry-After": "3600" },
    body: JSON.stringify({ error: "Daily anonymous scan limit of 15 reached." }),
  });
});
await quotaPage.goto(pathToFileURL(path.resolve(webRoot, "index.html")).href);
await quotaPage.fill("#url-input", "https://micros0ft.example/login");
await quotaPage.click("#trace-button");
await quotaPage.waitForSelector("#error-panel:not(.hidden)");
assert.equal(await quotaPage.textContent("#error-code"), "RATE_LIMITED");
assert.equal(await quotaPage.textContent("#error-message"), "Daily anonymous scan limit of 15 reached.");
assert.equal(await quotaPage.locator("#progress-panel.hidden").count(), 1);
assert.equal(await quotaPage.locator("#trace-button[disabled]").count(), 0);
await quotaContext.close();

await browser.close();
