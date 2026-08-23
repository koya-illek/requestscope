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
  dependencies: { total: 0, firstParty: 0, thirdParty: 0, uniqueHosts: [], items: [] },
  findings: [],
  summary: { critical: 0, warning: 0, positive: 0, info: 0 },
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
await cspContext.close();
server.close();

// Phase 4: the share flow. Loading #<reportId> must fetch and render the saved
// report without pushing history or losing focus discipline, an invalid hash
// must surface the INVALID_LINK notice, and dismissing it must clear the hash.
const linkContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const linkPage = await linkContext.newPage();
let savedReportFetches = 0;
await linkPage.route("**/api/health", async (route) => {
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, reputationProviders: {} }) });
});
await linkPage.route("**/api/scans/abcdefghijklmnop*", async (route) => {
  savedReportFetches += 1;
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(report) });
});
await linkPage.goto(`${pathToFileURL(path.resolve(webRoot, "index.html")).href}#abcdefghijklmnop`);
await linkPage.waitForSelector("#risk-verdict.high", { state: "visible" });
assert.equal(await linkPage.textContent("#risk-verdict"), "HIGH · 66/100");
assert.equal(savedReportFetches, 1);
assert.equal(await linkPage.title(), "micros0ft.example: RequestScope");
assert.equal(await linkPage.evaluate(() => document.activeElement?.id), "report-host");
assert.equal(await linkPage.evaluate(() => location.hash), "#abcdefghijklmnop");

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
assert.equal(await linkPage.evaluate(() => location.hash), "");
await linkContext.close();

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

await browser.close();
