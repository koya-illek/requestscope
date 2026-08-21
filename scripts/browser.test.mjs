import assert from "node:assert/strict";
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";
import path from "node:path";
import { pathToFileURL } from "node:url";

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
    hops: [{ index: 0, url: "https://micros0ft.example/login", hostname: "micros0ft.example", status: 200, statusText: "OK", elapsedMs: 143, location: null, responseHeaders: {}, cf: { colo: "DUB", tlsVersion: "TLSv1.3" }, evidenceKind: "edge_http_observation" }],
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

for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
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
  await page.goto(pathToFileURL(path.resolve("web/index.html")).href);
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

await browser.close();
