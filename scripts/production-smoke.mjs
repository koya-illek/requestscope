import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { chromium } from "playwright";
import {
  assertHealthPayload,
  assertLighthouseResult,
  assertMcpResponse,
  parseSmokeArgs,
} from "./production-smoke-lib.mjs";

const ORIGIN = "https://requestscope.illek.ie";
const VIEWPORTS = [
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1440, height: 1000 },
];
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const options = parseSmokeArgs(process.argv.slice(2));
const expectedRevision = options.expectedRevision || gitRevision();
const evidenceDirectory = await mkdtemp(path.join(tmpdir(), "requestscope-production-smoke-"));

const healthResponse = await fetch(`${ORIGIN}/api/health`, { cache: "no-store" });
assert.equal(healthResponse.status, 200, "GET /api/health must return 200.");
assertHealthPayload(await healthResponse.json(), expectedRevision);
console.log(`Health reports revision ${expectedRevision}.`);

const mcpResponse = await fetch(`${ORIGIN}/mcp/v2`, { method: "HEAD", cache: "no-store" });
assertMcpResponse(mcpResponse.status, mcpResponse.headers);
console.log("MCP method and security headers passed.");

const launchOptions = existsSync("/snap/bin/chromium")
  ? { executablePath: "/snap/bin/chromium", headless: true }
  : { headless: true };
const browser = await chromium.launch(launchOptions);
try {
  for (const pageDefinition of [
    { name: "home", path: "/", canonical: `${ORIGIN}/` },
    { name: "privacy", path: "/privacy", canonical: `${ORIGIN}/privacy` },
  ]) {
    for (const viewport of VIEWPORTS) {
      await checkPage({
        browser,
        url: `${ORIGIN}${pageDefinition.path}`,
        name: pageDefinition.name,
        canonical: pageDefinition.canonical,
        viewport,
        evidenceDirectory,
      });
    }
  }

  if (options.reportId) {
    for (const viewport of VIEWPORTS) {
      await checkReport({
        browser,
        reportId: options.reportId,
        viewport,
        evidenceDirectory,
      });
    }
  }
} finally {
  await browser.close();
}

if (options.runLighthouse) {
  const lighthousePath = path.join(evidenceDirectory, "lighthouse.json");
  const lighthouse = spawnSync("lighthouse", [
    `${ORIGIN}/`,
    "--quiet",
    "--chrome-flags=--headless",
    "--only-categories=performance,accessibility,best-practices,seo",
    "--output=json",
    `--output-path=${lighthousePath}`,
  ], { cwd: repositoryRoot, stdio: "inherit" });
  if (lighthouse.error?.code === "ENOENT") {
    throw new Error("The lighthouse executable is required. Install Lighthouse or pass --skip-lighthouse for a partial smoke run.");
  }
  assert.equal(lighthouse.status, 0, "Lighthouse did not complete successfully.");
  const report = JSON.parse(await readFile(lighthousePath, "utf8"));
  assertLighthouseResult(report);
  console.log("Lighthouse passed: performance at least 90; accessibility, best practices, and SEO at 100.");
}

console.log(`Production smoke passed. Evidence: ${evidenceDirectory}`);

async function checkPage({ browser: activeBrowser, url, name, canonical, viewport, evidenceDirectory: outputDirectory }) {
  const context = await activeBrowser.newContext({ viewport });
  const page = await context.newPage();
  const failures = monitorPage(page, ORIGIN);
  try {
    const response = await page.goto(url, { waitUntil: "networkidle" });
    assert.equal(response?.status(), 200, `${name} returned the wrong status at ${viewport.width}px.`);
    assert.equal(await page.locator('link[rel="canonical"]').getAttribute("href"), canonical);
    assert.equal(await page.locator("h1").count(), 1, `${name} must have one h1.`);
    assert.equal(await page.locator("main").count(), 1, `${name} must have one main landmark.`);
    await page.keyboard.press("Tab");
    assert.equal(
      await page.evaluate(() => document.activeElement?.classList.contains("skip-link")),
      true,
      `${name} must focus its skip link first.`,
    );
    await assertAccessiblePage(page, name, viewport.width);
    assert.deepEqual(failures, [], `${name} produced browser failures at ${viewport.width}px: ${failures.join(" | ")}`);
    await page.screenshot({
      path: path.join(outputDirectory, `${name}-${viewport.width}.png`),
      fullPage: true,
    });
  } finally {
    await context.close();
  }
}

async function checkReport({ browser: activeBrowser, reportId, viewport, evidenceDirectory: outputDirectory }) {
  const context = await activeBrowser.newContext({ viewport });
  const page = await context.newPage();
  const failures = monitorPage(page, ORIGIN);
  try {
    const response = await page.goto(`${ORIGIN}/#${reportId}`, { waitUntil: "networkidle" });
    assert.equal(response?.status(), 200, `Report shell returned the wrong status at ${viewport.width}px.`);
    await page.waitForSelector("#risk-verdict.low, #risk-verdict.medium, #risk-verdict.high", { state: "visible" });
    assert.match(await page.textContent("#risk-verdict"), /^(LOW|MEDIUM|HIGH) · \d+\/100$/);
    assert.equal(await page.locator("#risk-panel").isVisible(), true);
    assert.equal(await page.locator("#claimed-organisation").count(), 1);
    await assertAccessiblePage(page, "report", viewport.width);
    assert.deepEqual(failures, [], `report produced browser failures at ${viewport.width}px: ${failures.join(" | ")}`);
    await page.screenshot({
      path: path.join(outputDirectory, `report-${viewport.width}.png`),
      fullPage: true,
    });
  } finally {
    await context.close();
  }
}

async function assertAccessiblePage(page, name, width) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert.equal(overflow, false, `${name} has horizontal overflow at ${width}px.`);
  const accessibility = await new AxeBuilder({ page }).analyze();
  assert.deepEqual(
    accessibility.violations.map(({ id, impact, nodes }) => ({
      id,
      impact,
      targets: nodes.map((node) => node.target),
    })),
    [],
    `${name} has accessibility violations at ${width}px.`,
  );
}

function monitorPage(page, origin) {
  const failures = [];
  page.on("console", (message) => {
    if (message.type() === "error") failures.push(`console: ${message.text()}`);
  });
  page.on("pageerror", (error) => failures.push(`page: ${String(error)}`));
  page.on("requestfailed", (request) => {
    if (new URL(request.url()).origin === origin) {
      failures.push(`request: ${request.method()} ${request.url()} ${request.failure()?.errorText || "failed"}`);
    }
  });
  return failures;
}

function gitRevision() {
  const result = spawnSync("git", ["rev-parse", "--short=12", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  if (result.error || result.status !== 0) {
    throw new Error(result.stderr?.trim() || result.error?.message || "Could not resolve the release revision.");
  }
  return result.stdout.trim();
}
