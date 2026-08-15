import assert from "node:assert/strict";
import { chromium } from "playwright";

const reportId = process.argv[2];
if (!/^[A-Za-z0-9_-]{16}$/.test(reportId || "")) throw new Error("Pass a 16-character production report ID");
const browser = await chromium.launch({ executablePath: "/snap/bin/chromium", headless: true });

for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
  const page = await browser.newPage({ viewport });
  const response = await page.goto(`https://requestscope.illek.ie/#${reportId}`, { waitUntil: "networkidle" });
  assert.equal(response?.status(), 200);
  await page.waitForSelector("#risk-verdict.low, #risk-verdict.medium, #risk-verdict.high", { state: "visible" });
  assert.match(await page.textContent("#risk-verdict"), /^(LOW|MEDIUM|HIGH) · \d+\/100$/);
  assert.equal(await page.locator("#risk-panel").isVisible(), true);
  assert.equal(await page.locator("#claimed-organisation").count(), 1);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert.equal(overflow, false, `${viewport.width}px production layout has horizontal overflow`);
  await page.screenshot({ path: `/tmp/requestscope-production-${viewport.width}.png`, fullPage: true });
  await page.close();
}

await browser.close();
