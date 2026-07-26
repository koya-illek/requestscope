import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const read = (name) => readFile(new URL(`../web/${name}`, import.meta.url), "utf8");

test("public shell exposes metadata, keyboard navigation and privacy", async () => {
  const [html, headers, robots, sitemap] = await Promise.all([
    read("index.html"),
    read("_headers"),
    read("robots.txt"),
    read("sitemap.xml")
  ]);
  assert.match(html, /rel="canonical"/);
  assert.match(html, /Skip to URL trace/);
  assert.ok(html.includes("tools.illek.ie/privacy.html"));
  assert.ok(headers.includes("static.cloudflareinsights.com"));
  assert.match(robots, /Sitemap:/);
  assert.ok(sitemap.includes("requestscope.illek.ie"));
});
