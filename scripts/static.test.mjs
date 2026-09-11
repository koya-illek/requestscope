import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { readFile, stat } from "node:fs/promises";
import { test } from "node:test";


test("shipped asset weights stay inside the performance budget", async () => {
  // The product ships no build step by design, so the budget is the guard:
  // raw bytes bound what a maintainer may add, and the gzip numbers bound
  // what a visitor transfers (Cloudflare compresses text assets).
  const budgets = [
    { file: "app.js", maxBytes: 56 * 1024, maxGzipBytes: 16 * 1024 },
    { file: "styles.css", maxBytes: 44 * 1024, maxGzipBytes: 11 * 1024 },
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

test("API_VERSION stays in lockstep with package manifests", async () => {
  const versionSource = await readFile(new URL("../api/src/version.ts", import.meta.url), "utf8");
  const apiManifest = JSON.parse(await readFile(new URL("../api/package.json", import.meta.url), "utf8"));
  const rootManifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const version = versionSource.match(/export const API_VERSION = "([^"]+)"/)?.[1];
  assert.equal(version, apiManifest.version);
  assert.equal(version, rootManifest.version);
});
