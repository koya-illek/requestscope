import assert from "node:assert/strict";
import test from "node:test";
import {
  assertHealthPayload,
  assertLighthouseResult,
  assertMcpResponse,
  parseSmokeArgs,
} from "./production-smoke-lib.mjs";

test("production smoke arguments require release-shaped identifiers", () => {
  assert.deepEqual(parseSmokeArgs([]), {
    expectedRevision: null,
    reportId: null,
    runLighthouse: true,
  });
  assert.deepEqual(
    parseSmokeArgs(["--revision", "ebb631e67992", "--report-id", "abcdefghijklmnop", "--skip-lighthouse"]),
    {
      expectedRevision: "ebb631e67992",
      reportId: "abcdefghijklmnop",
      runLighthouse: false,
    },
  );
  assert.throws(() => parseSmokeArgs(["--revision", "working-tree"]), /7 to 40 lowercase hexadecimal/);
  assert.throws(() => parseSmokeArgs(["--report-id", "too-short"]), /16-character/);
  assert.throws(() => parseSmokeArgs(["--unknown"]), /Unknown argument/);
});

test("health validation binds the smoke run to the released revision", () => {
  const health = {
    ok: true,
    service: "requestscope-api",
    version: "1.4.0",
    sourceRevision: "ebb631e67992",
    databaseSchemaVersion: 1,
    reputationProviders: {
      googleWebRisk: true,
      phishTank: false,
      cloudflareFamilyDns: true,
    },
  };
  assert.doesNotThrow(() => assertHealthPayload(health, "ebb631e67992"));
  assert.throws(() => assertHealthPayload({ ...health, sourceRevision: "a0337b2" }, "ebb631e67992"), /expected ebb631e67992/);
  assert.throws(() => assertHealthPayload({ ...health, databaseSchemaVersion: "1" }, "ebb631e67992"), /databaseSchemaVersion/);
});

test("MCP smoke validation enforces the release security-header baseline", () => {
  const headers = new Headers({
    Allow: "POST, OPTIONS",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow",
  });
  assert.doesNotThrow(() => assertMcpResponse(405, headers));
  headers.delete("Strict-Transport-Security");
  assert.throws(() => assertMcpResponse(405, headers), /strict-transport-security/);
});

test("Lighthouse smoke validation keeps public release gates explicit", () => {
  const passing = {
    categories: {
      performance: { score: 0.91 },
      accessibility: { score: 1 },
      "best-practices": { score: 1 },
      seo: { score: 1 },
    },
  };
  assert.doesNotThrow(() => assertLighthouseResult(passing));
  assert.throws(
    () => assertLighthouseResult({
      ...passing,
      categories: { ...passing.categories, accessibility: { score: 0.99 } },
    }),
    /accessibility score 99 is below 100/,
  );
});
