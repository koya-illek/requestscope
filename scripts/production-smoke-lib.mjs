import assert from "node:assert/strict";

const REVISION_PATTERN = /^[0-9a-f]{7,40}$/;
const REPORT_ID_PATTERN = /^[A-Za-z0-9_-]{16}$/;

export function parseSmokeArgs(args) {
  const options = {
    expectedRevision: null,
    reportId: null,
    runLighthouse: true,
  };

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--skip-lighthouse") {
      options.runLighthouse = false;
      continue;
    }
    if (argument === "--revision") {
      options.expectedRevision = readValue(args, ++index, argument);
      continue;
    }
    if (argument === "--report-id") {
      options.reportId = readValue(args, ++index, argument);
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }

  if (options.expectedRevision && !REVISION_PATTERN.test(options.expectedRevision)) {
    throw new Error("--revision must be 7 to 40 lowercase hexadecimal characters.");
  }
  if (options.reportId && !REPORT_ID_PATTERN.test(options.reportId)) {
    throw new Error("--report-id must be a 16-character RequestScope report ID.");
  }
  return options;
}

export function assertHealthPayload(payload, expectedRevision) {
  assert.ok(isRecord(payload), "Health response must be a JSON object.");
  assert.equal(payload.ok, true, "Health response must report ok: true.");
  assert.equal(payload.service, "requestscope-api", "Health response has the wrong service name.");
  assert.equal(typeof payload.version, "string", "Health response must include a version string.");
  assert.equal(
    payload.sourceRevision,
    expectedRevision,
    `Production source revision ${String(payload.sourceRevision)} did not match expected ${expectedRevision}.`,
  );
  assert.equal(
    typeof payload.databaseSchemaVersion,
    "number",
    "Health response databaseSchemaVersion must be a number.",
  );
  assert.ok(isRecord(payload.reputationProviders), "Health response must describe reputation providers.");
  for (const provider of ["googleWebRisk", "phishTank", "cloudflareFamilyDns"]) {
    assert.equal(
      typeof payload.reputationProviders[provider],
      "boolean",
      `Health response reputationProviders.${provider} must be a boolean.`,
    );
  }
}

export function assertMcpResponse(status, headers) {
  assert.equal(status, 405, "HEAD /mcp/v2 must return 405.");
  const expectedHeaders = {
    allow: "POST, OPTIONS",
    "cache-control": "no-store",
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "x-frame-options": "DENY",
    "x-robots-tag": "noindex, nofollow",
  };
  for (const [name, expected] of Object.entries(expectedHeaders)) {
    assert.equal(headers.get(name), expected, `HEAD /mcp/v2 has the wrong ${name} header.`);
  }
}

export function assertLighthouseResult(report) {
  assert.ok(isRecord(report), "Lighthouse output must be a JSON object.");
  assert.ok(isRecord(report.categories), "Lighthouse output must include categories.");
  const minimums = {
    performance: 0.9,
    accessibility: 1,
    "best-practices": 1,
    seo: 1,
  };
  for (const [category, minimum] of Object.entries(minimums)) {
    const result = report.categories[category];
    assert.ok(isRecord(result), `Lighthouse output is missing ${category}.`);
    const score = result.score;
    assert.equal(typeof score, "number", `Lighthouse ${category} score must be a number.`);
    assert.ok(
      score >= minimum,
      `Lighthouse ${category} score ${Math.round(score * 100)} is below ${Math.round(minimum * 100)}.`,
    );
  }
}

function readValue(args, index, flag) {
  const value = args[index];
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value.`);
  return value;
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
