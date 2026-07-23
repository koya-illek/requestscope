import { describe, expect, it } from "vitest";
import { buildFindings } from "../src/findings";
import type { ScanReport } from "../src/types";

function report(overrides: Partial<Omit<ScanReport, "findings" | "summary">> = {}) {
  const base: Omit<ScanReport, "findings" | "summary"> = {
    schemaVersion: 1,
    id: "abcdefghijklmnop",
    requestedUrl: "http://example.com",
    normalizedUrl: "http://example.com/",
    finalUrl: "https://example.com/",
    hostname: "example.com",
    status: "complete",
    createdAt: "2026-07-23T00:00:00.000Z",
    expiresAt: "2026-08-06T00:00:00.000Z",
    totalDurationMs: 100,
    observation: {
      vantage: "cloudflare-edge",
      disclaimer: "test",
    },
    dns: {
      queries: [],
      addresses: ["93.184.216.34"],
      dnssecAuthenticated: false,
    },
    http: {
      hops: [{
        index: 0,
        url: "https://example.com/",
        hostname: "example.com",
        status: 200,
        statusText: "OK",
        elapsedMs: 100,
        location: null,
        responseHeaders: {
          "cache-control": "public, max-age=3600",
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": "default-src 'self'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "strict-origin",
        },
        cf: {},
        evidenceKind: "edge_http_observation",
      }],
      finalStatus: 200,
      contentType: "text/html",
      contentBytesInspected: 100,
      truncated: false,
    },
    dependencies: {
      total: 0,
      firstParty: 0,
      thirdParty: 0,
      uniqueHosts: [],
      items: [],
    },
  };
  return { ...base, ...overrides };
}

describe("buildFindings", () => {
  it("generates evidence-linked positive findings", () => {
    const findings = buildFindings(report());
    expect(findings.some((item) => item.code === "https-final" && item.severity === "positive")).toBe(true);
    expect(findings.some((item) => item.code === "cache-explicit")).toBe(true);
    expect(findings.every((item) => item.evidencePath.length > 0)).toBe(true);
  });

  it("flags a non-HTTPS final URL", () => {
    const findings = buildFindings(report({ finalUrl: "http://example.com/" }));
    expect(findings.find((item) => item.code === "http-final")?.severity).toBe("critical");
  });

  it("does not invent protocol or header findings when no final response exists", () => {
    const failed = report({
      finalUrl: null,
      status: "failed",
      http: {
        hops: [],
        finalStatus: null,
        contentType: null,
        contentBytesInspected: 0,
        truncated: false,
      },
    });
    const findings = buildFindings(failed);
    expect(findings.some((item) => item.code === "http-final")).toBe(false);
    expect(findings.some((item) => item.code === "cache-control-missing")).toBe(false);
    expect(findings.some((item) => item.code === "security-headers-missing")).toBe(false);
  });
});
