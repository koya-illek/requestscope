import { describe, expect, it } from "vitest";
import { assessUrlRisk } from "../src/url-risk";
import type { ScanReport } from "../src/types";

function report(hostname = "example.com", overrides: Partial<ScanReport> = {}): ScanReport {
  const url = `https://${hostname}/`;
  return {
    schemaVersion: 1,
    id: "abcdefghijklmnop",
    requestedUrl: url,
    normalizedUrl: url,
    finalUrl: url,
    hostname,
    status: "complete",
    createdAt: "2026-08-14T00:00:00.000Z",
    expiresAt: "2026-08-28T00:00:00.000Z",
    totalDurationMs: 100,
    observation: { vantage: "cloudflare-edge", disclaimer: "test" },
    dns: { queries: [], addresses: ["93.184.216.34"], dnssecAuthenticated: false },
    http: {
      hops: [{
        index: 0, url, hostname, status: 200, statusText: "OK", elapsedMs: 50,
        location: null, responseHeaders: {}, cf: {}, evidenceKind: "edge_http_observation",
      }],
      finalStatus: 200, contentType: "text/html", contentBytesInspected: 100, truncated: false,
    },
    dependencies: { total: 0, firstParty: 0, thirdParty: 0, uniqueHosts: [], items: [] },
    findings: [],
    summary: { critical: 0, warning: 0, positive: 0, info: 0 },
    ...overrides,
  };
}

describe("URL risk assessment", () => {
  it("does not call an ordinary URL safe", () => {
    const result = assessUrlRisk(report(), "https://example.com/");
    expect(result.verdict).toBe("low");
    expect(result.summary).toContain("does not prove");
    expect(result.reputation.status).toBe("not_requested");
  });

  it("detects a claimed-brand lookalike with a password form", () => {
    const target = report("micros0ft.com", {
      pageSecuritySignals: { passwordForm: true, forms: 1, externalFormAction: false, matchedLanguage: ["login"] },
    });
    const result = assessUrlRisk(target, "https://micros0ft.com/login", { claimedOrganisation: "Microsoft" });
    expect(result.verdict).toBe("high");
    expect(result.findings.map((finding) => finding.code)).toEqual(expect.arrayContaining(["brand-lookalike", "password-form"]));
  });

  it("downgrades an exact brand name on a plausible sibling TLD instead of hard-flagging it", () => {
    const result = assessUrlRisk(report("google.dev"), "https://google.dev/");
    const lookalike = result.findings.find((finding) => finding.code === "brand-lookalike");
    expect(lookalike?.severity).toBe("medium");
    expect(lookalike?.confidence).toBe("medium");
    expect(lookalike?.evidence.matchType).toBe("exact-name-alt-tld");
    expect(result.verdict).toBe("low");
  });

  it("keeps a single-character brand typo at high severity", () => {
    const result = assessUrlRisk(report("goagle.com"), "https://goagle.com/");
    const lookalike = result.findings.find((finding) => finding.code === "brand-lookalike");
    expect(lookalike?.severity).toBe("high");
    expect(lookalike?.confidence).toBe("high");
    expect(lookalike?.evidence.matchType).toBe("edit-distance");
    expect(result.riskScore).toBeGreaterThanOrEqual(30);
  });

  it("flags hyphenated brand impersonation through token containment", () => {
    const result = assessUrlRisk(report("microsoft-login.com"), "https://microsoft-login.com/signin");
    const lookalike = result.findings.find((finding) => finding.code === "brand-lookalike");
    expect(lookalike?.evidence.matchedName).toBe("microsoft");
    expect(lookalike?.evidence.matchType).toBe("name-containment");
    expect(lookalike?.severity).toBe("medium");
    expect(lookalike?.confidence).toBe("medium");
  });

  it("does not invent a lookalike finding for an organisation without known domains", () => {
    const result = assessUrlRisk(report(), "https://example.com/", { claimedOrganisation: "Example" });
    expect(result.verdict).toBe("low");
    expect(result.claimedOrganisation).toBe("Example");
    expect(result.findings.some((finding) => finding.code === "brand-lookalike")).toBe(false);
  });

  it("identifies shorteners and cross-domain redirects", () => {
    const target = report("bit.ly", {
      finalUrl: "https://example.net/login",
      http: {
        hops: [
          { index: 0, url: "https://bit.ly/a", hostname: "bit.ly", status: 302, statusText: "Found", elapsedMs: 20, location: "https://example.net/login", responseHeaders: {}, cf: {}, evidenceKind: "edge_http_observation" },
          { index: 1, url: "https://example.net/login", hostname: "example.net", status: 200, statusText: "OK", elapsedMs: 30, location: null, responseHeaders: {}, cf: {}, evidenceKind: "edge_http_observation" },
        ],
        finalStatus: 200, contentType: "text/html", contentBytesInspected: 100, truncated: false,
      },
    });
    const result = assessUrlRisk(target, "https://bit.ly/a");
    expect(result.findings.map((finding) => finding.code)).toEqual(expect.arrayContaining(["known-shortener", "cross-domain-redirect"]));
  });

  it("detects mixed-script Unicode supplied hostnames", () => {
    const target = report("xn--pple-43d.com");
    const result = assessUrlRisk(target, "https://аpple.com");
    expect(result.findings.find((finding) => finding.code === "internationalized-domain")?.severity).toBe("high");
  });

  it("promotes an external reputation match to a high verdict", () => {
    const result = assessUrlRisk(report(), "https://example.com/", {}, {
      status: "matched",
      detail: "A provider matched.",
      consentRequired: true,
      providers: [{
        provider: "google_web_risk",
        target: "requested",
        hostname: "example.com",
        status: "matched",
        threatTypes: ["SOCIAL_ENGINEERING"],
        detail: "Google Web Risk lists this URL for social engineering.",
        checkedAt: "2026-08-14T00:00:00.000Z",
        expiresAt: "2026-08-14T00:20:00.000Z",
        advisoryUrl: "https://docs.cloud.google.com/web-risk/docs/advisory",
        attribution: "Advisory provided by Google",
      }],
    });
    expect(result.verdict).toBe("high");
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
    expect(result.findings.some((finding) => finding.source === "reputation_provider")).toBe(true);
  });
});
