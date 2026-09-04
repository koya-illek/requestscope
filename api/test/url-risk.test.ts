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
    const result = assessUrlRisk(report("example.com", {
      pageSecuritySignals: { passwordForm: false, forms: 0, externalFormAction: false, matchedLanguage: ["login", "verification"] },
    }), "https://example.com/");
    expect(result.verdict).toBe("low");
    expect(result.summary).toContain("does not prove");
    expect(result.reputation.status).toBe("not_requested");
    expect(result.riskScore).toBe(0);
    expect(result.findings.some((finding) => finding.code === "sensitive-action-language")).toBe(false);
  });

  it("detects a claimed-brand lookalike with a password form", () => {
    const target = report("micros0ft.com", {
      pageSecuritySignals: { passwordForm: true, forms: 1, externalFormAction: false, matchedLanguage: ["login"] },
    });
    const result = assessUrlRisk(target, "https://micros0ft.com/login", { claimedOrganisation: "Microsoft" });
    expect(result.verdict).toBe("high");
    expect(result.findings.map((finding) => finding.code)).toEqual(expect.arrayContaining(["brand-lookalike", "password-form", "sensitive-action-language"]));
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

  it("resolves an exact short organisation claim to its brand", () => {
    const result = assessUrlRisk(report("aib-security.ie"), "https://aib-security.ie/", { claimedOrganisation: "AIB" });
    const lookalike = result.findings.find((finding) => finding.code === "brand-lookalike");
    expect(lookalike?.evidence.organisation).toBe("AIB");
    expect(lookalike?.evidence.matchType).toBe("name-containment");
    expect(lookalike?.score).toBe(22);
  });

  it("resolves an exact short alias claim to the owning organisation", () => {
    const result = assessUrlRisk(report("aws-verify.net"), "https://aws-verify.net/", { claimedOrganisation: "AWS" });
    const lookalike = result.findings.find((finding) => finding.code === "brand-lookalike");
    expect(lookalike?.evidence.organisation).toBe("Amazon");
    expect(lookalike?.evidence.matchType).toBe("name-containment");
  });

  it("keeps short-alias containment silent without a claimed brand", () => {
    const result = assessUrlRisk(report("boi-secure.com"), "https://boi-secure.com/");
    expect(result.findings.some((finding) => finding.code === "brand-lookalike")).toBe(false);
    expect(result.verdict).toBe("low");
  });

  it("lets an explicit brand claim cover its short aliases in containment matching", () => {
    const result = assessUrlRisk(report("boi-secure.com"), "https://boi-secure.com/", { claimedOrganisation: "Bank of Ireland" });
    const lookalike = result.findings.find((finding) => finding.code === "brand-lookalike");
    expect(lookalike?.evidence.organisation).toBe("Bank of Ireland");
    expect(lookalike?.evidence.matchedName).toBe("boi");
    expect(lookalike?.evidence.matchType).toBe("name-containment");
  });

  it("does not flag ordinary compound words that merely share a brand alias", () => {
    for (const host of ["apple-orchard.com", "office-supplies.ie", "amazon-river-tours.com", "stripe-curtains.ie"]) {
      const result = assessUrlRisk(report(host), `https://${host}/`);
      expect(result.findings.some((finding) => finding.code === "brand-lookalike"), host).toBe(false);
      expect(result.verdict, host).toBe("low");
      expect(result.confidence, host).toBe("high");
    }
  });

  it("still flags compound lookalikes that carry risk-context tokens", () => {
    const result = assessUrlRisk(report("secure-stripe-billing.net"), "https://secure-stripe-billing.net/");
    const lookalike = result.findings.find((finding) => finding.code === "brand-lookalike");
    expect(lookalike?.evidence.matchedName).toBe("stripe");
    expect(lookalike?.evidence.matchType).toBe("name-containment");
  });

  it("never reassures about a blocked, failed, or truncated destination", () => {
    const base = report();
    for (const target of [
      report("example.com", { status: "failed" }),
      report("example.com", { http: { ...base.http, finalStatus: 403 } }),
      report("example.com", { http: { ...base.http, finalStatus: 503 } }),
      report("example.com", { http: { ...base.http, truncated: true } }),
    ]) {
      const result = assessUrlRisk(target, target.requestedUrl);
      expect(result.confidence).toBe("medium");
      expect(result.findings.some(f => f.code === "incomplete-observation")).toBe(true);
      expect(result.summary).toContain("Inspection limited");
    }
  });

  it("does not invent a lookalike finding for an organisation without known domains", () => {
    const result = assessUrlRisk(report(), "https://example.com/", { claimedOrganisation: "Example" });
    expect(result.verdict).toBe("low");
    expect(result.claimedOrganisation).toBe("Example");
    expect(result.findings.some((finding) => finding.code === "brand-lookalike")).toBe(false);
  });

  it("resolves verbose claimed organisations to their brand", () => {
    const target = report("micros0ft.com");
    const result = assessUrlRisk(target, "https://micros0ft.com/", { claimedOrganisation: "Microsoft Corporation" });
    const lookalike = result.findings.find((finding) => finding.code === "brand-lookalike");
    expect(lookalike?.evidence.organisation).toBe("Microsoft");
    expect(lookalike?.evidence.matchType).toBe("edit-distance");
  });

  it("does not let a short alias prefix absorb an unrelated claim", () => {
    const result = assessUrlRisk(report(), "https://example.com/", { claimedOrganisation: "Boiler Repair Co" });
    expect(result.claimedOrganisation).toBe("Boiler Repair Co");
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

  it("categorises brand-owned services by their real function, not always functional", () => {
    const result = assessUrlRisk(report("www.paypal.com"), "https://www.paypal.com/");
    const service = result.services.find((entry) => entry.hostname === "www.paypal.com");
    expect(service?.organisation).toBe("PayPal");
    expect(service?.category).toBe("payment");

    const stripe = assessUrlRisk(report("stripe.com"), "https://stripe.com/");
    expect(stripe.services[0]?.category).toBe("payment");

    const linkedIn = assessUrlRisk(report("linkedin.com"), "https://linkedin.com/");
    expect(linkedIn.services[0]?.category).toBe("social");

    const cloudflare = assessUrlRisk(report("cloudflare.com"), "https://cloudflare.com/");
    expect(cloudflare.services[0]?.category).toBe("cdn");

    const microsoft = assessUrlRisk(report("microsoft.com"), "https://microsoft.com/");
    expect(microsoft.services[0]).toMatchObject({ organisation: "Microsoft", category: "functional" });
  });
});
