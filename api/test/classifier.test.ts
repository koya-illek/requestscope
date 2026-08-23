import { describe, expect, it } from "vitest";
import { assessPiiRisk, classifyDomain, classifyHostname } from "../src/classifier";

describe("domain classification label boundary", () => {
  it("does not misclassify hosts that merely end in a brand suffix", () => {
    for (const host of ["netflix.com", "box.com", "citrix.com", "medical.com", "evil-x.com", "yahoo-mail.co"]) {
      const match = classifyDomain(host);
      expect(match.category, host).toBe("unknown");
      expect(match.name, host).toBeNull();
    }
  });

  it("still recognises exact and subdomain matches", () => {
    expect(classifyDomain("x.com").name).toBe("Twitter/X");
    expect(classifyDomain("www.x.com").name).toBe("Twitter/X");
    expect(classifyDomain("platform.twitter.com").name).toBe("Twitter/X");
    expect(classifyDomain("cal.com").name).toBe("Cal.com");
    expect(classifyDomain("js.stripe.com").name).toBe("Stripe");
    expect(classifyDomain("google-analytics.com").name).toBe("Google Analytics");
    expect(classifyHostname("www.google-analytics.com").name).toBe("Google Analytics");
  });

  it("requires a dot boundary for subdomain-style patterns", () => {
    expect(classifyDomain("matomo.example.com").name).toBe("Matomo/Piwik");
    expect(classifyDomain("mypiwik.example").category).toBe("unknown");
    expect(classifyDomain("not-turnstile.site").category).toBe("unknown");
    expect(classifyDomain("challenges.cloudflare.com").name).toBe("Cloudflare Turnstile");
  });

  it("requires the Turnstile suffix to end the hostname", () => {
    expect(classifyDomain("sub.turnstile.site").name).toBe("Cloudflare Turnstile");
    for (const host of ["turnstile.sitedemo.com", "evil.turnstile.site.attacker.com"]) {
      const match = classifyDomain(host);
      expect(match.category, host).toBe("unknown");
      expect(match.name, host).toBeNull();
    }
  });

  it("keeps the Irish service entries working", () => {
    expect(classifyDomain("www.revenue.ie").name).toBe("Revenue IE");
    expect(classifyDomain("bankofireland.com").name).toBe("Bank of Ireland");
  });
});

describe("PII fallback heuristics", () => {
  it("flags hosts whose labels name a data-collecting pattern", () => {
    expect(assessPiiRisk("tracker-cdn.example.com", "unknown")).toBe(true);
    expect(assessPiiRisk("analytics.internal", "unknown")).toBe(true);
    expect(assessPiiRisk("beacon.foo.ie", "unknown")).toBe(true);
  });

  it("does not flag innocuous substring collisions", () => {
    expect(assessPiiRisk("trackandfield.ie", "unknown")).toBe(false);
    expect(assessPiiRisk("soundtrack-cdn.example.com", "unknown")).toBe(false);
    expect(assessPiiRisk("businessinsights.ie", "unknown")).toBe(false);
  });

  it("still trusts category-based assessment first", () => {
    expect(assessPiiRisk("plain-host.example", "advertising")).toBe(true);
  });
});
