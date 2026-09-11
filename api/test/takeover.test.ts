import { describe, expect, it, vi } from "vitest";
import { evaluateTakeoverVerdict, matchTakeoverSignature, matchVulnerablePattern, probeTakeover } from "../src/takeover";
import { BudgetExceededError, RequestBudget } from "../src/budget";

describe("takeover verdict evaluation", () => {
  it("marks a signature on a failure status as vulnerable", () => {
    const outcome = evaluateTakeoverVerdict("GitHub Pages", 404, true, "lost.example.com");
    expect(outcome.vulnerable).toBe(true);
    expect(outcome.evidence).toContain("takeover signature found");
    expect(outcome.evidence).toContain("status 404");
  });

  it("keeps a signature on an active response non-vulnerable with manual verification", () => {
    const outcome = evaluateTakeoverVerdict("Tumblr", 200, true, "live.example.com");
    expect(outcome.vulnerable).toBe(false);
    expect(outcome.evidence).toContain("active HTTP 200 response");
    expect(outcome.evidence).toContain("manual verification recommended");
  });

  it("treats a bare 404 on a matching CNAME as potential rather than vulnerable", () => {
    const outcome = evaluateTakeoverVerdict("Heroku", 404, false, "dangling.example.com");
    expect(outcome.vulnerable).toBe(false);
    expect(outcome.evidence).toContain("potential dangling resource");
  });

  it("treats a healthy active response as not vulnerable", () => {
    const outcome = evaluateTakeoverVerdict("Shopify", 200, false, "shop.example.com");
    expect(outcome.vulnerable).toBe(false);
    expect(outcome.evidence).toContain("appears active");
  });
});

describe("vulnerable CNAME pattern matching", () => {
  it("matches global, regional, dualstack, and legacy dash S3 endpoints", () => {
    for (const target of [
      "bucket.s3.amazonaws.com",
      "bucket.s3.eu-west-1.amazonaws.com",
      "bucket.s3.dualstack.us-east-1.amazonaws.com",
      "bucket.s3-eu-west-1.amazonaws.com",
    ]) {
      expect(matchVulnerablePattern(target)?.service, target).toBe("AWS S3");
    }
    expect(matchVulnerablePattern("internal-elb.eu-west-1.elb.amazonaws.com")).toBeNull();
    expect(matchVulnerablePattern("example.com")).toBeNull();
  });
});

describe("takeover signature matching", () => {
  it("matches the verified Webflow dangling sentence in raw and entity-encoded forms", () => {
    expect(matchTakeoverSignature("Webflow", "<p>The page you are looking for doesn't exist or has been moved.</p>")).toBe(true);
    expect(matchTakeoverSignature("Webflow", "<p>The page you are looking for doesn&#x27;t exist or has been moved.</p>")).toBe(true);
    // The shorter generic sentence on an active site's custom 404 must not
    // produce a vulnerability claim.
    expect(matchTakeoverSignature("Webflow", "<h1>The page you are looking for doesn't exist</h1>")).toBe(false);
  });

  it("matches the verified Ghost domain-error page instead of Webflow's copy", () => {
    expect(matchTakeoverSignature("Ghost", "<title>Domain error</title><h1>Domain error</h1>")).toBe(true);
    expect(matchTakeoverSignature("Ghost", "<p>The page you are looking for doesn't exist or has been moved.</p>")).toBe(false);
  });

  it("matches the verified Squarespace title marker", () => {
    expect(matchTakeoverSignature("Squarespace", "<title>Squarespace - No Such Website</title>")).toBe(true);
  });

  it("keeps Cargo detection to its service-marked variant", () => {
    expect(matchTakeoverSignature("Cargo", "<h1>404 Not Found</h1><p>cargo collective</p>")).toBe(true);
    expect(matchTakeoverSignature("Cargo", "<h1>The page you were looking for doesn't exist</h1>")).toBe(false);
  });

  it("keeps Azure detection to its specific error marker", () => {
    expect(matchTakeoverSignature("Azure", "<h1>404 Web Site not found</h1>")).toBe(true);
    expect(matchTakeoverSignature("Azure", "<p>The web site you have accessed is not available</p>")).toBe(false);
  });
});

describe("probeTakeover result contract", () => {
  it("reports only subdomains whose CNAME matches a known pattern", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com") {
        const name = url.searchParams.get("name");
        const answer = (data: string) => Response.json({ Status: 0, AD: false, Answer: [{ name, type: 5, TTL: 300, data }] });
        if (name === "dangling.example.com") return answer("rs8-probe.webflow.io.");
        if (name === "unrelated.example.com") return answer("internal-elb.eu-west-1.elb.amazonaws.com.");
        if (name === "broken.example.com") throw new TypeError("resolver unreachable");
        return Response.json({ Status: 3 });
      }
      if (url.hostname === "dangling.example.com") {
        return new Response("<p>The page you are looking for doesn&#x27;t exist or has been moved.</p>", { status: 404 });
      }
      return new Response("", { status: 200 });
    }));

    const results = await probeTakeover([
      "dangling.example.com",
      "unrelated.example.com",
      "broken.example.com",
    ], new RequestBudget());

    expect(results.length).toBe(1);
    expect(results[0]?.subdomain).toBe("dangling.example.com");
    expect(results[0]?.cname).toBe("rs8-probe.webflow.io");
    expect(results[0]?.vulnerable).toBe(true);
    expect(results[0]?.httpStatus).toBe(404);
    vi.unstubAllGlobals();
  });

  it("fails closed when a takeover HTTP probe has no request budget", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com") {
        return Response.json({
          Status: 0,
          Answer: [{ name: url.searchParams.get("name"), type: 5, TTL: 300, data: "rs8-probe.webflow.io." }],
        });
      }
      return new Response("should not be fetched", { status: 404 });
    }));
    await expect(probeTakeover(["dangling.example.com"])).rejects.toBeInstanceOf(BudgetExceededError);
    vi.unstubAllGlobals();
  });

  it("charges inspected takeover response bytes to the request-wide budget", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com") {
        const name = url.searchParams.get("name");
        return Response.json({
          Status: 0,
          Answer: [{ name, type: 5, TTL: 300, data: "site.webflow.io." }],
        });
      }
      return new Response("x".repeat(200), { status: 404 });
    }));

    const budget = new RequestBudget({ maxBodyBytes: 32 });
    const validatedHosts = new Map([["dangling.example.com", {
      hostname: "dangling.example.com",
      addresses: ["93.184.216.34"],
      queries: [],
    }]]);
    await probeTakeover(["dangling.example.com"], budget, validatedHosts);

    expect(budget.snapshot()).toMatchObject({
      bodyBytesInspected: 32,
      exhausted: true,
      exhaustionReason: "response body budget reached",
    });
    vi.unstubAllGlobals();
  });
});
