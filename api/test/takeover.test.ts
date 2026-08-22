import { describe, expect, it } from "vitest";
import { evaluateTakeoverVerdict } from "../src/takeover";

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
