import { afterEach, describe, expect, it, vi } from "vitest";
import { analyzeUrl } from "../src/analyzer";
import { inspectDns } from "../src/dns";

function dnsResponse(url: URL): Response {
  const type = url.searchParams.get("type");
  const name = url.searchParams.get("name") || "example.com";
  const answers = type === "A"
    ? [{ name: `${name}.`, type: 1, TTL: 300, data: "93.184.216.34" }]
    : type === "NS"
      ? [{ name: `${name}.`, type: 2, TTL: 300, data: "ns1.example.net." }]
      : [];
  return Response.json({ Status: 0, AD: true, Answer: answers });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("analyzeUrl", () => {
  it("creates a complete redacted report and emits real stages", async () => {
    const stages: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      return new Response(`
        <html><head>
          <link rel="stylesheet" href="/app.css?version=123">
          <style>.hero{background:url("https://cdn.example.net/hero.jpg?sig=secret")}</style>
        </head><body>
          <img srcset="/small.jpg 1x, /large.jpg 2x">
          <script src="https://cdn.example.net/app.js"></script>
        </body></html>`, {
        status: 200,
        headers: {
          "Content-Type": "text/html",
          "Cache-Control": "public, max-age=60",
        },
      });
    }));

    const report = await analyzeUrl(
      "https://example.com/page?token=secret",
      14,
      { colo: "DUB", country: "IE" },
      (event) => stages.push(event.stage),
    );

    expect(report.status).toBe("complete");
    expect(report.finalUrl).toContain("token=%5Bredacted%5D");
    expect(JSON.stringify(report)).not.toContain("secret");
    expect(report.dependencies.items.length).toBeGreaterThanOrEqual(4);
    expect(report.dependencies.items.every((item) => !item.url.includes("sig=secret"))).toBe(true);
    expect(stages).toEqual(expect.arrayContaining(["validated", "dns", "hop", "response", "complete"]));
  });

  it("records one partial hop when a redirect target is blocked", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      return new Response(null, { status: 302, headers: { Location: "http://127.0.0.1/admin" } });
    }));

    const report = await analyzeUrl("https://example.com", 14);
    expect(report.status).toBe("partial");
    expect(report.http.hops).toHaveLength(1);
    expect(report.http.hops[0].status).toBe(302);
    expect(report.http.hops[0].error).toMatch(/Redirect blocked/);
    expect(report.finalUrl).toBeNull();
    expect(report.findings.some((item) => item.code === "http-final")).toBe(false);
  });

  it("bounds HTML inspection", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      return new Response(`<html>${"x".repeat(300 * 1024)}</html>`, {
        headers: { "Content-Type": "text/html" },
      });
    }));

    const report = await analyzeUrl("https://example.com", 14);
    expect(report.http.truncated).toBe(true);
    expect(report.http.contentBytesInspected).toBe(256 * 1024);
  });
});

describe("DNS apex handling", () => {
  it("uses the public suffix list for multi-label suffixes", async () => {
    const queried: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      queried.push(`${url.searchParams.get("type")}:${url.searchParams.get("name")}`);
      return dnsResponse(url);
    }));
    await inspectDns("www.example.co.jp");
    expect(queried).toContain("NS:example.co.jp");
    expect(queried).toContain("CAA:example.co.jp");
  });
});
