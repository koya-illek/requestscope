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
          <form action="https://collector.example.net/session"><input type="password"></form>
          <p>Verify your account and reset your password.</p>
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
    expect(report.pageSecuritySignals).toMatchObject({
      passwordForm: true,
      forms: 1,
      externalFormAction: true,
      matchedLanguage: expect.arrayContaining(["verification", "password-reset"]),
    });
    expect(report.urlRisk?.findings.some((item) => item.code === "external-form-action")).toBe(true);
    expect(stages).toEqual(expect.arrayContaining(["validated", "dns", "hop", "response", "complete"]));
  });

  it("fetches dependency scripts with their original query values while storing them redacted", async () => {
    const requested: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      requested.push(url.toString());
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      if (url.hostname === "crt.sh") return Response.json([]);
      return new Response('<html><script src="https://cdn.example.net/app.js?v=1.2.3"></script></html>', {
        headers: { "Content-Type": "text/html" },
      });
    }));

    const report = await analyzeUrl("https://example.com", 14, {}, () => {}, { mapDependencies: true });
    expect(requested).toContain("https://cdn.example.net/app.js?v=1.2.3");
    expect(requested.some((value) => value.includes("%5Bredacted%5D"))).toBe(false);
    expect(report.dependencies.items[0]?.url).toContain("v=%5Bredacted%5D");
  });

  it("observes through the requested device profile and records it in the report", async () => {
    const userAgents: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      if (url.hostname === "crt.sh") return Response.json([]);
      userAgents.push(String(new Headers(init?.headers).get("User-Agent")));
      return new Response('<html><script src="https://cdn.example.net/app.js"></script></html>', {
        headers: { "Content-Type": "text/html" },
      });
    }));

    const mobile = await analyzeUrl("https://example.com", 14, {}, () => {}, { mapDependencies: true, deviceProfile: "mobile" });
    expect(mobile.observation.deviceProfile).toBe("mobile");
    // The embedded risk assessment must carry the profile too, so
    // assess_url_risk consumers can tell which identity observed the target.
    expect(mobile.urlRisk?.deviceProfile).toBe("mobile");
    // Core hop and dependency bundle requests both carry the mobile identity.
    expect(userAgents.length).toBeGreaterThanOrEqual(2);
    expect(userAgents.every((agent) => agent.includes("iPhone"))).toBe(true);

    userAgents.length = 0;
    const desktop = await analyzeUrl("https://example.com", 14, {}, () => {}, { mapDependencies: true });
    expect(desktop.observation.deviceProfile).toBe("desktop");
    expect(userAgents.every((agent) => agent.startsWith("RequestScope/1.0"))).toBe(true);
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

  it("fails closed when a resolver errors instead of treating a sibling answer as enough", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
        if (url.searchParams.get("type") === "AAAA" && url.hostname === "cloudflare-dns.com") return new Response(null, { status: 503 });
        return dnsResponse(url);
      }
      return new Response("ok", { headers: { "Content-Type": "text/html" } });
    }));
    await expect(analyzeUrl("https://example.com", 14)).rejects.toThrow(/inconclusive|DNS/i);
  });

  it("does not fetch a private dependency script or a script redirect escape", async () => {
    const requested: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      requested.push(url.toString());
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      if (url.hostname === "crt.sh") return Response.json([]);
      if (url.pathname.endsWith("/private.js")) return new Response("alert(1)");
      if (url.pathname.endsWith("/redirect.js")) return new Response(null, { status: 302, headers: { Location: "http://127.0.0.1/metadata" } });
      return new Response('<html><script src="http://127.0.0.1/private.js"></script><script src="https://cdn.example.net/redirect.js"></script></html>', {
        headers: { "Content-Type": "text/html" },
      });
    }));
    const report = await analyzeUrl("https://example.com", 14, {}, () => {}, { mapDependencies: true });
    expect(report.coverage?.phases.dependencies.status).toMatch(/complete|partial/);
    expect(requested.some((value) => value.includes("127.0.0.1"))).toBe(false);
  });

  it("reports requested-but-impossible phases as unavailable, not skipped or complete", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      return new Response(null, { status: 302, headers: { Location: "http://127.0.0.1/admin" } });
    }));

    const blocked = await analyzeUrl("https://example.com", 14, {}, () => {}, { mapDependencies: true });
    expect(blocked.coverage?.phases.dependencies.status).toBe("unavailable");
    expect(blocked.coverage?.phases.dependencies.skipped).toBe(0);
    expect(blocked.coverage?.phases.dependencies.detail).toContain("was requested but");

    const unconfigured = await analyzeUrl("https://example.com", 14, {}, () => {}, {
      reputation: { enabled: true },
    });
    expect(unconfigured.coverage?.phases.reputation.status).toBe("unavailable");
    expect(unconfigured.coverage?.phases.reputation.detail).toContain("No reputation provider is configured");

    const optedOut = await analyzeUrl("https://example.com", 14);
    expect(optedOut.coverage?.phases.reputation.status).toBe("skipped");
    expect(optedOut.coverage?.phases.reputation.skipped).toBe(1);
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
