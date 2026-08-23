import { describe, expect, it, vi } from "vitest";
import { mapDependencies, MAX_CT_RESPONSE_BYTES } from "../src/deps";

describe("mapDependencies", () => {
  it("parses CSP headers and extracts domains", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") {
        return Response.json([]);
      }
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {
        "content-security-policy": "default-src 'self'; script-src 'self' https://cdn.example.net https://js.stripe.com; connect-src 'self' https://api.example.com wss://sockets.example.com; img-src 'self' https://www.google-analytics.com",
      },
      [],
    );

    expect(result.sources.csp.present).toBe(true);
    expect(result.sources.csp.domains).toContain("cdn.example.net");
    expect(result.sources.csp.domains).toContain("js.stripe.com");
    expect(result.sources.csp.domains).toContain("www.google-analytics.com");
    expect(result.sources.csp.domains).toContain("sockets.example.com");
  });

  it("classifies known domains into categories", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") return Response.json([]);
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {
        "content-security-policy": "script-src 'self' https://www.google-analytics.com https://js.stripe.com https://js.pusher.com; connect-src https://cdn.cloudflare.com",
      },
      [],
    );

    const ga = result.domains.find((d) => d.domain === "www.google-analytics.com");
    expect(ga?.category).toBe("analytics");
    expect(ga?.piiRisk).toBe(true);

    const stripe = result.domains.find((d) => d.domain === "js.stripe.com");
    expect(stripe?.category).toBe("payment");
    expect(stripe?.piiRisk).toBe(true);

    const pusher = result.domains.find((d) => d.domain === "js.pusher.com");
    expect(pusher?.category).toBe("communication");

    const cf = result.domains.find((d) => d.domain === "cdn.cloudflare.com");
    expect(cf?.category).toBe("cdn");
  });

  it("scrapes JS bundles for embedded domains", async () => {
    const fakeJs = `
      const ws = new WebSocket("wss://socks.pusher.com/app?key=secret");
      fetch("https://api.chronogolf.com/api/v1/booking");
      var s = document.createElement('script');
      s.src = 'https://www.googletagmanager.com/gtag/js?id=G-XXXX';
    `;

    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") return Response.json([]);
      if (url.pathname.endsWith(".js")) {
        return new Response(fakeJs, {
          headers: { "Content-Type": "application/javascript" },
        });
      }
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {},
      [{ url: "https://cdn.example.com/app.js", host: "cdn.example.com" }],
    );

    expect(result.sources.jsBundles.bundlesFetched).toBe(1);
    expect(result.sources.jsBundles.domains).toContain("socks.pusher.com");
    expect(result.sources.jsBundles.domains).toContain("api.chronogolf.com");
    expect(result.sources.jsBundles.domains).toContain("www.googletagmanager.com");
  });

  it("queries Certificate Transparency for subdomains", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") {
        return Response.json([
          { name_value: "api.example.com" },
          { name_value: "www.example.com" },
          { name_value: "evil-example.com" },
          { name_value: "*.example.com" },
          { name_value: "staging.example.com\nadmin.example.com" },
        ]);
      }
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {},
      [],
    );

    expect(result.sources.certTransparency.total).toBe(4);
    expect(result.sources.certTransparency.subdomains).toContain("api.example.com");
    expect(result.sources.certTransparency.subdomains).toContain("www.example.com");
    expect(result.sources.certTransparency.subdomains).toContain("staging.example.com");
    expect(result.sources.certTransparency.subdomains).toContain("admin.example.com");
    expect(result.sources.certTransparency.subdomains).not.toContain("evil-example.com");
  });

  it("extracts wildcard-scheme hosts and rejects hashes, keeping host shape strict", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") return Response.json([]);
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {
        "content-security-policy": [
          "img-src https://*.cloudfront.net *.googleusercontent.com",
          "script-src 'sha256-abcdef123456' sharethis.com shard.example.net https://js.example.org/bundle.js",
        ].join("; "),
      },
      [],
    );

    expect(result.sources.csp.domains).toContain("cloudfront.net");
    expect(result.sources.csp.domains).toContain("googleusercontent.com");
    expect(result.sources.csp.domains).toContain("sharethis.com");
    expect(result.sources.csp.domains).toContain("shard.example.net");
    expect(result.sources.csp.domains).toContain("js.example.org");
    for (const domain of result.sources.csp.domains) {
      expect(domain, domain).toMatch(/^[a-z0-9.-]+$/);
      expect(domain, domain).not.toContain("/");
    }
  });

  it("reports Certificate Transparency truncation honestly in both directions", async () => {
    const manyNames = Array.from({ length: 130 }, (_, i) => ({
      name_value: `host-${String(i).padStart(3, "0")}.example.com`,
      not_before: "2026-01-01T00:00:00.000Z",
      not_after: "2027-01-01T00:00:00.000Z",
    }));
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") return Response.json(manyNames);
      return new Response("", { status: 404 });
    }));

    const overCap = await mapDependencies("example.com", new URL("https://example.com"), {}, []);
    expect(overCap.sources.certTransparency.subdomains.length).toBe(100);
    expect(overCap.sources.certTransparency.total).toBe(130);
    expect(overCap.sources.certTransparency.truncated).toBe(true);

    // Many certificates reusing few names is not truncation.
    const repeatedNames = Array.from({ length: 150 }, () => ({ name_value: "one.example.com" }));
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") return Response.json(repeatedNames);
      return new Response("", { status: 404 });
    }));

    const underCap = await mapDependencies("example.com", new URL("https://example.com"), {}, []);
    expect(underCap.sources.certTransparency.total).toBe(1);
    expect(underCap.sources.certTransparency.truncated).toBe(false);
  });

  it("keeps CT-observed domains out of the post-auth-only flag even when another source also saw them", async () => {
    const fakeJs = `fetch("https://api.example.com/v1/data");`;

    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") return Response.json([{ name_value: "api.example.com" }]);
      if (url.pathname.endsWith(".js")) {
        return new Response(fakeJs, { headers: { "Content-Type": "application/javascript" } });
      }
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {},
      [{ url: "https://cdn.example.com/app.js", host: "cdn.example.com" }],
    );

    const api = result.domains.find((d) => d.domain === "api.example.com");
    expect(api?.source).toBe("multiple");
    expect(api?.postAuthOnly).toBe(false);
  });

  it("handles missing CSP gracefully", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") return Response.json([]);
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {},
      [],
    );

    expect(result.sources.csp.present).toBe(false);
    expect(result.sources.csp.domains).toEqual([]);
  });

  it("marks post-auth-only domains correctly", async () => {
    const fakeJs = `fetch("https://ws.pusher.com/subscribe");`;

    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") return Response.json([]);
      if (url.pathname.endsWith(".js")) {
        return new Response(fakeJs, { headers: { "Content-Type": "application/javascript" } });
      }
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      { "content-security-policy": "script-src 'self' https://cdn.example.com" },
      [{ url: "https://cdn.example.com/app.js", host: "cdn.example.com" }],
    );

    const pusher = result.domains.find((d) => d.domain === "ws.pusher.com");
    expect(pusher).toBeDefined();
    expect(pusher?.postAuthOnly).toBe(true);
    expect(pusher?.source).toBe("js-bundle");
  });

  it("fails the CT analysis honestly when the crt.sh response exceeds the inspection cap", async () => {
    const oversized = `[{"name_value":"a.example.com"},"${"x".repeat(1024)}"` + ",1".repeat(MAX_CT_RESPONSE_BYTES);
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") {
        return new Response(oversized, { headers: { "Content-Type": "application/json" } });
      }
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {},
      [],
    );

    expect(result.sources.certTransparency.failed).toBe(1);
    expect(result.sources.certTransparency.truncated).toBe(true);
    expect(result.sources.certTransparency.error).toMatch(/inspection cap/);
    expect(result.sources.certTransparency.subdomains).toEqual([]);
  });

  it("reports invalid CT JSON as a failed analysis instead of throwing", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "crt.sh") {
        return new Response("<html>maintenance</html>", { headers: { "Content-Type": "text/html" } });
      }
      return new Response("", { status: 404 });
    }));

    const result = await mapDependencies(
      "example.com",
      new URL("https://example.com"),
      {},
      [],
    );

    expect(result.sources.certTransparency.failed).toBe(1);
    expect(result.sources.certTransparency.error).toMatch(/not valid JSON/);
  });
});
