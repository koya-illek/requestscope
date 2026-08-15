import { describe, expect, it, vi } from "vitest";
import { mapDependencies } from "../src/deps";

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
});
