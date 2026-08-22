import { afterEach, describe, expect, it, vi } from "vitest";
import { assertPublicTarget, fetchPublicUrl } from "../src/egress";
import { RequestBudget } from "../src/budget";

function dnsResponse(url: URL, status = 0, address = "93.184.216.34"): Response {
  const type = url.searchParams.get("type");
  return Response.json({
    Status: status,
    Answer: status === 0 && type === "A" ? [{ name: "target.example.", type: 1, TTL: 300, data: address }] : [],
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("shared public-target egress gate", () => {
  it("fails closed when one resolver family errors despite a public sibling answer", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" && url.searchParams.get("type") === "AAAA") return dnsResponse(url, -1);
      return dnsResponse(url);
    }));
    await expect(assertPublicTarget("target.example", new RequestBudget())).rejects.toThrow(/inconclusive/);
  });

  it("does not fetch a private redirect target", async () => {
    const requested: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      requested.push(url.toString());
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      return new Response(null, { status: 302, headers: { Location: "http://127.0.0.1/admin" } });
    }));
    await expect(fetchPublicUrl("https://target.example", new RequestBudget())).rejects.toThrow(/public|IP|redirect/i);
    expect(requested.some((value) => value.includes("127.0.0.1"))).toBe(false);
  });

  it("reuses a supplied validation memo instead of re-resolving the host", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      return new Response("<html></html>", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const memo = new Map([["target.example", {
      hostname: "target.example",
      addresses: ["93.184.216.34"],
      queries: [],
    }]]);
    const { response } = await fetchPublicUrl("https://target.example/bundle.js", new RequestBudget(), {}, 2, memo);
    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(memo.get("target.example")).toBeDefined();
  });

  it("caches each validated hostname into the supplied memo", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      return new Response(null, { status: 200 });
    }));

    const memo = new Map();
    await fetchPublicUrl("https://target.example/", new RequestBudget(), {}, 0, memo);
    expect(memo.get("target.example")?.addresses).toEqual(["93.184.216.34"]);
  });
});
