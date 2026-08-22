import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkExternalReputation } from "../src/reputation";

const fixedNow = () => new Date("2026-08-14T12:00:00.000Z");

beforeEach(() => {
  const entries = new Map<string, Response>();
  vi.stubGlobal("caches", {
    open: vi.fn(async () => ({
      match: vi.fn(async (request: Request) => entries.get(request.url)?.clone()),
      put: vi.fn(async (request: Request, response: Response) => { entries.set(request.url, response.clone()); }),
    })),
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("external reputation", () => {
  it("does nothing until a caller explicitly opts in", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const assessment = await checkExternalReputation("https://example.com/", null, { enabled: false, now: fixedNow });
    expect(assessment.status).toBe("not_requested");
    expect(assessment.providers).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("combines Google Web Risk and PhishTank without returning the raw URL", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "webrisk.googleapis.com") {
        expect(url.searchParams.get("uri")).toContain("token=private-value");
        return Response.json({
          threat: {
            threatTypes: ["SOCIAL_ENGINEERING"],
            expireTime: "2026-08-14T12:20:00.000Z",
          },
        });
      }
      expect(String(init?.body)).toContain("private-value");
      return Response.json({ results: { in_database: false } });
    });
    vi.stubGlobal("fetch", fetchMock);

    const assessment = await checkExternalReputation(
      "https://example.com/login?token=private-value",
      null,
      {
        enabled: true,
        googleWebRiskApiKey: "google-key",
        phishTankAppKey: "phishtank-key",
        consumeQuota: async () => true,
        now: fixedNow,
      },
    );

    expect(assessment.status).toBe("matched");
    expect(assessment.providers.filter((item) => item.status !== "not_configured")).toHaveLength(2);
    expect(assessment.providers.find((item) => item.provider === "google_web_risk")).toMatchObject({
      status: "matched",
      threatTypes: ["SOCIAL_ENGINEERING"],
      attribution: "Advisory provided by Google",
    });
    expect(JSON.stringify(assessment)).not.toContain("private-value");
  });

  it("stops before calling a provider when the RequestScope quota is exhausted", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const assessment = await checkExternalReputation("https://example.com/", null, {
      enabled: true,
      googleWebRiskApiKey: "google-key",
      consumeQuota: async () => false,
      now: fixedNow,
    });
    expect(assessment.status).toBe("unavailable");
    expect(assessment.providers.find((item) => item.provider === "google_web_risk")?.status).toBe("quota_limited");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("supports PhishTank's documented keyless mode without sending a blank app key", async () => {
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      expect(String(init?.body)).not.toContain("app_key");
      expect(new Headers(init?.headers).get("user-agent")).toBe("phishtank/requestscope (+https://requestscope.illek.ie)");
      return Response.json({ results: { in_database: false } });
    });
    vi.stubGlobal("fetch", fetchMock);
    const assessment = await checkExternalReputation("https://example.com/", null, {
      enabled: true,
      phishTankEnabled: true,
      consumeQuota: async () => true,
      now: fixedNow,
    });
    expect(assessment.status).toBe("not_listed");
    expect(assessment.providers.find((item) => item.provider === "phishtank")).toMatchObject({
      provider: "phishtank",
      status: "not_listed",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("treats Cloudflare's documented 0.0.0.0 malware response as a hostname-level match", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      expect(url.hostname).toBe("security.cloudflare-dns.com");
      expect(url.searchParams.get("name")).toBe("malware.testcategory.com");
      expect(url.search).not.toContain("private-value");
      return Response.json({ Status: 0, Answer: [{ type: 1, data: "0.0.0.0" }] });
    });
    vi.stubGlobal("fetch", fetchMock);
    const assessment = await checkExternalReputation(
      "https://malware.testcategory.com/path?token=private-value",
      null,
      {
        enabled: true,
        cloudflareFamilyDnsEnabled: true,
        consumeQuota: async () => true,
        now: fixedNow,
      },
    );
    expect(assessment.status).toBe("matched");
    expect(assessment.providers.find((item) => item.provider === "cloudflare_family_dns")).toMatchObject({
      status: "matched",
      threatTypes: ["MALWARE_OR_PHISHING_DOMAIN"],
    });
    expect(JSON.stringify(assessment)).not.toContain("private-value");
  });

  it("reuses cached results without consuming quota again", async () => {
    const consumeQuota = vi.fn(async () => true);
    const fetchMock = vi.fn(async () => Response.json({}));
    vi.stubGlobal("fetch", fetchMock);
    const config = { enabled: true, googleWebRiskApiKey: "google-key", consumeQuota, now: fixedNow };
    await checkExternalReputation("https://example.com/", null, config);
    await checkExternalReputation("https://example.com/", null, config);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(consumeQuota).toHaveBeenCalledTimes(1);
  });

  it("still checks the final URL when a redirect changes only query values", async () => {
    const checkedUris: string[] = [];
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "webrisk.googleapis.com") {
        checkedUris.push(url.searchParams.get("uri") || "");
        return Response.json({});
      }
      return Response.json({ results: { in_database: false } });
    });
    vi.stubGlobal("fetch", fetchMock);

    await checkExternalReputation(
      "https://landing.example/login?utm_source=mail",
      "https://landing.example/login?sid=victim-session",
      { enabled: true, googleWebRiskApiKey: "google-key", consumeQuota: async () => true, now: fixedNow },
    );

    expect(checkedUris).toContain("https://landing.example/login?utm_source=mail");
    expect(checkedUris).toContain("https://landing.example/login?sid=victim-session");
  });
});
