import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { retryAfterSeconds } from "../src/security";
import type { Env } from "../src/types";

const env = {
  ALLOWED_ORIGINS: "https://requestscope.illek.ie",
  REPORT_RETENTION_DAYS: "14",
  DAILY_SCAN_LIMIT: "15",
} as Env;

const ctx = {
  waitUntil() {},
  passThroughOnException() {},
  props: {},
} as unknown as ExecutionContext;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("API routing and input boundary", () => {
  it("serves no worker route for / because static assets own it", async () => {
    const response = await worker.fetch(new Request("https://api.example/"), env, ctx);
    expect(response.status).toBe(404);
    expect(response.headers.get("location")).toBeNull();
  });

  it("publishes endpoint discovery", async () => {
    const response = await worker.fetch(new Request("https://api.example/api"), env, ctx);
    expect(response.status).toBe(200);
    const body = await response.json<{ endpoints: Record<string, string>; documentation: Record<string, string> }>();
    expect(body.endpoints.streamScan).toBe("POST /api/scans/stream");
    expect(body.endpoints.urlRisk).toBe("POST /api/v1/url-risk");
    // Discovery must hand integrators the published contracts directly.
    expect(body.documentation).toEqual({ openapi: "/openapi.yaml", mcpConnector: "/mcp-copilot.yaml", privacy: "/privacy" });
  });

  it("rejects a body larger than the stream boundary even without relying on Content-Length", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://requestscope.illek.ie",
      },
      body: JSON.stringify({ url: `https://example.com/${"x".repeat(9000)}` }),
    }), env, ctx);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Request body is too large." });
  });

  it("checks the client limit before serving a cached scan", async () => {
    const cachedReport = { id: "cached-report" };
    let rateLimitChecks = 0;
    vi.stubGlobal("caches", {
      open: vi.fn(async () => ({
        match: vi.fn(async () => new Response(JSON.stringify(cachedReport))),
      })),
    });
    const db = {
      prepare: vi.fn(() => ({
        bind: vi.fn(() => ({
          first: vi.fn(async () => {
            rateLimitChecks += 1;
            return { request_count: 1 };
          }),
        })),
      })),
    } as unknown as D1Database;

    const response = await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" }),
    }), { ...env, DB: db }, ctx);

    expect(response.status).toBe(201);
    // A created report advertises its retrieval path per REST conventions.
    expect(response.headers.get("location")).toBe("/api/scans/cached-report");
    expect(response.headers.get("x-requestscope-recent-observation")).toBe("reused");
    expect(rateLimitChecks).toBe(1);
    expect(await response.json()).toEqual({ ...cachedReport, reusedRecentObservation: true });
  });

  it("bypasses scan accounting for an owner IP stored in a Worker secret", async () => {
    const cachedReport = { id: "owner-cached-report" };
    vi.stubGlobal("caches", {
      open: vi.fn(async () => ({
        match: vi.fn(async () => new Response(JSON.stringify(cachedReport))),
      })),
    });
    const db = { prepare: vi.fn(() => { throw new Error("rate limit storage should not be used"); }) } as unknown as D1Database;
    const response = await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.42" },
      body: JSON.stringify({ url: "https://example.com" }),
    }), { ...env, DB: db, RATE_LIMIT_BYPASS_IPS: "198.51.100.7, 203.0.113.42" }, ctx);
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({ ...cachedReport, reusedRecentObservation: true });
    expect(db.prepare).not.toHaveBeenCalled();
  });

  it("rejects disallowed browser origins", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.example" },
      body: JSON.stringify({ url: "https://example.com" }),
    }), env, ctx);
    expect(response.status).toBe(403);
  });

  it("validates bounded Copilot risk context", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/v1/url-risk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com", messageContext: "x".repeat(1001) }),
    }), env, ctx);
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "messageContext is too long." });
  });

  it("rejects non-boolean external reputation consent", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/v1/url-risk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com", externalReputation: "yes" }),
    }), env, ctx);
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "externalReputation must be a boolean." });
  });

  it("accepts the mobile observation profile on scan and risk boundaries", async () => {
    const db = { prepare: vi.fn(() => ({
      bind: vi.fn(() => ({ first: vi.fn(async () => ({ request_count: 1 })) })),
    })) } as unknown as D1Database;
    const servedKeys: string[] = [];
    vi.stubGlobal("caches", {
      open: vi.fn(async () => ({
        match: vi.fn(async (key: Request) => {
          servedKeys.push(key.url);
          return new Response(JSON.stringify({ id: "profiled-report" }));
        }),
      })),
    });
    const scan = await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com", mobileUserAgent: true }),
    }), { ...env, DB: db }, ctx);
    expect(scan.status).toBe(201);

    const risk = await worker.fetch(new Request("https://api.example/api/v1/url-risk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com", mobileUserAgent: true }),
    }), { ...env, DB: db }, ctx);
    expect(risk.status).toBe(200);

    // The recent-result cache is keyed by every observation option: the same
    // URL without the flag must be a distinct key, never answered by the
    // stored mobile observation.
    await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" }),
    }), { ...env, DB: db }, ctx);
    expect(servedKeys[2]).not.toBe(servedKeys[0]);
    expect(new Set(servedKeys).size).toBe(2);
  });

  it("does not share the recent-scan cache across clients", async () => {
    const servedKeys: string[] = [];
    const db = { prepare: vi.fn(() => ({
      bind: vi.fn(() => ({ first: vi.fn(async () => ({ request_count: 1 })) })),
    })) } as unknown as D1Database;
    vi.stubGlobal("caches", {
      open: vi.fn(async () => ({
        match: vi.fn(async (key: Request) => {
          servedKeys.push(key.url);
          return new Response(JSON.stringify({ id: "client-report" }));
        }),
      })),
    });
    for (const ip of ["203.0.113.10", "203.0.113.11"]) {
      await worker.fetch(new Request("https://api.example/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip },
        body: JSON.stringify({ url: "https://example.com" }),
      }), { ...env, DB: db }, ctx);
    }
    expect(servedKeys).toHaveLength(2);
    expect(servedKeys[0]).not.toBe(servedKeys[1]);
  });

  it("defaults MCP traces off the dependency map and charges two units when it is enabled", async () => {
    const servedKeys: string[] = [];
    const increments: number[] = [];
    const db = { prepare: vi.fn(() => ({
      bind: vi.fn((...values: unknown[]) => {
        if (typeof values[2] === "number") increments.push(values[2]);
        return { first: vi.fn(async () => ({ request_count: 1 })) };
      }),
    })) } as unknown as D1Database;
    vi.stubGlobal("caches", {
      open: vi.fn(async () => ({
        match: vi.fn(async (key: Request) => {
          servedKeys.push(key.url);
          return new Response(JSON.stringify({ id: "mcp-report", urlRisk: { verdict: "low" } }));
        }),
      })),
    });
    const mcpCall = (args: Record<string, unknown>) => worker.fetch(new Request("https://api.example/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "trace_request", arguments: args } }),
    }), { ...env, DB: db }, ctx);

    expect((await mcpCall({ url: "https://example.com" })).status).toBe(200);
    expect((await mcpCall({ url: "https://example.com", mapDependencies: true })).status).toBe(200);
    expect(servedKeys[0]).not.toBe(servedKeys[1]);
    expect(increments).toEqual([1, 2]);
  });

  it("rejects non-boolean mobile profile requests by name", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com", mobileUserAgent: "iPhone" }),
    }), env, ctx);
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "mobileUserAgent must be a boolean." });
  });

  it("rejects unknown scan fields instead of silently ignoring them", async () => {
    // A silently ignored "externalreputation" would return a trace whose
    // consented lookups never ran; the published schema says such a field is
    // a client bug, so the boundary names it.
    const db = { prepare: vi.fn(() => { throw new Error("quota must not be charged for a malformed body"); }) } as unknown as D1Database;
    const response = await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com", externalreputation: true }),
    }), { ...env, DB: db }, ctx);
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "Unsupported request field: externalreputation." });
    expect(db.prepare).not.toHaveBeenCalled();
  });

  it("rejects unknown url-risk fields at the same strictness as MCP arguments", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/v1/url-risk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com", mapDependencies: true }),
    }), env, ctx);
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "Unsupported request field: mapDependencies." });
  });

  it("protects the Copilot endpoint when an API credential is configured", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/v1/url-risk", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer wrong" },
      body: JSON.stringify({ url: "https://example.com" }),
    }), { ...env, COPILOT_API_KEY: "correct" }, ctx);
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: "Invalid API credential" });
  });

  it("rejects a blocked target at the HTTP boundary before the stream opens", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans/stream", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://requestscope.illek.ie",
      },
      body: JSON.stringify({ url: "http://127.0.0.1" }),
    }), env, ctx);
    expect(response.status).toBe(403);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("content-type")).not.toContain("ndjson");
    await expect(response.json()).resolves.toEqual({ error: "Direct IP address targets are not supported." });
  });

  it("answers an invalid stream target with 400 before charging quota", async () => {
    const db = { prepare: vi.fn(() => { throw new Error("quota must not be charged for an invalid target"); }) } as unknown as D1Database;
    const response = await worker.fetch(new Request("https://api.example/api/scans/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "not a url" }),
    }), { ...env, DB: db }, ctx);
    expect(response.status).toBe(400);
    expect(db.prepare).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({ error: "Enter a valid public URL." });
  });

  it("rate-limits the stream at the HTTP boundary and charges exactly once per request", async () => {
    const cachedReport = { id: "cached-stream-report" };
    vi.stubGlobal("caches", {
      open: vi.fn(async () => ({
        match: vi.fn(async () => new Response(JSON.stringify(cachedReport))),
      })),
    });
    let requestCount = 0;
    const db = {
      prepare: vi.fn(() => ({
        bind: vi.fn(() => ({ first: vi.fn(async () => ({ request_count: requestCount += 1 })) })),
      })),
    } as unknown as D1Database;
    const streamRequest = () => new Request("https://api.example/api/scans/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" }),
    });

    const first = await worker.fetch(streamRequest(), { ...env, DAILY_SCAN_LIMIT: "1", DB: db }, ctx);
    expect(first.status).toBe(200);
    const events = (await first.text()).trim().split("\n").map((line) => JSON.parse(line));
    expect(events[0]).toMatchObject({ type: "progress", stage: "accepted" });
    expect(events.at(-1)).toMatchObject({ type: "result", report: { ...cachedReport, reusedRecentObservation: true } });

    const second = await worker.fetch(streamRequest(), { ...env, DAILY_SCAN_LIMIT: "1", DB: db }, ctx);
    expect(second.status).toBe(429);
    // The back-off hint points at the UTC-daily window rollover that metered
    // the client, not an arbitrary fixed hour.
    expect(second.headers.get("retry-after")).toBe(String(retryAfterSeconds()));
    await expect(second.json()).resolves.toEqual({ error: "Daily anonymous scan limit of 1 reached." });
    // One charge per stream request: the boundary metered it, so the
    // createScan call inside the stream must not meter again.
    expect(requestCount).toBe(2);
  });

  it("delivers mid-trace failures as in-band NDJSON error events", async () => {
    // Inconclusive public-DNS resolution is discovered only once the trace
    // has started, so it cannot be an HTTP status any more: the stream
    // reports it as a structured error event instead.
    vi.stubGlobal("caches", {
      open: vi.fn(async () => ({ match: vi.fn(async () => null) })),
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response("resolver unavailable", { status: 503 })));
    const db = {
      prepare: vi.fn(() => ({
        bind: vi.fn(() => ({ first: vi.fn(async () => ({ request_count: 1 })) })),
      })),
    } as unknown as D1Database;
    const response = await worker.fetch(new Request("https://api.example/api/scans/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com/trace-fails-late" }),
    }), { ...env, DB: db }, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/x-ndjson");
    const events = (await response.text()).trim().split("\n").map((line) => JSON.parse(line));
    expect(events[0].type).toBe("progress");
    expect(events.at(-1)).toMatchObject({ type: "error", status: 403 });
  });

  it("logs a non-identifying completion line for fresh scans", async () => {
    const dnsResponse = (url: URL) => Response.json({
      Status: 0,
      AD: true,
      Answer: url.searchParams.get("type") === "A"
        ? [{ name: `${url.searchParams.get("name") || "example.com"}.`, type: 1, TTL: 300, data: "93.184.216.34" }]
        : [],
    });
    vi.stubGlobal("caches", {
      open: vi.fn(async () => ({ match: vi.fn(async () => null), put: vi.fn(async () => {}) })),
    });
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
      if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return dnsResponse(url);
      return new Response("<html><body>ok</body></html>", {
        status: 200,
        headers: { "Content-Type": "text/html", "Cache-Control": "public, max-age=60" },
      });
    }));
    const db = {
      prepare: vi.fn((sql: string) => ({
        bind: vi.fn(() => ({
          first: vi.fn(async () => (sql.includes("rate_limits") ? { request_count: 1 } : undefined)),
          run: vi.fn(async () => {}),
        })),
      })),
    } as unknown as D1Database;
    const logged: string[] = [];
    const logSpy = vi.spyOn(console, "log").mockImplementation((...parts: unknown[]) => {
      logged.push(parts.map((part) => String(part)).join(" "));
    });

    const response = await worker.fetch(new Request("https://api.example/api/scans/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com/observed-page" }),
    }), { ...env, DB: db }, ctx);
    expect(response.status).toBe(200);
    const events = (await response.text()).trim().split("\n").map((line) => JSON.parse(line));
    expect(events.at(-1)).toMatchObject({ type: "result", report: { status: "complete" } });

    logSpy.mockRestore();
    const completion = logged.find((line) => line.startsWith("scan_completed"));
    expect(completion).toBeTruthy();
    // The product promises that targets and hostnames never reach logs; the
    // operational line must carry counters only.
    expect(completion).not.toContain("example.com");
    expect(completion).toMatch(/"status":"complete"/);
  });

  it("does not write D1 for MCP handshake or discovery", async () => {
    const db = { prepare: vi.fn(() => { throw new Error("MCP handshake must not touch D1"); }) } as unknown as D1Database;
    const response = await worker.fetch(new Request("https://api.example/mcp/v2", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    }), { ...env, DB: db }, ctx);
    expect(response.status).toBe(200);
    expect(db.prepare).not.toHaveBeenCalled();
  });

  it("rate-limits report retrieval durably and reads the report from D1", async () => {
    const report = { id: "abcdefghijklmnop" };
    const prepare = vi.fn((sql: string) => ({
      bind: vi.fn(() => ({ first: vi.fn(async () => sql.trimStart().startsWith("SELECT") ? { report_json: JSON.stringify(report) } : undefined) })),
    }));
    const response = await worker.fetch(new Request("https://api.example/api/scans/abcdefghijklmnop"), { ...env, DB: { prepare } as unknown as D1Database }, ctx);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(report);
    expect(prepare).toHaveBeenCalledTimes(2);
    expect(prepare.mock.calls[0][0]).toMatch(/^\s*SELECT/i);
    expect(prepare.mock.calls[1][0]).toMatch(/^\s*INSERT INTO rate_limits/i);
    // Stored reports are immutable, so the report ID is published as a
    // strong validator for conditional retrieval.
    expect(response.headers.get("etag")).toBe('"abcdefghijklmnop"');
  });

  it("does not write rate-limit rows for a well-formed missing report ID", async () => {
    const prepare = vi.fn((sql: string) => ({
      bind: vi.fn(() => ({ first: vi.fn(async () => sql.trimStart().startsWith("SELECT") ? undefined : { request_count: 1 }) })),
    }));
    const response = await worker.fetch(new Request("https://api.example/api/scans/abcdefghijklmnop"), { ...env, DB: { prepare } as unknown as D1Database }, ctx);
    expect(response.status).toBe(404);
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(prepare.mock.calls[0][0]).toMatch(/^\s*SELECT/i);
  });

  it("serves stored reports conditionally and keeps the quota charged on a hit", async () => {
    const report = { id: "abcdefghijklmnop" };
    const prepare = vi.fn((sql: string) => ({
      bind: vi.fn(() => ({ first: vi.fn(async () => sql.trimStart().startsWith("SELECT") ? { report_json: JSON.stringify(report) } : undefined) })),
    }));
    const envWithDb = { ...env, DB: { prepare } as unknown as D1Database };
    for (const header of ['"abcdefghijklmnop"', 'W/"abcdefghijklmnop"', '"stale-value", "abcdefghijklmnop"', "*"]) {
      const response = await worker.fetch(new Request("https://api.example/api/scans/abcdefghijklmnop", {
        headers: { "If-None-Match": header },
      }), envWithDb, ctx);
      expect(response.status, `If-None-Match: ${header}`).toBe(304);
      expect(await response.text()).toBe("");
      expect(response.headers.get("etag")).toBe('"abcdefghijklmnop"');
      expect(response.headers.get("cache-control")).toBe("private, max-age=60");
    }
    // Every 304 still consumed quota and re-read D1: two prepare calls
    // (report select, then rate-limit write) per conditional request.
    expect(prepare).toHaveBeenCalledTimes(8);
    const miss = await worker.fetch(new Request("https://api.example/api/scans/abcdefghijklmnop", {
      headers: { "If-None-Match": '"different-report-id"' },
    }), envWithDb, ctx);
    expect(miss.status).toBe(200);
    expect(await miss.json()).toEqual(report);

    const exportHit = await worker.fetch(new Request("https://api.example/api/scans/abcdefghijklmnop/export", {
      headers: { "If-None-Match": '"abcdefghijklmnop"' },
    }), envWithDb, ctx);
    expect(exportHit.status).toBe(304);
    expect(exportHit.headers.get("content-disposition")).toBeNull();
  });
});

describe("rate-limited public access", () => {
  it("allows the production custom origin", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/health", {
      headers: { Origin: "https://requestscope.illek.ie" },
    }), env, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe("https://requestscope.illek.ie");
    await expect(response.json()).resolves.toMatchObject({ protection: "rate-limit", sourceRevision: "uncommitted-source", databaseSchemaVersion: 1 });
  });

  it("exposes operational headers to cross-origin browser clients", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/health", {
      headers: { Origin: "https://requestscope.illek.ie" },
    }), env, ctx);
    // Without Expose-Headers a cross-origin fetch cannot read the ETag,
    // creation Location, Retry-After, or export disposition at all, so
    // browser-based integrators could never implement conditional GETs or
    // honour the back-off hint.
    expect(response.headers.get("access-control-expose-headers")).toBe("ETag, Location, Retry-After, Content-Disposition, X-RequestScope-Recent-Observation");
  });
});

describe("scheduled retention cleanup", () => {
  it("deletes expired reports and stale quota rows in one D1 batch", async () => {
    const statements: Array<{ sql: string; values: unknown[] }> = [];
    const prepare = vi.fn((sql: string) => {
      const statement = {
        sql,
        values: [] as unknown[],
        bind: vi.fn((...values: unknown[]) => {
          statement.values = values;
          return statement;
        }),
      };
      statements.push(statement);
      return statement;
    });
    const batch = vi.fn(async () => [
      { meta: { changes: 3 } },
      { meta: { changes: 12 } },
      { meta: { changes: 1 } },
    ] as D1Result[]);
    const db = { prepare, batch } as unknown as D1Database;
    const pending: Promise<unknown>[] = [];
    const scheduledContext = {
      waitUntil(promise: Promise<unknown>) {
        pending.push(promise);
      },
      passThroughOnException() {},
      props: {},
    } as unknown as ExecutionContext;
    const logged: string[] = [];
    const logSpy = vi.spyOn(console, "log").mockImplementation((...parts: unknown[]) => {
      logged.push(parts.map((part) => String(part)).join(" "));
    });

    await worker.scheduled({} as ScheduledController, { ...env, DB: db }, scheduledContext);
    expect(pending).toHaveLength(1);
    await Promise.all(pending);
    logSpy.mockRestore();

    expect(batch).toHaveBeenCalledOnce();
    expect(batch).toHaveBeenCalledWith(statements);
    expect(statements).toHaveLength(3);
    expect(statements[0].sql).toMatch(/DELETE FROM scans WHERE expires_at <= \?/);
    expect(statements[0].values).toHaveLength(1);
    expect(prepare).toHaveBeenCalledTimes(3);
    expect(prepare.mock.calls[1][0]).toMatch(/DELETE FROM rate_limits WHERE window_date < date\('now', '-2 day'\)/);
    expect(prepare.mock.calls[2][0]).toMatch(/DELETE FROM provider_usage WHERE updated_at < datetime\('now', '-90 day'\)/);
    // Free observability with the same hygiene contract as scan_completed:
    // deleted-row counters only, never report contents or identifiers.
    const completion = logged.find((line) => line.startsWith("cleanup_completed"));
    expect(completion).toBe('cleanup_completed {"expiredReports":3,"staleRateLimits":12,"staleProviderUsage":1}');
  });
});

describe("HEAD probes on read endpoints", () => {
  it("answers HEAD /api/health with GET headers and no body", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/health", { method: "HEAD" }), env, ctx);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("");
    expect(response.headers.get("x-robots-tag")).toBe("noindex, nofollow");
    expect(response.headers.get("content-type")).toContain("application/json");
  });

  it("answers HEAD report and export requests with the same caching headers as GET", async () => {
    const report = { id: "abcdefghijklmnop" };
    const prepare = vi.fn((sql: string) => ({
      bind: vi.fn(() => ({ first: vi.fn(async () => sql.trimStart().startsWith("SELECT") ? { report_json: JSON.stringify(report) } : undefined) })),
    }));
    const envWithDb = { ...env, DB: { prepare } as unknown as D1Database };
    const head = await worker.fetch(new Request("https://api.example/api/scans/abcdefghijklmnop", { method: "HEAD" }), envWithDb, ctx);
    expect(head.status).toBe(200);
    expect(head.headers.get("cache-control")).toBe("private, max-age=60");
    expect(await head.text()).toBe("");
    const exportHead = await worker.fetch(new Request("https://api.example/api/scans/abcdefghijklmnop/export", { method: "HEAD" }), envWithDb, ctx);
    expect(exportHead.status).toBe(200);
    expect(exportHead.headers.get("content-disposition")).toContain("attachment");
    expect(await exportHead.text()).toBe("");
  });

  it("keeps write routes closed to HEAD with a method-aware status", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans", { method: "HEAD" }), env, ctx);
    // The route exists and is open for POST only, so HEAD is a 405 with an
    // Allow header, not a 404 that misdescribes the resource as missing.
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST, OPTIONS");
  });

  it("answers unsupported methods on known routes with 405 and Allow", async () => {
    const cases: Array<[string, Request, string]> = [
      ["GET /api/scans", new Request("https://api.example/api/scans", { method: "GET" }), "POST, OPTIONS"],
      ["GET /api/scans/stream", new Request("https://api.example/api/scans/stream", { method: "GET" }), "POST, OPTIONS"],
      ["DELETE stored report", new Request("https://api.example/api/scans/abcdefghijklmnop", { method: "DELETE" }), "GET, HEAD, OPTIONS"],
      ["POST export", new Request("https://api.example/api/scans/abcdefghijklmnop/export", { method: "POST" }), "GET, HEAD, OPTIONS"],
      ["PUT health", new Request("https://api.example/api/health", { method: "PUT" }), "GET, HEAD, OPTIONS"],
      ["POST discovery", new Request("https://api.example/api", { method: "POST" }), "GET, HEAD, OPTIONS"],
    ];
    for (const [label, request, allow] of cases) {
      const response = await worker.fetch(request, env, ctx);
      expect(response.status, label).toBe(405);
      expect(response.headers.get("allow"), label).toBe(allow);
      await expect(response.json(), label).resolves.toEqual({ error: `Method not allowed. Allowed: ${allow}.` });
    }
  });
});
