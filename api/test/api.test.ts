import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
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
    expect(rateLimitChecks).toBe(1);
    expect(await response.json()).toEqual(cachedReport);
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
    expect(await response.json()).toEqual(cachedReport);
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

  it("requires external reputation consent to be an explicit boolean", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/v1/url-risk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com", externalReputation: "yes" }),
    }), env, ctx);
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "externalReputation must be a boolean." });
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

  it("streams a structured error for a blocked target", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans/stream", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://requestscope.illek.ie",
      },
      body: JSON.stringify({ url: "http://127.0.0.1" }),
    }), env, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/x-ndjson");
    const events = (await response.text()).trim().split("\n").map((line) => JSON.parse(line));
    expect(events[0].type).toBe("progress");
    expect(events.at(-1)).toMatchObject({ type: "error", status: 403 });
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
    expect(prepare.mock.calls[0][0]).toMatch(/^\s*INSERT INTO rate_limits/i);
    expect(prepare.mock.calls[1][0]).toMatch(/^\s*SELECT/i);
    // Stored reports are immutable, so the report ID is published as a
    // strong validator for conditional retrieval.
    expect(response.headers.get("etag")).toBe('"abcdefghijklmnop"');
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
    // (rate-limit write, report select) per conditional request.
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
    const batch = vi.fn(async () => []);
    const db = { prepare, batch } as unknown as D1Database;
    const pending: Promise<unknown>[] = [];
    const scheduledContext = {
      waitUntil(promise: Promise<unknown>) {
        pending.push(promise);
      },
      passThroughOnException() {},
      props: {},
    } as unknown as ExecutionContext;

    await worker.scheduled({} as ScheduledController, { ...env, DB: db }, scheduledContext);
    expect(pending).toHaveLength(1);
    await Promise.all(pending);

    expect(batch).toHaveBeenCalledOnce();
    expect(batch).toHaveBeenCalledWith(statements);
    expect(statements).toHaveLength(3);
    expect(statements[0].sql).toMatch(/DELETE FROM scans WHERE expires_at <= \?/);
    expect(statements[0].values).toHaveLength(1);
    expect(prepare).toHaveBeenCalledTimes(3);
    expect(prepare.mock.calls[1][0]).toMatch(/DELETE FROM rate_limits WHERE window_date < date\('now', '-2 day'\)/);
    expect(prepare.mock.calls[2][0]).toMatch(/DELETE FROM provider_usage WHERE updated_at < datetime\('now', '-90 day'\)/);
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

  it("keeps write routes closed to HEAD", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans", { method: "HEAD" }), env, ctx);
    expect(response.status).toBe(404);
  });
});
