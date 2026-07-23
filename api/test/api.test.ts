import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { verifyTurnstile } from "../src/index";
import type { Env } from "../src/types";

const env = {
  ENVIRONMENT: "test",
  ALLOWED_ORIGINS: "https://requestscope.pages.dev",
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
  it("redirects human visitors from the Worker root", async () => {
    const response = await worker.fetch(new Request("https://api.example/"), env, ctx);
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("https://requestscope.pages.dev/");
  });

  it("publishes endpoint discovery", async () => {
    const response = await worker.fetch(new Request("https://api.example/api"), env, ctx);
    expect(response.status).toBe(200);
    const body = await response.json<{ endpoints: Record<string, string> }>();
    expect(body.endpoints.streamScan).toBe("POST /api/scans/stream");
  });

  it("rejects a body larger than the stream boundary even without relying on Content-Length", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://requestscope.pages.dev",
      },
      body: JSON.stringify({ url: `https://example.com/${"x".repeat(9000)}` }),
    }), env, ctx);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Request body is too large." });
  });

  it("rejects disallowed browser origins", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.example" },
      body: JSON.stringify({ url: "https://example.com" }),
    }), env, ctx);
    expect(response.status).toBe(403);
  });

  it("streams a structured error for a blocked target", async () => {
    const response = await worker.fetch(new Request("https://api.example/api/scans/stream", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://requestscope.pages.dev",
      },
      body: JSON.stringify({ url: "http://127.0.0.1" }),
    }), env, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/x-ndjson");
    const events = (await response.text()).trim().split("\n").map((line) => JSON.parse(line));
    expect(events[0].type).toBe("progress");
    expect(events.at(-1)).toMatchObject({ type: "error", status: 403 });
  });
});

describe("Turnstile verification", () => {
  it("accepts only the configured hostname and action", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      success: true,
      hostname: "requestscope.pages.dev",
      action: "requestscope_scan",
    })));
    await expect(verifyTurnstile(
      new Request("https://api.example/api/scans"),
      "valid-token",
      { ...env, TURNSTILE_SECRET: "secret" },
    )).resolves.toBeUndefined();
  });

  it("rejects a token minted for a different action", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      success: true,
      hostname: "requestscope.pages.dev",
      action: "other_action",
    })));
    await expect(verifyTurnstile(
      new Request("https://api.example/api/scans"),
      "wrong-action-token",
      { ...env, TURNSTILE_SECRET: "secret" },
    )).rejects.toThrow(/verification failed/i);
  });
});
