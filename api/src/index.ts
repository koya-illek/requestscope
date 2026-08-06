import { analyzeUrl, type AnalyzerProgress } from "./analyzer";
import {
  allowedOrigin,
  BlockedTargetError,
  InputError,
  normalizeUrl,
} from "./security";
import type { Env, ScanReport } from "./types";

const API_VERSION = "1.1.0";
const REPORT_ID = /^[A-Za-z0-9_-]{16}$/;
const MAX_REQUEST_BYTES = 8192;
const RECENT_SCAN_TTL = 300;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const origin = allowedOrigin(request, env.ALLOWED_ORIGINS || "");
    const cors = corsHeaders(origin);

    if (request.method === "OPTIONS") {
      if (request.headers.get("Origin") && !origin) return json({ error: "Origin not allowed" }, 403);
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      if (url.pathname === "/" && (request.method === "GET" || request.method === "HEAD")) {
        return Response.redirect("https://requestscope.pages.dev/", 302);
      }

      if ((url.pathname === "/api" || url.pathname === "/api/") && request.method === "GET") {
        return json({
          service: "RequestScope API",
          version: API_VERSION,
          website: "https://requestscope.pages.dev/",
          endpoints: {
            health: "GET /api/health",
            createScan: "POST /api/scans",
            streamScan: "POST /api/scans/stream",
            getScan: "GET /api/scans/:id",
            exportScan: "GET /api/scans/:id/export",
          },
        }, 200, cors);
      }

      if (url.pathname === "/api/health" && request.method === "GET") {
        return json({
          ok: true,
          service: "requestscope-api",
          version: API_VERSION,
          environment: env.ENVIRONMENT,
          protection: "rate-limit",
          time: new Date().toISOString(),
        }, 200, cors);
      }

      if ((url.pathname === "/api/scans" || url.pathname === "/api/scans/stream") && request.method === "POST") {
        if (request.headers.get("Origin") && !origin) return json({ error: "Origin not allowed" }, 403, cors);
        const input = await readScanInput(request);
        if (url.pathname.endsWith("/stream")) {
          return streamScan(request, input, env, ctx, cors);
        }
        const report = await createScan(request, input, env, ctx);
        return json(report, 201, { ...cors, "Cache-Control": "no-store" });
      }

      const match = url.pathname.match(/^\/api\/scans\/([A-Za-z0-9_-]+)(\/export)?$/);
      if (match && request.method === "GET") {
        if (!REPORT_ID.test(match[1])) return json({ error: "Report not found" }, 404, cors);
        const report = await loadReport(env.DB, match[1]);
        if (!report) return json({ error: "Report not found or expired" }, 404, cors);
        if (match[2]) {
          return new Response(JSON.stringify(report, null, 2), {
            headers: {
              ...cors,
              "Content-Type": "application/json; charset=utf-8",
              "Content-Disposition": `attachment; filename="requestscope-${report.id}.json"`,
              "Cache-Control": "private, max-age=60",
              ...securityHeaders(),
            },
          });
        }
        return json(report, 200, { ...cors, "Cache-Control": "public, max-age=60" });
      }

      return json({ error: "Not found" }, 404, cors);
    } catch (error) {
      return errorResponse(error, cors);
    }
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(cleanExpired(env.DB));
  },
};

interface ScanInput {
  url: string;
  mapDependencies?: boolean;
}

class RateLimitError extends Error {}

async function readScanInput(request: Request): Promise<ScanInput> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new InputError("Content-Type must be application/json.");
  }
  if (!request.body) throw new InputError("Request body is required.");

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_REQUEST_BYTES) {
        await reader.cancel();
        throw new InputError("Request body is too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new InputError("Invalid JSON request body.");
  }
  if (!parsed || typeof parsed !== "object") throw new InputError("JSON request body must be an object.");
  const body = parsed as Record<string, unknown>;
  if (typeof body.url !== "string") throw new InputError("A URL is required.");
  if (body.mapDependencies !== undefined && typeof body.mapDependencies !== "boolean") {
    throw new InputError("mapDependencies must be a boolean.");
  }
  return {
    url: body.url,
    mapDependencies: body.mapDependencies === true,
  };
}

async function createScan(
  request: Request,
  input: ScanInput,
  env: Env,
  ctx: ExecutionContext,
  onProgress: (event: AnalyzerProgress) => void = () => {},
): Promise<ScanReport> {
  const normalized = normalizeUrl(input.url);
  await enforceRateLimit(request, env);
  const cacheKey = await recentScanCacheKey(request.url, normalized.toString());
  const recentCache = await caches.open("requestscope-recent");
  const cached = await recentCache.match(cacheKey);
  if (cached) {
    const report = await cached.json<ScanReport>();
    onProgress({ stage: "complete", message: "Loaded a recent edge observation" });
    return report;
  }

  const retention = clampInt(env.REPORT_RETENTION_DAYS, 14, 1, 90);
  const incomingCf = request.cf as Record<string, unknown> | undefined;
  const report = await analyzeUrl(input.url, retention, {
    colo: typeof incomingCf?.colo === "string" ? incomingCf.colo : undefined,
    country: typeof incomingCf?.country === "string" ? incomingCf.country : undefined,
  }, onProgress, { mapDependencies: input.mapDependencies });
  await saveReport(env.DB, report);
  const cacheResponse = new Response(JSON.stringify(report), {
    headers: { "Content-Type": "application/json", "Cache-Control": `public, max-age=${RECENT_SCAN_TTL}` },
  });
  ctx.waitUntil(recentCache.put(cacheKey, cacheResponse));
  return report;
}

function streamScan(
  request: Request,
  input: ScanInput,
  env: Env,
  ctx: ExecutionContext,
  cors: Record<string, string>,
): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (value: unknown) => controller.enqueue(encoder.encode(`${JSON.stringify(value)}\n`));
      try {
        send({ type: "progress", stage: "accepted", message: "Trace accepted" });
        const report = await createScan(request, input, env, ctx, (event) => send({ type: "progress", ...event }));
        send({ type: "result", report });
      } catch (error) {
        const normalized = normalizeError(error);
        send({ type: "error", error: normalized.message, status: normalized.status });
      } finally {
        controller.close();
      }
    },
  });
  return new Response(stream, {
    status: 200,
    headers: {
      ...cors,
      ...securityHeaders(),
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function recentScanCacheKey(requestUrl: string, targetUrl: string): Promise<Request> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(targetUrl));
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const base = new URL(requestUrl);
  return new Request(`${base.origin}/__recent_scan/${hash}`, { method: "GET" });
}

async function enforceRateLimit(request: Request, env: Env): Promise<void> {
  const limit = clampInt(env.DAILY_SCAN_LIMIT, 15, 1, 500);
  const date = new Date().toISOString().slice(0, 10);
  const ip = request.headers.get("CF-Connecting-IP") || "local";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${date}:${ip}`));
  const key = [...new Uint8Array(digest)].slice(0, 16).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const now = new Date().toISOString();
  const row = await env.DB.prepare(`
    INSERT INTO rate_limits (client_key, window_date, request_count, updated_at)
    VALUES (?, ?, 1, ?)
    ON CONFLICT(client_key, window_date)
    DO UPDATE SET request_count = request_count + 1, updated_at = excluded.updated_at
    RETURNING request_count
  `).bind(key, date, now).first<{ request_count: number }>();
  if ((row?.request_count || 1) > limit) throw new RateLimitError(`Daily anonymous scan limit of ${limit} reached.`);
}

async function saveReport(db: D1Database, report: ScanReport): Promise<void> {
  await db.prepare(`
    INSERT INTO scans (
      id, normalized_url, hostname, status, schema_version,
      duration_ms, report_json, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    report.id,
    report.normalizedUrl,
    report.hostname,
    report.status,
    report.schemaVersion,
    report.totalDurationMs,
    JSON.stringify(report),
    report.createdAt,
    report.expiresAt,
  ).run();
}

async function loadReport(db: D1Database, id: string): Promise<ScanReport | null> {
  const row = await db.prepare(`
    SELECT report_json FROM scans WHERE id = ? AND expires_at > ?
  `).bind(id, new Date().toISOString()).first<{ report_json: string }>();
  if (!row) return null;
  return JSON.parse(row.report_json) as ScanReport;
}

async function cleanExpired(db: D1Database): Promise<void> {
  const today = new Date().toISOString();
  await db.batch([
    db.prepare("DELETE FROM scans WHERE expires_at <= ?").bind(today),
    db.prepare("DELETE FROM rate_limits WHERE window_date < date('now', '-2 day')"),
  ]);
}

function clampInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value || "", 10);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    ...(origin ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : {}),
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function securityHeaders(): Record<string, string> {
  return {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Frame-Options": "DENY",
  };
}

function normalizeError(error: unknown): { status: number; message: string } {
  if (error instanceof InputError || error instanceof BlockedTargetError) return { status: error.status, message: error.message };
  if (error instanceof RateLimitError) return { status: 429, message: error.message };
  console.error("request_failed", error);
  return { status: 500, message: "The trace could not be completed. Please try again." };
}

function errorResponse(error: unknown, cors: Record<string, string>): Response {
  const normalized = normalizeError(error);
  return json({ error: normalized.message }, normalized.status, {
    ...cors,
    ...(normalized.status === 429 ? { "Retry-After": "3600" } : {}),
  });
}

function json(payload: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...securityHeaders(),
      ...extra,
    },
  });
}
