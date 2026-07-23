import { analyzeUrl } from "./analyzer";
import { allowedOrigin, BlockedTargetError, InputError } from "./security";
import type { Env, ScanReport } from "./types";

const API_VERSION = "1.0.0";
const REPORT_ID = /^[A-Za-z0-9_-]{16}$/;

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
          documentation: "https://requestscope.pages.dev/#methodology",
          endpoints: {
            health: "GET /api/health",
            createScan: "POST /api/scans",
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
          time: new Date().toISOString(),
        }, 200, cors);
      }

      if (url.pathname === "/api/scans" && request.method === "POST") {
        if (request.headers.get("Origin") && !origin) return json({ error: "Origin not allowed" }, 403, cors);
        const contentLength = Number.parseInt(request.headers.get("content-length") || "0", 10);
        if (contentLength > 4096) return json({ error: "Request body is too large" }, 413, cors);
        await enforceRateLimit(request, env);
        const contentType = request.headers.get("content-type") || "";
        if (!contentType.toLowerCase().includes("application/json")) {
          return json({ error: "Content-Type must be application/json" }, 415, cors);
        }
        const body = await request.json<{ url?: unknown }>();
        const retention = clampInt(env.REPORT_RETENTION_DAYS, 30, 1, 90);
        const incomingCf = request.cf as Record<string, unknown> | undefined;
        const report = await analyzeUrl(body.url, retention, {
          colo: typeof incomingCf?.colo === "string" ? incomingCf.colo : undefined,
          country: typeof incomingCf?.country === "string" ? incomingCf.country : undefined,
        });
        await saveReport(env.DB, report);
        ctx.waitUntil(cleanExpired(env.DB));
        return json(report, 201, cors);
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
      if (error instanceof InputError || error instanceof BlockedTargetError) {
        return json({ error: error.message }, error.status, cors);
      }
      if (error instanceof SyntaxError) return json({ error: "Invalid JSON request body" }, 400, cors);
      if (error instanceof RateLimitError) {
        return json({ error: error.message }, 429, { ...cors, "Retry-After": "3600" });
      }
      console.error("request_failed", error);
      return json({ error: "The trace could not be completed. Please try again." }, 500, cors);
    }
  },
};

class RateLimitError extends Error {}

async function enforceRateLimit(request: Request, env: Env): Promise<void> {
  const limit = clampInt(env.DAILY_SCAN_LIMIT, 30, 1, 500);
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
  if (Math.random() > 0.05) return;
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
