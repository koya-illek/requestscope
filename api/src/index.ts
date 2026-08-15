import { analyzeUrl, type AnalyzerProgress } from "./analyzer";
import {
  allowedOrigin,
  BlockedTargetError,
  InputError,
  normalizeUrl,
} from "./security";
import type { Env, ReputationProviderName, ScanReport } from "./types";
import { handleMcp } from "./mcp";

const API_VERSION = "1.4.0";
const REPORT_ID = /^[A-Za-z0-9_-]{16}$/;
const MAX_REQUEST_BYTES = 8192;
const RECENT_SCAN_TTL = 300;
const edgeRateBuckets = new Map<string, { count: number; expiresAt: number }>();

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
        return Response.redirect("https://requestscope.illek.ie/", 302);
      }

      if ((url.pathname === "/api" || url.pathname === "/api/") && request.method === "GET") {
        return json({
          service: "RequestScope API",
          version: API_VERSION,
          sourceRevision: env.SOURCE_REVISION || "uncommitted-source",
          databaseSchemaVersion: 1,
          website: "https://requestscope.illek.ie/",
          endpoints: {
            health: "GET /api/health",
            createScan: "POST /api/scans",
            streamScan: "POST /api/scans/stream",
            getScan: "GET /api/scans/:id",
            exportScan: "GET /api/scans/:id/export",
            urlRisk: "POST /api/v1/url-risk",
            mcp: "POST /mcp (also /mcp/v2)",
          },
        }, 200, cors);
      }

      if (url.pathname === "/api/health" && request.method === "GET") {
        return json({
          ok: true,
          service: "requestscope-api",
          version: API_VERSION,
          sourceRevision: env.SOURCE_REVISION || "uncommitted-source",
          databaseSchemaVersion: 1,
          environment: env.ENVIRONMENT,
          protection: "rate-limit",
          reputationProviders: {
            googleWebRisk: Boolean(env.GOOGLE_WEB_RISK_API_KEY),
            phishTank: env.PHISHTANK_KEYLESS_ENABLED === "true" || Boolean(env.PHISHTANK_APP_KEY),
            cloudflareFamilyDns: env.CLOUDFLARE_FAMILY_DNS_ENABLED === "true",
          },
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

      if (url.pathname === "/api/v1/url-risk" && request.method === "POST") {
        if (request.headers.get("Origin") && !origin) return json({ error: "Origin not allowed" }, 403, cors);
        if (!await authorizedRiskRequest(request, env)) return json({ error: "Invalid API credential" }, 401, cors);
        const input = await readRiskInput(request);
        const report = await createScan(request, input, env, ctx);
        return json(report.urlRisk, 200, { ...cors, "Cache-Control": "no-store" });
      }

      if (url.pathname === "/mcp" || url.pathname === "/mcp/v2") {
        if (request.headers.get("Origin") && !origin) return json({ error: "Origin not allowed" }, 403, cors);
        if (!await authorizedRiskRequest(request, env)) return json({ error: "Invalid API credential" }, 401, cors);
        return handleMcp(request, async (tool, args) => {
          if (tool === "get_requestscope_report") {
            const reportId = String(args.reportId || "");
            if (!REPORT_ID.test(reportId)) throw new InputError("A valid 16-character report ID is required.");
            const stored = await loadReport(env.DB, reportId);
            if (!stored) throw new InputError("Report not found or expired.");
            return stored;
          }
          const input = {
            url: String(args.url || ""),
            mapDependencies: tool === "trace_request" ? args.mapDependencies !== false : false,
            claimedOrganisation: args.claimedOrganisation as string | undefined,
            messageContext: args.messageContext as string | undefined,
            externalReputation: args.externalReputation === true,
          };
          const report = await createScan(request, input, env, ctx);
          return tool === "assess_url_risk" ? report.urlRisk! : report;
        }, {
          // Handshake, ping, discovery and malformed messages remain read-only.
          // Charge only validated tool calls through an isolate-local counter;
          // durable D1 accounting is reserved for scans and provider quotas.
          beforeToolCall: async () => enforceEdgeRateLimit(request, "mcp", clampInt(env.MCP_DAILY_LIMIT, 200, 1, 5000), "Daily MCP request limit"),
        });
      }

      const match = url.pathname.match(/^\/api\/scans\/([A-Za-z0-9_-]+)(\/export)?$/);
      if (match && request.method === "GET") {
        if (!REPORT_ID.test(match[1])) return json({ error: "Report not found" }, 404, cors);
        await enforceEdgeRateLimit(request, "report", clampInt(env.REPORT_DAILY_LIMIT, 120, 1, 5000), "Daily report retrieval limit");
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
  claimedOrganisation?: string;
  messageContext?: string;
  externalReputation?: boolean;
}

interface RiskInput {
  url: string;
  claimedOrganisation?: string;
  messageContext?: string;
  externalReputation?: boolean;
}

class RateLimitError extends Error {}

async function authorizedRiskRequest(request: Request, env: Env): Promise<boolean> {
  if (!env.COPILOT_API_KEY) return true;
  const supplied = request.headers.get("Authorization")?.match(/^Bearer\s+(.+)$/i)?.[1] || "";
  const encoder = new TextEncoder();
  const [expectedHash, suppliedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(env.COPILOT_API_KEY)),
    crypto.subtle.digest("SHA-256", encoder.encode(supplied)),
  ]);
  const expected = new Uint8Array(expectedHash);
  const actual = new Uint8Array(suppliedHash);
  let difference = expected.length ^ actual.length;
  for (let index = 0; index < expected.length; index += 1) difference |= expected[index] ^ (actual[index] || 0);
  return difference === 0;
}

async function readScanInput(request: Request): Promise<ScanInput> {
  const body = await readJsonObject(request);
  if (typeof body.url !== "string") throw new InputError("A URL is required.");
  if (body.mapDependencies !== undefined && typeof body.mapDependencies !== "boolean") {
    throw new InputError("mapDependencies must be a boolean.");
  }
  if (body.externalReputation !== undefined && typeof body.externalReputation !== "boolean") {
    throw new InputError("externalReputation must be a boolean.");
  }
  const context = readRiskContext(body);
  return {
    url: body.url,
    mapDependencies: body.mapDependencies === true,
    externalReputation: body.externalReputation === true,
    ...context,
  };
}

async function readRiskInput(request: Request): Promise<RiskInput> {
  const body = await readJsonObject(request);
  if (typeof body.url !== "string") throw new InputError("A URL is required.");
  if (body.externalReputation !== undefined && typeof body.externalReputation !== "boolean") {
    throw new InputError("externalReputation must be a boolean.");
  }
  return { url: body.url, externalReputation: body.externalReputation === true, ...readRiskContext(body) };
}

function readRiskContext(body: Record<string, unknown>): Omit<RiskInput, "url"> {
  if (body.claimedOrganisation !== undefined && typeof body.claimedOrganisation !== "string") throw new InputError("claimedOrganisation must be a string.");
  if (body.messageContext !== undefined && typeof body.messageContext !== "string") throw new InputError("messageContext must be a string.");
  if (typeof body.claimedOrganisation === "string" && body.claimedOrganisation.length > 120) throw new InputError("claimedOrganisation is too long.");
  if (typeof body.messageContext === "string" && body.messageContext.length > 1000) throw new InputError("messageContext is too long.");
  return { claimedOrganisation: body.claimedOrganisation as string | undefined, messageContext: body.messageContext as string | undefined };
}

async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
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
  return parsed as Record<string, unknown>;
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
  const cacheKey = await recentScanCacheKey(
    request.url,
    normalized.toString(),
    Boolean(input.mapDependencies),
    Boolean(input.externalReputation),
    input.claimedOrganisation,
    input.messageContext,
  );
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
    sourceRevision: env.SOURCE_REVISION || "uncommitted-source",
  }, onProgress, {
    mapDependencies: input.mapDependencies,
    riskContext: { claimedOrganisation: input.claimedOrganisation, messageContext: input.messageContext },
    reputation: {
      enabled: input.externalReputation === true,
      googleWebRiskApiKey: env.GOOGLE_WEB_RISK_API_KEY,
      phishTankAppKey: env.PHISHTANK_APP_KEY,
      phishTankEnabled: env.PHISHTANK_KEYLESS_ENABLED === "true",
      cloudflareFamilyDnsEnabled: env.CLOUDFLARE_FAMILY_DNS_ENABLED === "true",
      consumeQuota: (provider) => consumeProviderQuota(env, provider),
    },
  });
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

async function recentScanCacheKey(
  requestUrl: string,
  targetUrl: string,
  mapDeps: boolean,
  externalReputation: boolean,
  claimed?: string,
  context?: string,
): Promise<Request> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${targetUrl}:${mapDeps}:${externalReputation}:${claimed || ""}:${context || ""}`));
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const base = new URL(requestUrl);
  return new Request(`${base.origin}/__recent_scan/${hash}`, { method: "GET" });
}

async function enforceRateLimit(request: Request, env: Env): Promise<void> {
  return enforceScopedDailyRateLimit(request, env, "scan", clampInt(env.DAILY_SCAN_LIMIT, 15, 1, 500), "Daily anonymous scan limit");
}

async function enforceScopedDailyRateLimit(request: Request, env: Env, scope: string, limit: number, label: string): Promise<void> {
  const ip = request.headers.get("CF-Connecting-IP") || "local";
  if ((scope === "scan" || scope === "mcp") && bypassesScanRateLimit(ip, env.RATE_LIMIT_BYPASS_IPS)) return;
  const date = new Date().toISOString().slice(0, 10);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${date}:${ip}`));
  const key = `${scope}:${[...new Uint8Array(digest)].slice(0, 16).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  const now = new Date().toISOString();
  const row = await env.DB.prepare(`
    INSERT INTO rate_limits (client_key, window_date, request_count, updated_at)
    VALUES (?, ?, 1, ?)
    ON CONFLICT(client_key, window_date)
    DO UPDATE SET request_count = request_count + 1, updated_at = excluded.updated_at
    RETURNING request_count
  `).bind(key, date, now).first<{ request_count: number }>();
  if ((row?.request_count || 1) > limit) throw new RateLimitError(`${label} of ${limit} reached.`);
}

async function enforceEdgeRateLimit(request: Request, scope: string, limit: number, label: string): Promise<void> {
  const ip = request.headers.get("CF-Connecting-IP") || "local";
  const now = Date.now();
  const windowMs = 86_400_000;
  for (const [key, value] of edgeRateBuckets) {
    if (value.expiresAt <= now) edgeRateBuckets.delete(key);
  }
  const key = `${scope}:${ip}`;
  const current = edgeRateBuckets.get(key);
  if (!current || current.expiresAt <= now) {
    edgeRateBuckets.set(key, { count: 1, expiresAt: now + windowMs });
    return;
  }
  current.count += 1;
  if (current.count > limit) throw new RateLimitError(`${label} of ${limit} reached.`);
}

function bypassesScanRateLimit(ip: string, configured: string | undefined): boolean {
  if (!configured || ip === "local") return false;
  return configured.split(",").some((entry) => entry.trim() === ip);
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
    db.prepare("DELETE FROM provider_usage WHERE updated_at < datetime('now', '-90 day')"),
  ]);
}

async function consumeProviderQuota(env: Env, provider: ReputationProviderName): Promise<boolean> {
  const now = new Date();
  const windowKey = provider === "google_web_risk"
    ? now.toISOString().slice(0, 7)
    : now.toISOString().slice(0, 10);
  const limit = provider === "google_web_risk"
    ? clampInt(env.WEB_RISK_MONTHLY_LIMIT, 90_000, 1, 100_000)
    : provider === "cloudflare_family_dns"
      ? clampInt(env.CLOUDFLARE_FAMILY_DNS_DAILY_LIMIT, 5_000, 1, 100_000)
      : clampInt(env.PHISHTANK_DAILY_LIMIT, 100, 1, 100_000);
  const row = await env.DB.prepare(`
    INSERT INTO provider_usage (provider, window_key, request_count, updated_at)
    VALUES (?, ?, 1, ?)
    ON CONFLICT(provider, window_key)
    DO UPDATE SET request_count = request_count + 1, updated_at = excluded.updated_at
    RETURNING request_count
  `).bind(provider, windowKey, now.toISOString()).first<{ request_count: number }>();
  return (row?.request_count || 1) <= limit;
}

function clampInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value || "", 10);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    ...(origin ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : {}),
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version, MCP-Session-Id",
    "Access-Control-Max-Age": "86400",
  };
}

function securityHeaders(): Record<string, string> {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow",
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
