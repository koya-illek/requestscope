import type { ScanReport, UrlRiskAssessment } from "./types";
import type { UrlRiskContext } from "./url-risk";
import { BlockedTargetError, InputError, RateLimitError, retryAfterSeconds } from "./security";
import { MCP_SERVER_VERSION } from "./version";

const MCP_PROTOCOL_VERSION = "2025-11-25";
const MAX_MCP_REQUEST_BYTES = 16 * 1024;
const MCP_SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "X-Frame-Options": "DENY",
  "X-Robots-Tag": "noindex, nofollow",
};

interface McpRequest {
  jsonrpc?: unknown;
  id?: string | number | null;
  method?: unknown;
  params?: unknown;
}

export interface McpRiskInput extends UrlRiskContext {
  url: string;
}

/** Progress events are transport details of the executing scan; the handler
 * only needs a human-readable message to place in notifications/progress. */
export interface McpProgressEvent {
  message: string;
}

export type McpExecute = (
  name: string,
  input: Record<string, unknown>,
  onProgress: (event: McpProgressEvent) => void,
) => Promise<ScanReport | UrlRiskAssessment>;

export interface McpHandlerOptions {
  beforeToolCall?: () => Promise<void>;
  corsHeaders?: Record<string, string>;
}

/** A malformed request envelope: the payload parsed as JSON but is not a
 * usable JSON-RPC message (wrong shape, unsupported batch, or over size). */
class McpRequestShapeError extends Error {
  constructor(readonly jsonRpcCode: number, message: string) {
    super(message);
  }
}

export async function handleMcp(
  request: Request,
  execute: McpExecute,
  options: McpHandlerOptions = {},
): Promise<Response> {
  const cors = options.corsHeaders || {};
  const methodHeaders = { ...MCP_SECURITY_HEADERS, "Cache-Control": "no-store", Allow: "POST, OPTIONS", ...cors };
  if (request.method === "GET") {
    return new Response(null, { status: 405, headers: methodHeaders });
  }
  if (request.method !== "POST") return new Response(null, { status: 405, headers: methodHeaders });

  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) return rpcError(null, -32600, "Content-Type must be application/json", 415, cors);

  let message: McpRequest;
  try {
    message = await readMcpMessage(request);
  } catch (error) {
    if (error instanceof SyntaxError) return rpcError(null, -32700, "Invalid JSON", 400, cors);
    if (error instanceof McpRequestShapeError) return rpcError(null, error.jsonRpcCode, error.message, 400, cors);
    throw error;
  }
  if (message.jsonrpc !== "2.0" || typeof message.method !== "string") return rpcError(requestIdOf(message), -32600, "Invalid JSON-RPC request", 400, cors);

  const requestId = requestIdOf(message);
  if (message.method.startsWith("notifications/")) return new Response(null, { status: 202, headers: methodHeaders });
  if (message.id === undefined) return new Response(null, { status: 202, headers: methodHeaders });

  switch (message.method) {
    case "initialize":
      return rpcResult(requestId, {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "requestscope", title: "RequestScope URL Risk", version: MCP_SERVER_VERSION },
        instructions: "Use trace_request for full DNS, redirect, HTTP, dependency, security-signal, and finding evidence; assess_url_risk for phishing and impersonation risk; and get_requestscope_report to retrieve a shared report. A low result never certifies a URL as safe. Set externalReputation true only after the user agrees that the original and final URL, including query values, may be sent to Google Web Risk and PhishTank, while Cloudflare's malware-filtering DNS receives their hostnames only.",
      }, cors);
    case "ping":
      return rpcResult(requestId, {}, cors);
    case "tools/list":
      return rpcResult(requestId, { tools: [traceTool(), riskTool(), reportTool()] }, cors);
    case "tools/call":
      try {
        const progressToken = progressTokenOf(message.params);
        if (progressToken !== null && acceptsEventStream(request)) {
          return await streamedToolCall(request, requestId, message.params, progressToken, execute, options, cors);
        }
        return await callTool(requestId, message.params, execute, options);
      } catch (error) {
        // Quota failures must stay transport-visible so clients can back off
        // until the UTC-daily window that metered them rolls over.
        if (error instanceof RateLimitError) {
          return rpcError(requestId, -32000, error.message, 429, { ...cors, "Retry-After": String(retryAfterSeconds()) });
        }
        throw error;
      }
    default:
      return rpcError(requestId, -32601, `Method not found: ${message.method}`, 200, cors);
  }
}

/** A JSON-RPC id is a string, number, or null. Anything else an envelope may
 * carry (undefined, object, array) is answered with null instead of being
 * reflected back into the error response. */
function requestIdOf(message: McpRequest): string | number | null {
  return typeof message.id === "string" || typeof message.id === "number" ? message.id : null;
}

/** params._meta.progressToken (string or number) requests progress
 * notifications for this call; anything else means "don't". */
function progressTokenOf(params: unknown): string | number | null {
  if (!params || typeof params !== "object") return null;
  const meta = (params as Record<string, unknown>)._meta;
  if (!meta || typeof meta !== "object") return null;
  const token = (meta as Record<string, unknown>).progressToken;
  return typeof token === "string" || typeof token === "number" ? token : null;
}

function acceptsEventStream(request: Request): boolean {
  return (request.headers.get("Accept") || "").toLowerCase().includes("text/event-stream");
}

interface ParsedToolCall {
  name: string;
  args: Record<string, unknown>;
}

function parsedToolCall(params: unknown): ParsedToolCall {
  const value = params && typeof params === "object" ? params as Record<string, unknown> : {};
  const args = value.arguments && typeof value.arguments === "object" ? value.arguments as Record<string, unknown> : {};
  return { name: String(value.name), args };
}

/** Argument validation for every transport; the returned error is the
 * JSON-RPC -32602 payload, or null when the call may proceed. */
function toolRequestError(params: unknown): { code: number; message: string } | null {
  const { name, args } = parsedToolCall(params);
  if (!["trace_request", "assess_url_risk", "get_requestscope_report"].includes(name)) return { code: -32602, message: "Unknown tool name" };
  const allowedArguments = name === "trace_request"
    ? ["url", "mapDependencies", "claimedOrganisation", "messageContext", "externalReputation", "mobileUserAgent"]
    : name === "assess_url_risk"
      ? ["url", "claimedOrganisation", "messageContext", "externalReputation", "mobileUserAgent"]
      : ["reportId"];
  const unknownArgument = Object.keys(args).find((argument) => !allowedArguments.includes(argument));
  if (unknownArgument) return { code: -32602, message: `Unsupported argument: ${unknownArgument}` };
  if (name === "get_requestscope_report") {
    if (typeof args.reportId !== "string") return { code: -32602, message: "get_requestscope_report requires reportId" };
    if (!/^[A-Za-z0-9_-]{16}$/.test(args.reportId)) return { code: -32602, message: "reportId must be a valid 16-character report ID" };
  } else if (typeof args.url !== "string") return { code: -32602, message: `${name} requires a URL` };
  if (args.claimedOrganisation !== undefined && typeof args.claimedOrganisation !== "string") return { code: -32602, message: "claimedOrganisation must be a string" };
  if (args.messageContext !== undefined && typeof args.messageContext !== "string") return { code: -32602, message: "messageContext must be a string" };
  if (typeof args.claimedOrganisation === "string" && args.claimedOrganisation.length > 120) return { code: -32602, message: "claimedOrganisation is too long" };
  if (typeof args.messageContext === "string" && args.messageContext.length > 1000) return { code: -32602, message: "messageContext is too long" };
  if (args.mapDependencies !== undefined && typeof args.mapDependencies !== "boolean") return { code: -32602, message: "mapDependencies must be a boolean" };
  if (args.externalReputation !== undefined && typeof args.externalReputation !== "boolean") return { code: -32602, message: "externalReputation must be a boolean" };
  if (args.mobileUserAgent !== undefined && typeof args.mobileUserAgent !== "boolean") return { code: -32602, message: "mobileUserAgent must be a boolean" };
  return null;
}

/** The single execution path shared by the JSON and SSE transports. Tool
 * failures become isError results per the MCP spec: expected input/target
 * errors keep their helpful message, anything else is logged server-side and
 * masked so internal details never reach model-visible output. */
async function runTool(
  name: string,
  args: Record<string, unknown>,
  execute: McpExecute,
  onProgress: (event: McpProgressEvent) => void,
): Promise<Record<string, unknown>> {
  try {
    const assessment = await execute(name, args, onProgress);
    return { content: [{ type: "text", text: JSON.stringify(assessment) }], structuredContent: assessment, isError: false };
  } catch (error) {
    if (error instanceof InputError || error instanceof BlockedTargetError) {
      return { content: [{ type: "text", text: error.message }], isError: true };
    }
    console.error("mcp_tool_failed", error);
    return { content: [{ type: "text", text: "The URL assessment could not be completed. Please try again." }], isError: true };
  }
}

async function callTool(id: string | number | null, params: unknown, execute: McpExecute, options: McpHandlerOptions): Promise<Response> {
  const invalid = toolRequestError(params);
  if (invalid) return rpcError(id, invalid.code, invalid.message);
  const { name, args } = parsedToolCall(params);
  // Quota enforcement runs before the guarded execution so RateLimitError
  // propagates to handleMcp and becomes an HTTP 429 JSON-RPC error.
  await options.beforeToolCall?.();
  return rpcResult(id, await runTool(name, args, execute, () => {}));
}

/** A caller that supplied params._meta.progressToken and accepts SSE receives
 * notifications/progress while its trace runs, then the ordinary JSON-RPC
 * response as the final message event — the Streamable HTTP pattern for work
 * that takes tens of seconds. Validation failures and quota exhaustion still
 * answer as plain JSON because nothing has been streamed yet. */
async function streamedToolCall(
  request: Request,
  id: string | number | null,
  params: unknown,
  progressToken: string | number,
  execute: McpExecute,
  options: McpHandlerOptions,
  cors: Record<string, string>,
): Promise<Response> {
  const invalid = toolRequestError(params);
  if (invalid) return rpcError(id, invalid.code, invalid.message);
  await options.beforeToolCall?.();
  const { name, args } = parsedToolCall(params);
  const encoder = new TextEncoder();
  // A client disconnect makes enqueue reject; the flag turns later sends and
  // the close into no-ops. The scan keeps running so the report is still
  // persisted for its share link, exactly like the NDJSON stream endpoint.
  let closed = false;
  request.signal?.addEventListener("abort", () => { closed = true; }, { once: true });
  let progress = 0;
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (payload: unknown) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`event: message\ndata: ${JSON.stringify(payload)}\n\n`));
        } catch {
          closed = true;
        }
      };
      const onProgress = (event: McpProgressEvent) => {
        progress += 1;
        send({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken, progress, message: event.message } });
      };
      send({ jsonrpc: "2.0", id, result: await runTool(name, args, execute, onProgress) });
      if (!closed) {
        try {
          controller.close();
        } catch {
          closed = true;
        }
      }
    },
    cancel() {
      closed = true;
    },
  });
  return new Response(stream, {
    status: 200,
    headers: {
      ...cors,
      ...MCP_SECURITY_HEADERS,
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store",
      "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    },
  });
}

function traceTool() {
  return {
    name: "trace_request", title: "Trace a URL with RequestScope",
    description: "Return the full RequestScope report: DNS observations, redirect chain, HTTP evidence, page security signals, dependencies, optional dependency map, findings, opt-in Google Web Risk, PhishTank and Cloudflare DNS reputation, coverage, and shareable report ID.",
    inputSchema: { type: "object", additionalProperties: false, required: ["url"], properties: {
      url: { type: "string", maxLength: 2048, description: "Public HTTP or HTTPS URL." },
      mapDependencies: { type: "boolean", default: true, description: "Inspect bounded page dependencies and their relationships." },
      mobileUserAgent: { type: "boolean", default: false, description: "Request the target as mobile Safari instead of the RequestScope identity. Some sites serve different content per device; the report records which profile was used. The observer stays at the Cloudflare edge either way." },
      claimedOrganisation: { type: "string", maxLength: 120, description: "Organisation the surrounding message claims to represent, used by the URL-risk assessment included in the trace." },
      messageContext: { type: "string", maxLength: 1000, description: "Brief non-sensitive context, for example Password reset email." },
      externalReputation: { type: "boolean", default: false, description: "After user approval, send the original and final URL, including query values, to Google Web Risk and PhishTank; Cloudflare's malware-filtering DNS receives hostnames only. Never enable for private or token-bearing URLs." },
    } },
    outputSchema: scanReportSchema(),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  };
}

function reportTool() {
  return {
    name: "get_requestscope_report", title: "Retrieve a RequestScope report",
    description: "Retrieve a previously created, unexpired RequestScope report by its 16-character report ID.",
    inputSchema: { type: "object", additionalProperties: false, required: ["reportId"], properties: { reportId: { type: "string", pattern: "^[A-Za-z0-9_-]{16}$" } } },
    outputSchema: scanReportSchema(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  };
}

function scanReportSchema() {
  return { type: "object", required: ["schemaVersion", "id", "requestedUrl", "normalizedUrl", "finalUrl", "hostname", "status", "createdAt", "expiresAt", "totalDurationMs", "observation", "dns", "http", "dependencies", "findings", "summary", "coverage", "provenance"], properties: {
    schemaVersion: { type: "integer", enum: [1] }, id: { type: "string" }, requestedUrl: { type: "string" }, normalizedUrl: { type: "string" }, finalUrl: { type: ["string", "null"] },
    hostname: { type: "string" }, status: { type: "string", enum: ["complete", "partial", "failed"] },
    createdAt: { type: "string", format: "date-time" }, expiresAt: { type: "string", format: "date-time" }, totalDurationMs: { type: "integer", minimum: 0 },
    observation: { type: "object" }, dns: { type: "object" }, http: { type: "object" },
    pageSecuritySignals: { type: "object" }, dependencies: { type: "object" }, dependencyMap: { type: "object" }, urlRisk: urlRiskAssessmentSchema(), findings: { type: "array", items: { type: "object" } }, summary: { type: "object" }, coverage: coverageSchema(), provenance: { type: "object", required: ["apiVersion", "sourceRevision", "reportSchemaVersion", "databaseSchemaVersion"], properties: { apiVersion: { type: "string" }, sourceRevision: { type: "string" }, reportSchemaVersion: { type: "integer", enum: [1] }, databaseSchemaVersion: { type: "integer", enum: [1] } } },
  } };
}

function coverageSchema() {
  const phase = { type: "object", required: ["status", "attempted", "successful", "failed", "skipped", "bytesInspected", "truncated", "durationMs"], properties: {
    status: { type: "string", enum: ["complete", "partial", "failed", "unavailable", "skipped"] }, attempted: { type: "integer", minimum: 0 }, successful: { type: "integer", minimum: 0 }, failed: { type: "integer", minimum: 0 }, skipped: { type: "integer", minimum: 0 }, bytesInspected: { type: "integer", minimum: 0 }, truncated: { type: "boolean" }, durationMs: { type: "integer", minimum: 0 }, detail: { type: "string" },
  } };
  return { type: "object", required: ["status", "budget", "phases"], properties: { status: { type: "string", enum: ["complete", "partial", "failed", "unavailable", "skipped"] }, budget: { type: "object" }, phases: { type: "object", required: ["core", "dependencies", "reputation"], properties: { core: phase, dependencies: phase, reputation: phase } } } };
}

function riskTool() {
  return {
    name: "assess_url_risk",
    title: "Assess URL risk",
    description: "Safely follows a public URL and returns an evidence-backed low, medium, or high risk assessment with optional Google Web Risk, PhishTank and Cloudflare DNS reputation. Use for suspicious links, shortened URLs, possible brand impersonation, login, password reset, verification, or payment messages. Never describe a low result as proof that a URL is safe.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["url"],
      properties: {
        url: { type: "string", maxLength: 2048, description: "Public HTTP or HTTPS URL to trace and assess." },
        mobileUserAgent: { type: "boolean", default: false, description: "Request the target as mobile Safari instead of the RequestScope identity, exposing device-specific content. The report records which profile was used." },
        claimedOrganisation: { type: "string", maxLength: 120, description: "Organisation the surrounding message claims to represent." },
        messageContext: { type: "string", maxLength: 1000, description: "Brief non-sensitive context, for example Password reset email." },
        externalReputation: { type: "boolean", default: false, description: "Set true only after the user agrees that the original and final URL, including query values, may be sent to Google Web Risk and PhishTank; Cloudflare's malware-filtering DNS receives hostnames only." },
      },
    },
    outputSchema: urlRiskAssessmentSchema(),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  };
}

function urlRiskAssessmentSchema() {
  return {
    type: "object",
    required: ["schemaVersion", "verdict", "riskScore", "confidence", "summary", "requestedUrl", "finalUrl", "traceId", "reportPath", "claimedOrganisation", "services", "findings", "reputation", "limitations"],
    properties: {
      schemaVersion: { type: "integer", enum: [1] },
      verdict: { type: "string", enum: ["low", "medium", "high"] },
      riskScore: { type: "integer", minimum: 0, maximum: 100 },
      confidence: { type: "string", enum: ["high", "medium"] },
      summary: { type: "string" },
      requestedUrl: { type: "string" },
      finalUrl: { type: ["string", "null"] },
      traceId: { type: "string" },
      reportPath: { type: "string" },
      claimedOrganisation: { type: ["string", "null"] },
      services: { type: "array", items: { type: "object" } },
      findings: { type: "array", items: { type: "object" } },
      reputation: reputationAssessmentSchema(),
      limitations: { type: "array", items: { type: "string" } },
    },
  };
}

function reputationAssessmentSchema() {
  return {
    type: "object",
    required: ["status", "detail", "consentRequired", "providers"],
    properties: {
      status: { type: "string", enum: ["matched", "not_listed", "partial", "unavailable", "not_configured", "not_requested"] },
      detail: { type: "string" },
      consentRequired: { type: "boolean", enum: [true] },
      providers: {
        type: "array",
        items: {
          type: "object",
          required: ["provider", "target", "hostname", "status", "threatTypes", "detail", "checkedAt", "attribution"],
          properties: {
            provider: { type: "string", enum: ["google_web_risk", "phishtank", "cloudflare_family_dns"] },
            target: { type: "string", enum: ["requested", "final"] },
            hostname: { type: "string" },
            status: { type: "string", enum: ["matched", "not_listed", "inconclusive", "unavailable", "quota_limited", "not_configured"] },
            threatTypes: { type: "array", items: { type: "string" } },
            detail: { type: "string" },
            checkedAt: { type: "string", format: "date-time" },
            expiresAt: { type: ["string", "null"], format: "date-time" },
            advisoryUrl: { type: "string" },
            attribution: { type: "string" },
          },
        },
      },
    },
  };
}

async function readMcpMessage(request: Request): Promise<McpRequest> {
  if (!request.body) throw new McpRequestShapeError(-32600, "MCP request body is required");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_MCP_REQUEST_BYTES) {
        await reader.cancel();
        throw new McpRequestShapeError(-32600, "MCP request is too large");
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
  const decoded = new TextDecoder().decode(bytes);
  // JSON.parse failures surface as SyntaxError so the caller can answer with
  // -32700 Parse error; shape problems below are -32600 Invalid Request.
  const parsed = JSON.parse(decoded) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new McpRequestShapeError(-32600, "Invalid JSON-RPC request");
  }
  return parsed as McpRequest;
}

function rpcResult(id: string | number | null, result: unknown, cors: Record<string, string> = {}): Response {
  return rpc({ jsonrpc: "2.0", id, result }, 200, cors);
}

function rpcError(id: string | number | null, code: number, message: string, status = 200, cors: Record<string, string> = {}): Response {
  return rpc({ jsonrpc: "2.0", id, error: { code, message } }, status, cors);
}

function rpc(payload: unknown, status = 200, cors: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      ...cors,
      ...MCP_SECURITY_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    },
  });
}
