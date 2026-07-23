import { inspectDns, queryDns } from "./dns";
import { buildFindings } from "./findings";
import { BlockedTargetError, isPublicIp, normalizeUrl, safeRedirect } from "./security";
import type { Dependency, RedirectHop, ScanReport } from "./types";

const MAX_REDIRECTS = 8;
const MAX_BODY_BYTES = 256 * 1024;
const MAX_DEPENDENCIES = 100;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const STORED_HEADERS = new Set([
  "age",
  "cache-control",
  "cf-cache-status",
  "content-encoding",
  "content-language",
  "content-length",
  "content-security-policy",
  "content-type",
  "date",
  "etag",
  "expires",
  "last-modified",
  "location",
  "nel",
  "permissions-policy",
  "referrer-policy",
  "report-to",
  "server",
  "strict-transport-security",
  "vary",
  "via",
  "x-cache",
  "x-content-type-options",
  "x-frame-options",
  "x-robots-tag",
]);

export async function analyzeUrl(
  rawUrl: unknown,
  retentionDays: number,
  observer: { colo?: string; country?: string } = {},
): Promise<ScanReport> {
  const started = performance.now();
  const initial = normalizeUrl(rawUrl);
  const id = randomId();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + retentionDays * 86_400_000);
  const dnsQueries = await inspectDns(initial.hostname);
  assertPublicResolution(initial.hostname, dnsQueries);

  const hops: RedirectHop[] = [];
  let current = initial;
  let finalResponse: Response | null = null;
  let bodyText = "";
  let bytesInspected = 0;
  let truncated = false;
  let status: ScanReport["status"] = "complete";

  for (let index = 0; index <= MAX_REDIRECTS; index += 1) {
    if (index > 0) await assertTargetPublic(current.hostname);
    const hopStarted = performance.now();
    try {
      const response = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        headers: {
          Accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
          "User-Agent": "RequestScope/1.0 (+https://requestscope.pages.dev)",
        },
        signal: AbortSignal.timeout(10_000),
      });
      const location = response.headers.get("location");
      hops.push({
        index,
        url: current.toString(),
        hostname: current.hostname,
        status: response.status,
        statusText: response.statusText,
        elapsedMs: Math.round(performance.now() - hopStarted),
        location,
        responseHeaders: selectHeaders(response.headers),
        cf: extractCf(response),
        evidenceKind: "edge_http_observation",
      });

      if (REDIRECT_STATUSES.has(response.status) && location) {
        if (index === MAX_REDIRECTS) {
          status = "partial";
          hops[hops.length - 1].error = `Redirect limit of ${MAX_REDIRECTS} reached`;
          response.body?.cancel();
          break;
        }
        response.body?.cancel();
        current = safeRedirect(current, location);
        continue;
      }

      finalResponse = response;
      const body = await readBoundedBody(response, MAX_BODY_BYTES);
      bodyText = body.text;
      bytesInspected = body.bytes;
      truncated = body.truncated;
      break;
    } catch (error) {
      status = hops.length > 0 ? "partial" : "failed";
      hops.push({
        index,
        url: current.toString(),
        hostname: current.hostname,
        status: 0,
        statusText: "Request failed",
        elapsedMs: Math.round(performance.now() - hopStarted),
        location: null,
        responseHeaders: {},
        cf: {},
        error: error instanceof Error ? error.message : "Request failed",
        evidenceKind: "edge_http_observation",
      });
      break;
    }
  }

  const dependencies = finalResponse && isHtml(finalResponse.headers.get("content-type"))
    ? extractDependencies(bodyText, current)
    : [];
  const uniqueHosts = [...new Set(dependencies.map((item) => item.host))].sort();
  const base = {
    schemaVersion: 1 as const,
    id,
    requestedUrl: String(rawUrl).trim(),
    normalizedUrl: initial.toString(),
    finalUrl: finalResponse ? current.toString() : null,
    hostname: initial.hostname,
    status,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    totalDurationMs: Math.round(performance.now() - started),
    observation: {
      vantage: "cloudflare-edge" as const,
      colo: observer.colo || hops.find((hop) => hop.cf.colo)?.cf.colo,
      country: observer.country || hops.find((hop) => hop.cf.country)?.cf.country,
      disclaimer: "HTTP timings are Cloudflare edge observations, not browser DNS, TCP, TLS, or rendering timings.",
    },
    dns: {
      queries: dnsQueries,
      addresses: addressAnswers(dnsQueries),
      dnssecAuthenticated: dnsQueries.some((query) => query.authenticatedData),
    },
    http: {
      hops,
      finalStatus: finalResponse?.status ?? null,
      contentType: finalResponse?.headers.get("content-type") ?? null,
      contentBytesInspected: bytesInspected,
      truncated,
    },
    dependencies: {
      total: dependencies.length,
      firstParty: dependencies.filter((item) => item.party === "first-party").length,
      thirdParty: dependencies.filter((item) => item.party === "third-party").length,
      uniqueHosts,
      items: dependencies,
    },
  };
  const findings = buildFindings(base);
  const summary = {
    critical: findings.filter((item) => item.severity === "critical").length,
    warning: findings.filter((item) => item.severity === "warning").length,
    positive: findings.filter((item) => item.severity === "positive").length,
    info: findings.filter((item) => item.severity === "info").length,
  };
  return { ...base, findings, summary };
}

async function assertTargetPublic(hostname: string): Promise<void> {
  const results = await Promise.all([queryDns(hostname, "A"), queryDns(hostname, "AAAA")]);
  assertPublicResolution(hostname, results);
}

function assertPublicResolution(hostname: string, queries: Awaited<ReturnType<typeof inspectDns>>): void {
  const addresses = addressAnswers(queries);
  if (addresses.length === 0) {
    throw new BlockedTargetError(`No public A or AAAA address could be confirmed for ${hostname}.`);
  }
  const blocked = addresses.filter((address) => !isPublicIp(address));
  if (blocked.length > 0) {
    throw new BlockedTargetError("The hostname resolves to a private or reserved network address.");
  }
}

function addressAnswers(queries: Awaited<ReturnType<typeof inspectDns>>): string[] {
  return [...new Set(queries.flatMap((query) =>
    query.answers.filter((answer) => answer.type === "A" || answer.type === "AAAA").map((answer) => answer.data),
  ))];
}

function selectHeaders(headers: Headers): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const [name, value] of headers.entries()) {
    if (STORED_HEADERS.has(name.toLowerCase())) selected[name.toLowerCase()] = value.slice(0, 4096);
  }
  return selected;
}

function extractCf(response: Response): RedirectHop["cf"] {
  const cf = response.cf as Record<string, unknown> | undefined;
  return {
    colo: typeof cf?.colo === "string" ? cf.colo : undefined,
    country: typeof cf?.country === "string" ? cf.country : undefined,
    httpProtocol: typeof cf?.httpProtocol === "string" ? cf.httpProtocol : undefined,
    tlsVersion: typeof cf?.tlsVersion === "string" ? cf.tlsVersion : undefined,
  };
}

async function readBoundedBody(response: Response, limit: number): Promise<{ text: string; bytes: number; truncated: boolean }> {
  if (!response.body) return { text: "", bytes: 0, truncated: false };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (total + value.byteLength > limit) {
        const remaining = Math.max(0, limit - total);
        if (remaining) chunks.push(value.slice(0, remaining));
        total += remaining;
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: new TextDecoder("utf-8", { fatal: false }).decode(merged), bytes: total, truncated };
}

function isHtml(contentType: string | null): boolean {
  return Boolean(contentType && /(?:text\/html|application\/xhtml\+xml)/i.test(contentType));
}

function extractDependencies(html: string, pageUrl: URL): Dependency[] {
  const patterns: Array<[RegExp, Dependency["type"]]> = [
    [/<script\b[^>]*\bsrc\s*=\s*["']([^"'<>]+)["']/gi, "script"],
    [/<link\b[^>]*\bhref\s*=\s*["']([^"'<>]+)["'][^>]*>/gi, "stylesheet"],
    [/<img\b[^>]*\bsrc\s*=\s*["']([^"'<>]+)["']/gi, "image"],
    [/<iframe\b[^>]*\bsrc\s*=\s*["']([^"'<>]+)["']/gi, "frame"],
    [/<(?:video|audio|source)\b[^>]*\bsrc\s*=\s*["']([^"'<>]+)["']/gi, "media"],
  ];
  const seen = new Set<string>();
  const results: Dependency[] = [];

  for (const [pattern, defaultType] of patterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(html)) && results.length < MAX_DEPENDENCIES) {
      const raw = decodeHtmlAttribute(match[1]);
      if (!raw || /^(?:data:|blob:|javascript:|mailto:|tel:|#)/i.test(raw)) continue;
      try {
        const url = new URL(raw, pageUrl);
        if (url.protocol !== "http:" && url.protocol !== "https:") continue;
        url.hash = "";
        const type = defaultType === "stylesheet" ? classifyLink(match[0], url) : defaultType;
        const key = `${type}:${url.toString()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        results.push({
          url: url.toString().slice(0, 2048),
          host: url.hostname,
          type,
          party: sameSite(pageUrl.hostname, url.hostname) ? "first-party" : "third-party",
        });
      } catch {
        // Ignore malformed dependency URLs.
      }
    }
  }
  return results;
}

function classifyLink(tag: string, url: URL): Dependency["type"] {
  const rel = tag.match(/\brel\s*=\s*["']([^"']+)["']/i)?.[1]?.toLowerCase() || "";
  const as = tag.match(/\bas\s*=\s*["']([^"']+)["']/i)?.[1]?.toLowerCase() || "";
  if (rel.includes("stylesheet")) return "stylesheet";
  if (as === "font" || /\.(?:woff2?|ttf|otf)(?:\?|$)/i.test(url.pathname)) return "font";
  if (rel.includes("preload") || rel.includes("modulepreload")) return "preload";
  return "other";
}

function sameSite(a: string, b: string): boolean {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

function decodeHtmlAttribute(value: string): string {
  return value
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .trim();
}

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
