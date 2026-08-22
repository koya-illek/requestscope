import { inspectDns, queryDns } from "./dns";
import { getDomain } from "tldts";
import { mapDependencies } from "./deps";
import { buildFindings } from "./findings";
import { checkExternalReputation, type ReputationConfig } from "./reputation";
import { assessUrlRisk, type UrlRiskContext } from "./url-risk";
import {
  BlockedTargetError,
  isPublicIp,
  normalizeUrl,
  redactUrlForStorage,
  safeRedirect,
  redactHeaderForStorage,
} from "./security";
import { RequestBudget, BudgetExceededError } from "./budget";
import { assertPublicTarget, assertResolutionHealthy, uniqueAddresses, type PublicResolution } from "./egress";
import type { Dependency, DnsQueryResult, PageSecuritySignals, RedirectHop, ScanReport, PhaseCoverage } from "./types";

const MAX_REDIRECTS = 6;
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

export interface AnalyzerProgress {
  stage: "validated" | "dns" | "hop" | "response" | "reputation" | "deps-csp" | "deps-js" | "deps-ct" | "deps-ssl" | "deps-takeover" | "deps-complete" | "complete";
  message: string;
  hop?: number;
  status?: number;
}

export async function analyzeUrl(
  rawUrl: unknown,
  retentionDays: number,
  observer: { colo?: string; country?: string; sourceRevision?: string } = {},
  onProgress: (event: AnalyzerProgress) => void = () => {},
  options: { mapDependencies?: boolean; riskContext?: UrlRiskContext; reputation?: ReputationConfig; budget?: RequestBudget } = {},
): Promise<ScanReport> {
  const started = performance.now();
  const budget = options.budget || new RequestBudget();
  const scanBudgetStart = budget.snapshot();
  const initial = normalizeUrl(rawUrl);
  onProgress({ stage: "validated", message: `Validated ${initial.hostname}` });
  const id = randomId();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + retentionDays * 86_400_000);
  const dnsQueries = await inspectDns(initial.hostname, budget);
  assertResolutionHealthy(initial.hostname, dnsQueries);
  const initialAddresses = uniqueAddresses(dnsQueries);
  if (initialAddresses.some((address) => !isPublicIp(address))) {
    throw new BlockedTargetError("The hostname resolves to a private or reserved network address.");
  }
  const secondaryQueries = await assertSecondaryResolutionPublic(initial.hostname, budget);
  onProgress({ stage: "dns", message: `Resolved ${initialAddresses.length} public address records` });

  const hops: RedirectHop[] = [];
  // One validation per unique redirect hostname per request: revisiting a host
  // inside the same trace reuses its public-target resolution instead of
  // spending four more DNS subrequests on it. The initial host is seeded so a
  // redirect loop back to the origin reuses its completed validation.
  const validatedTargets = new Map<string, PublicResolution>();
  validatedTargets.set(initial.hostname.toLowerCase().replace(/\.$/, ""), {
    hostname: initial.hostname,
    addresses: initialAddresses,
    queries: [...dnsQueries, ...secondaryQueries],
  });
  let current = initial;
  let finalResponse: Response | null = null;
  let bodyText = "";
  let bytesInspected = 0;
  let truncated = false;
  let status: ScanReport["status"] = "complete";

  for (let index = 0; index <= MAX_REDIRECTS; index += 1) {
    const hopStarted = performance.now();
    let response: Response;
    try {
      response = await budget.fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        cache: "no-store",
        headers: {
          Accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
          "User-Agent": "RequestScope/1.0 (+https://requestscope.illek.ie)",
        },
        signal: AbortSignal.timeout(10_000),
        resource: "http",
      });
    } catch (error) {
      status = hops.length > 0 ? "partial" : "failed";
      hops.push({
        index,
        url: redactUrlForStorage(current.toString()),
        hostname: current.hostname,
        status: 0,
        statusText: "Request failed",
        elapsedMs: Math.round(performance.now() - hopStarted),
        location: null,
        responseHeaders: {},
        cf: {},
        error: error instanceof DOMException && error.name === "TimeoutError"
          ? "Request timed out after 10 seconds"
          : error instanceof BudgetExceededError
            ? "Request budget exhausted before the next hop"
            : "Network request failed",
        evidenceKind: "edge_http_observation",
      });
      onProgress({ stage: "hop", hop: index, status: 0, message: `Request to ${current.hostname} failed` });
      break;
    }

    const location = response.headers.get("location");
    const hop: RedirectHop = {
      index,
      url: redactUrlForStorage(current.toString()),
      hostname: current.hostname,
      status: response.status,
      statusText: response.statusText,
      elapsedMs: Math.round(performance.now() - hopStarted),
      location: location ? redactRedirectLocation(current, location) : null,
      responseHeaders: selectHeaders(response.headers, current),
      cf: extractCf(response),
      evidenceKind: "edge_http_observation",
    };
    if (hop.responseHeaders.location) {
      hop.responseHeaders.location = redactRedirectLocation(current, hop.responseHeaders.location);
    }
    hops.push(hop);
    onProgress({
      stage: "hop",
      hop: index,
      status: response.status,
      message: `Received HTTP ${response.status} from ${current.hostname}`,
    });

    if (REDIRECT_STATUSES.has(response.status) && location) {
      if (index === MAX_REDIRECTS) {
        status = "partial";
        hop.error = `Redirect limit of ${MAX_REDIRECTS} reached`;
        response.body?.cancel();
        break;
      }
      try {
        const next = safeRedirect(current, location);
        await assertPublicTarget(next.hostname, budget, validatedTargets);
        response.body?.cancel();
        current = next;
      } catch (error) {
        status = "partial";
        hop.error = error instanceof Error ? `Redirect blocked: ${error.message}` : "Redirect target blocked";
        response.body?.cancel();
        break;
      }
      continue;
    }

    finalResponse = response;
    try {
      const body = await readBoundedBody(response, MAX_BODY_BYTES, budget);
      bodyText = body.text;
      bytesInspected = body.bytes;
      truncated = body.truncated;
    } catch (error) {
      status = "partial";
      hop.error = "Response inspection failed before the bounded body could be decoded";
    }
    onProgress({ stage: "response", message: `Inspected ${bytesInspected} response bytes` });
    break;
  }

  const dependenciesRaw = finalResponse && isHtml(finalResponse.headers.get("content-type"))
    ? extractDependencies(bodyText, current)
    : [];
  const dependencies = dependenciesRaw.map((item) => ({ ...item, url: redactUrlForStorage(item.url) }));
  const uniqueHosts = [...new Set(dependencies.map((item) => item.host))].sort();
  const pageSecuritySignals = finalResponse && isHtml(finalResponse.headers.get("content-type"))
    ? extractPageSecuritySignals(bodyText, current)
    : undefined;
  const base = {
    schemaVersion: 1 as const,
    id,
    requestedUrl: redactUrlForStorage(initial.toString()),
    normalizedUrl: redactUrlForStorage(initial.toString()),
    finalUrl: finalResponse ? redactUrlForStorage(current.toString()) : null,
    hostname: initial.hostname,
    status,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    totalDurationMs: 0,
    observation: {
      vantage: "cloudflare-edge" as const,
      colo: observer.colo || hops.find((hop) => hop.cf.colo)?.cf.colo,
      country: observer.country || hops.find((hop) => hop.cf.country)?.cf.country,
      disclaimer: "HTTP timings are Cloudflare edge observations, not browser DNS, TCP, TLS, or rendering timings.",
      sourceRevision: observer.sourceRevision,
    },
    dns: {
      queries: dnsQueries,
      addresses: uniqueAddresses(dnsQueries),
      dnssecAuthenticated: dnsQueries.some((query) => query.authenticatedData),
    },
    http: {
      hops,
      finalStatus: finalResponse?.status ?? null,
      contentType: finalResponse?.headers.get("content-type") ?? null,
      contentBytesInspected: bytesInspected,
      truncated,
    },
    pageSecuritySignals,
    dependencies: {
      total: dependencies.length,
      firstParty: dependencies.filter((item) => item.party === "first-party").length,
      thirdParty: dependencies.filter((item) => item.party === "third-party").length,
      uniqueHosts,
      items: dependencies,
    },
  };
  const coreBudget = budget.snapshot();
  const dependencyBudgetBefore = budget.snapshot();
  let dependencyMap: ScanReport["dependencyMap"] = undefined;
  if (options.mapDependencies && finalResponse) {
    dependencyMap = await mapDependencies(
      initial.hostname,
      current,
      hops.at(-1)?.responseHeaders || {},
      dependencies.filter((d) => d.type === "script").map((d) => ({ url: d.url, host: d.host })),
      (event) => onProgress({ stage: event.stage as AnalyzerProgress["stage"], message: event.message }),
      budget,
    );
  }
  const dependencyBudgetAfter = budget.snapshot();

  if (options.reputation?.enabled) {
    onProgress({ stage: "reputation", message: "Checking consented external reputation sources" });
  }
  const reputation = await checkExternalReputation(
    initial.toString(),
    finalResponse ? current.toString() : null,
    { ...(options.reputation || { enabled: false }), budget },
  );
  const reputationBudget = budget.snapshot();

  const findings = buildFindings(base);
  const summary = {
    critical: findings.filter((item) => item.severity === "critical").length,
    warning: findings.filter((item) => item.severity === "warning").length,
    positive: findings.filter((item) => item.severity === "positive").length,
    info: findings.filter((item) => item.severity === "info").length,
  };
  const finalBudget = budget.snapshot();
  const report = {
    ...base,
    totalDurationMs: Math.round(performance.now() - started),
    dependencyMap,
    findings,
    summary,
    coverage: {
      status: (status === "complete" && !budget.exhausted ? "complete" : "partial") as "complete" | "partial",
      budget: finalBudget,
      phases: {
        core: phaseCoverage("core", scanBudgetStart, coreBudget, base.http.contentBytesInspected, base.http.truncated, status === "complete" ? undefined : "Core trace is partial."),
        dependencies: dependencyMap?.coverage || phaseCoverage("dependencies", dependencyBudgetBefore, dependencyBudgetAfter, 0, false, options.mapDependencies ? "Dependency map unavailable" : "Dependency mapping was not requested."),
        reputation: phaseCoverage("reputation", dependencyBudgetAfter, reputationBudget, 0, false, options.reputation?.enabled
          ? reputation.status === "not_configured" ? "No reputation provider is configured." : undefined
          : "External reputation was not requested."),
      },
    },
    provenance: {
      apiVersion: "1.4.0",
      sourceRevision: observer.sourceRevision || "uncommitted-source",
      reportSchemaVersion: 1,
      databaseSchemaVersion: 1,
    },
  };
  const urlRisk = assessUrlRisk(report, typeof rawUrl === "string" ? rawUrl : initial.toString(), options.riskContext, reputation);
  onProgress({ stage: "complete", message: "Report complete" });
  return { ...report, urlRisk };
}

export function extractPageSecuritySignals(html: string, pageUrl: URL): PageSecuritySignals {
  const forms = [...html.matchAll(/<form\b[^>]*>/gi)];
  const passwordForm = /<input\b[^>]*\btype\s*=\s*["']?password\b/i.test(html);
  let externalFormAction = false;
  for (const match of forms) {
    const action = match[0].match(/\baction\s*=\s*["']([^"'<>]+)["']/i)?.[1];
    if (!action) continue;
    try {
      const target = new URL(decodeHtmlAttribute(action), pageUrl);
      if ((target.protocol === "http:" || target.protocol === "https:") && !sameSite(pageUrl.hostname, target.hostname)) {
        externalFormAction = true;
      }
    } catch {
      // Malformed actions do not create evidence.
    }
  }

  const text = html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:nbsp|amp|quot|#39);/gi, " ")
    .replace(/\s+/g, " ")
    .slice(0, 100_000)
    .toLowerCase();
  const matchedLanguage: PageSecuritySignals["matchedLanguage"] = [];
  if (/\b(?:log[ -]?in|sign[ -]?in|authenticate)\b/.test(text)) matchedLanguage.push("login");
  if (/\b(?:verify|verification|confirm (?:your|the) (?:account|identity))\b/.test(text)) matchedLanguage.push("verification");
  if (/\b(?:reset|expired|update|change) (?:your )?password\b/.test(text)) matchedLanguage.push("password-reset");
  if (/\b(?:payment|billing|invoice|credit card|debit card|bank account)\b/.test(text)) matchedLanguage.push("payment");
  return { passwordForm, forms: forms.length, externalFormAction, matchedLanguage };
}

async function assertSecondaryResolutionPublic(hostname: string, budget: RequestBudget): Promise<DnsQueryResult[]> {
  const results = await Promise.all([
    queryDns(hostname, "A", "google", budget),
    queryDns(hostname, "AAAA", "google", budget),
  ]);
  assertResolutionHealthy(hostname, results);
  if (uniqueAddresses(results).some((address) => !isPublicIp(address))) {
    throw new BlockedTargetError("The hostname resolves to a private or reserved network address.");
  }
  return results;
}

function selectHeaders(headers: Headers, baseUrl: URL): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const [name, value] of headers.entries()) {
    if (STORED_HEADERS.has(name.toLowerCase())) {
      selected[name.toLowerCase()] = redactHeaderForStorage(name, value.slice(0, 4096), baseUrl);
    }
  }
  return selected;
}

function redactRedirectLocation(current: URL, location: string): string {
  try {
    return redactUrlForStorage(new URL(location, current).toString());
  } catch {
    return "[invalid redirect URL]";
  }
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

async function readBoundedBody(response: Response, limit: number, budget: RequestBudget): Promise<{ text: string; bytes: number; truncated: boolean }> {
  if (!response.body) return { text: "", bytes: 0, truncated: false };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const requestRemaining = Math.max(0, limit - total);
      const budgetRemaining = budget.remainingBodyBytes;
      if (requestRemaining === 0 || budgetRemaining === 0) {
        truncated = true;
        await reader.cancel();
        break;
      }
      if (total + value.byteLength > limit || value.byteLength > budgetRemaining) {
        const remaining = Math.min(requestRemaining, budgetRemaining);
        if (remaining) chunks.push(value.slice(0, remaining));
        total += remaining;
        budget.inspectBytes(remaining);
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(value);
      total += value.byteLength;
      budget.inspectBytes(value.byteLength);
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
    [/<(?:img|source)\b[^>]*\bsrcset\s*=\s*["']([^"'<>]+)["']/gi, "image"],
    [/\burl\(\s*["']?([^"')<>]+)["']?\s*\)/gi, "other"],
  ];
  const seen = new Set<string>();
  const results: Dependency[] = [];

  for (const [pattern, defaultType] of patterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(html)) && results.length < MAX_DEPENDENCIES) {
      const raw = decodeHtmlAttribute(defaultType === "image" && match[0].toLowerCase().includes("srcset")
        ? match[1].split(",")[0].trim().split(/\s+/)[0]
        : match[1]);
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
  if (a === b) return true;
  const aDomain = getDomain(a, { allowPrivateDomains: true });
  const bDomain = getDomain(b, { allowPrivateDomains: true });
  return Boolean(aDomain && bDomain && aDomain === bDomain);
}

function decodeHtmlAttribute(value: string): string {
  return value
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .trim();
}

function phaseCoverage(
  name: "core" | "dependencies" | "reputation",
  before: ReturnType<RequestBudget["snapshot"]>,
  after: ReturnType<RequestBudget["snapshot"]>,
  bytesInspected: number,
  truncated: boolean,
  detail?: string,
): PhaseCoverage {
  const attempted = Math.max(0, after.subrequestsStarted - before.subrequestsStarted);
  const successful = Math.max(0, after.subrequestsSucceeded - before.subrequestsSucceeded);
  const failed = Math.max(0, after.subrequestsFailed - before.subrequestsFailed);
  const skipped = detail && /not requested|unavailable|skipped/i.test(detail) ? 1 : 0;
  return {
    status: detail && /not requested|unavailable|skipped/i.test(detail)
      ? "skipped"
      : detail && /partial/i.test(detail)
        ? "partial"
      : failed && successful === 0
        ? "failed"
        : after.exhausted || truncated
          ? "partial"
          : "complete",
    attempted,
    successful,
    failed,
    skipped,
    bytesInspected,
    truncated,
    durationMs: Math.max(0, after.elapsedMs - before.elapsedMs),
    ...(detail ? { detail: `${name}: ${detail}` } : {}),
  };
}

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
