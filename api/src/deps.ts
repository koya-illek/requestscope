import { getDomain } from "tldts";
import {
  classifyHostname,
  detectSdks as detectSdksFromClassifier,
  assessPiiRisk as classifierPiiRisk,
} from "./classifier";
import { probeTakeover } from "./takeover";
import { fetchPublicUrl, type PublicResolution } from "./egress";
import { RequestBudget } from "./budget";
import { redactTextForStorage } from "./security";
import type {
  CertTransparencyAnalysis,
  CspAnalysis,
  DependencyMap,
  JsBundleAnalysis,
  MappedDomain,
  SslDetail,
  SubdomainTakeoverCheck,
  PhaseCoverage,
} from "./types";

const MAX_JS_BUNDLES = 15;
const MAX_BUNDLE_BYTES = 512 * 1024;
const MAX_CT_RESULTS = 100;
// crt.sh returns one JSON array for every certificate that ever logged a name
// under the apex, which reaches tens of MB on busy domains. Parse only what
// fits this cap; anything larger becomes an explicit failed analysis instead
// of an unbounded memory read inside the isolate.
export const MAX_CT_RESPONSE_BYTES = 4 * 1024 * 1024;
const FETCH_TIMEOUT = 8_000;
const CT_TIMEOUT = 12_000;

const URL_PATTERN = /(?:https?:)?\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?::\d+)?(?:\/[^\s"'<>`)]*)?/gi;
const WS_PATTERN = /wss?:\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?::\d+)?(?:\/[^\s"'<>`)]*)?/gi;
const FETCH_CALL_PATTERN = /\b(?:fetch|axios|XMLHttpRequest)\s*\(\s*['"`]?(?:https?:)?\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)/gi;

export interface DepsProgress {
  stage: string;
  message: string;
}

export async function mapDependencies(
  hostname: string,
  pageUrl: URL,
  responseHeaders: Record<string, string>,
  scriptDeps: Array<{ url: string; host: string }>,
  onProgress: (event: DepsProgress) => void = () => {},
  budget?: RequestBudget,
): Promise<DependencyMap> {
  const started = performance.now();
  const budgetStarted = budget?.snapshot();
  // One shared validation memo for every derived fetch of this map, so hosts
  // repeated across bundles and takeover probes resolve once per request.
  const validatedHosts = new Map<string, PublicResolution>();

  onProgress({ stage: "deps-csp", message: "Analysing Content-Security-Policy" });
  const csp = analyseCsp(responseHeaders["content-security-policy"]);

  onProgress({ stage: "deps-js", message: "Scanning JavaScript bundles" });
  const { analysis: jsBundles, rawJsText } = await scrapeJsBundles(scriptDeps, budget, validatedHosts);

  onProgress({ stage: "deps-ct", message: "Querying Certificate Transparency logs" });
  const certT = await queryCertTransparency(hostname, budget);

  const domainMap = new Map<string, MappedDomain>();
  // Collapsed MappedDomain.source strings ("multiple") lose which channels
  // produced a domain; the per-domain set keeps that information so the
  // post-auth-only heuristic can still honour Certificate Transparency.
  const domainSources = new Map<string, Set<MappedDomain["source"]>>();

  for (const domain of csp.domains) {
    addDomain(domainMap, domainSources, domain, "csp", "CSP directive");
  }

  for (const finding of jsBundles.patterns) {
    addDomain(domainMap, domainSources, finding.domain, "js-bundle", finding.context);
  }

  for (const subdomain of certT.subdomains) {
    addDomain(domainMap, domainSources, subdomain, "cert-transparency", "Certificate Transparency log");
  }

  const domains = [...domainMap.values()];
  for (const d of domains) {
    const match = classifyHostname(d.domain);
    d.category = match.category;
    d.serviceName = match.name;
    d.piiRisk = classifierPiiRisk(d.domain, d.category);
    // This is a visibility heuristic, not evidence of an authenticated
    // browser session. The UI labels it accordingly. A name in public CT
    // logs is externally visible by definition, whatever else also saw it.
    d.postAuthOnly = !csp.domains.includes(d.domain) &&
      !scriptDeps.some((s) => s.host === d.domain) &&
      !(domainSources.get(d.domain)?.has("cert-transparency"));
  }

  // Detect SDKs from concatenated JS bundle text
  const sdks = detectSdksFromClassifier(rawJsText);

  onProgress({ stage: "deps-ssl", message: "Inspecting SSL/TLS certificate" });
  const ssl: SslDetail = {
    source: "certificate_transparency",
    protocol: null,
    cipher: null,
    issuer: null,
    subject: null,
    validFrom: certT.latest?.notBefore || null,
    validTo: certT.latest?.notAfter || null,
    daysUntilExpiry: null,
    authorityKeyIdentifier: null,
  };

  onProgress({ stage: "deps-takeover", message: "Probing subdomains for takeover risk" });
  const takeover = certT.subdomains.length > 0
    ? await probeTakeover(certT.subdomains, budget, validatedHosts)
    : [];

  const byCategory = domains.reduce((acc, d) => {
    acc[d.category] = (acc[d.category] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  onProgress({ stage: "deps-complete", message: "Dependency map complete" });

  const budgetFinished = budget?.snapshot();
  const coverage: PhaseCoverage = {
    status: budget?.exhausted ? "partial" : "complete",
    attempted: budgetStarted && budgetFinished ? budgetFinished.subrequestsStarted - budgetStarted.subrequestsStarted : jsBundles.attempted + (certT.attempted || 0),
    successful: budgetStarted && budgetFinished ? budgetFinished.subrequestsSucceeded - budgetStarted.subrequestsSucceeded : jsBundles.successful + (certT.successful || 0),
    failed: budgetStarted && budgetFinished ? budgetFinished.subrequestsFailed - budgetStarted.subrequestsFailed : jsBundles.failed + (certT.failed || 0),
    skipped: jsBundles.skipped + (certT.skipped || 0),
    bytesInspected: budgetStarted && budgetFinished ? budgetFinished.bodyBytesInspected - budgetStarted.bodyBytesInspected : jsBundles.totalBytes,
    truncated: jsBundles.truncated || Boolean(certT.truncated),
    durationMs: Math.round(performance.now() - started),
    ...(budget?.exhausted ? { detail: budget.snapshot().exhaustionReason || "Request budget limited optional dependency coverage." } : {}),
  };

  return {
    createdAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - started),
    sources: { csp, jsBundles, certTransparency: certT },
    domains: domains.sort((a, b) => a.domain.localeCompare(b.domain)),
    sdks,
    ssl,
    takeover,
    summary: {
      totalDomains: domains.length,
      byCategory,
      piiRisk: domains.filter((d) => d.piiRisk).length,
      postAuthOnly: domains.filter((d) => d.postAuthOnly).length,
    },
    coverage,
  };
}

function analyseCsp(raw?: string): CspAnalysis {
  if (!raw) {
    return { present: false, directives: {}, domains: [] };
  }

  const directives: Record<string, string[]> = {};
  const domains = new Set<string>();
  const tokens = raw.trim().split(/\s*;+\s*/);

  for (const token of tokens) {
    const parts = token.trim().split(/\s+/);
    if (!parts.length) continue;
    const name = parts[0].toLowerCase();
    const rawSources = parts.slice(1);
    const sources = rawSources.map((source) => redactTextForStorage(source));
    directives[name] = sources;

    for (const source of rawSources) {
      const host = extractHostFromCspSource(source);
      if (host) domains.add(host);
    }
  }

  return {
    present: true,
    raw: redactTextForStorage(raw.slice(0, 4096)),
    directives,
    domains: [...domains].sort(),
  };
}

/** A strict hostname shape for CSP-derived map entries: label characters
 * only, at least two labels. CSP grammar permits paths and other punctuation
 * in a host-source; those carry no registrable identity and would otherwise
 * land in the dependency map as junk domains. */
const CSP_HOST_SHAPE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function extractHostFromCspSource(source: string): string | null {
  const trimmed = source.trim().replace(/^["']/, "").replace(/["']$/, "");

  // Skip keywords
  if (/^(?:self|none|unsafe-inline|unsafe-eval|strict-dynamic|unsafe-hashes|wasm-unsafe-eval|report-sample|all|dynamic)$/i.test(trimmed)) {
    return null;
  }
  if (trimmed === "*") return null;
  if (/^nonce-/i.test(trimmed)) return null;
  // Hash sources carry no host information.
  if (/^sha(?:256|384|512)-/i.test(trimmed)) return null;

  // Wildcard subdomains normalise to their parent host, bare or after a scheme.
  const candidate = trimmed.replace(/^\*\./i, "").replace(/^([a-z][a-z0-9+.-]*:\/\/)\*\./i, "$1");

  // Scheme-only sources name no host.
  if (/^(?:https?|wss?|data|blob|filesystem|mediastream):/i.test(candidate) && !candidate.includes("://")) return null;

  const hostMatch = candidate.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?([^:/\s*]+)/i);
  if (!hostMatch) return null;

  const host = hostMatch[1].toLowerCase();
  return CSP_HOST_SHAPE.test(host) ? host : null;
}

async function scrapeJsBundles(scriptDeps: Array<{ url: string; host: string }>, budget?: RequestBudget, validatedHosts?: Map<string, PublicResolution>): Promise<{ analysis: JsBundleAnalysis; rawJsText: string }> {
  const bundles = scriptDeps
    .filter((d) => d.url.match(/\.m?js(?:\?|$)/i) || d.url.match(/\/js\//i))
    .slice(0, MAX_JS_BUNDLES);

  const domains = new Set<string>();
  const patterns: Array<{ domain: string; pattern: string; context: string }> = [];
  const allText: string[] = [];
  let successful = 0;
  let failed = 0;
  let skipped = 0;
  let totalBytes = 0;
  let truncatedAny = false;

  for (const bundle of bundles) {
    if (budget && !budget.canStart()) {
      skipped += 1;
      continue;
    }
    try {
      const requestInit = {
        method: "GET",
        cache: "no-store" as RequestCache,
        headers: { "User-Agent": "RequestScope/1.0 (+https://requestscope.illek.ie)" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      };
      const response = budget
        ? (await fetchPublicUrl(bundle.url, budget, requestInit, 2, validatedHosts)).response
        : await fetch(bundle.url, { ...requestInit, redirect: "manual" });

      if (!response.ok) {
        failed += 1;
        response.body?.cancel();
        continue;
      }

      const reader = response.body?.getReader();
      if (!reader) {
        failed += 1;
        continue;
      }

      const chunks: Uint8Array[] = [];
      let total = 0;
      let truncated = false;

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (total + value.byteLength > MAX_BUNDLE_BYTES) {
            // The budget's accepted value can be smaller than the cap room
            // when the aggregate body budget runs out first; count only what
            // was really inspected so decoded text never exceeds the books.
            const room = Math.max(0, MAX_BUNDLE_BYTES - total);
            const accepted = budget ? budget.inspectBytes(room) : room;
            if (accepted > 0) {
              chunks.push(value.slice(0, accepted));
              total += accepted;
            }
            truncated = true;
            truncatedAny = true;
            await reader.cancel();
            break;
          }
          const accepted = budget ? budget.inspectBytes(value.byteLength) : value.byteLength;
          if (accepted < value.byteLength) {
            if (accepted) chunks.push(value.slice(0, accepted));
            total += accepted;
            truncated = true;
            truncatedAny = true;
            await reader.cancel();
            break;
          }
          chunks.push(value);
          total += accepted;
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
      const text = new TextDecoder("utf-8", { fatal: false }).decode(merged);
      allText.push(text);
      successful += 1;
      totalBytes += total;

      const found = extractDomainsFromJs(text);
      for (const { domain, pattern, context } of found) {
        domains.add(domain);
        patterns.push({ domain, pattern, context: `${redactTextForStorage(bundle.url).slice(0, 80)} -> ${redactTextForStorage(context)}` });
      }
    } catch (error) {
      // Network errors and timeouts are expected — skip the bundle.
      if (error instanceof Error && error.name === "BudgetExceededError") skipped += 1;
      else failed += 1;
    }
  }

  const analysis: JsBundleAnalysis = {
    attempted: bundles.length,
    successful,
    failed,
    skipped,
    bundlesFetched: successful,
    totalBytes,
    truncated: truncatedAny,
    domains: [...domains].sort(),
    patterns,
  };

  return { analysis, rawJsText: allText.join("\n") };
}

function extractDomainsFromJs(text: string): Array<{ domain: string; pattern: string; context: string }> {
  const results: Array<{ domain: string; pattern: string; context: string }> = [];
  const seen = new Set<string>();

  const processMatch = (match: RegExpExecArray, patternType: string) => {
    const host = match[1]?.toLowerCase();
    if (!host || !host.includes(".") || seen.has(`${patternType}:${host}`)) return;
    seen.add(`${patternType}:${host}`);

    // Filter infrastructure domains
    if (/^(?:localhost|example\.(?:com|net|org)|schemas\.w3\.org)/i.test(host)) return;

    const context = text.slice(Math.max(0, match.index - 30), match.index + match[0].length + 30);
    results.push({
      domain: host,
      pattern: patternType,
      context: context.replace(/\n/g, " ").trim().slice(0, 120),
    });
  };

  let match: RegExpExecArray | null;
  const patterns: Array<[RegExp, string]> = [
    [new RegExp(URL_PATTERN), "https/http URL"],
    [new RegExp(WS_PATTERN), "WebSocket URL"],
    [new RegExp(FETCH_CALL_PATTERN), "fetch() call"],
  ];

  for (const [regex, label] of patterns) {
    regex.lastIndex = 0;
    while ((match = regex.exec(text)) && results.length < 200) {
      processMatch(match, label);
    }
  }

  return results;
}

async function queryCertTransparency(hostname: string, budget?: RequestBudget): Promise<CertTransparencyAnalysis> {
  const apex = getDomain(hostname, { allowPrivateDomains: true }) || hostname;
  const url = `https://crt.sh/?q=%.${encodeURIComponent(apex)}&output=json`;

  try {
    const response = await (budget ? budget.fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(CT_TIMEOUT),
      cache: "no-store",
      resource: "ct",
    }) : fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(CT_TIMEOUT),
      cache: "no-store",
    }));

    if (!response.ok) {
      return { attempted: 1, successful: 0, failed: 1, skipped: 0, subdomains: [], total: 0, error: `crt.sh returned HTTP ${response.status}` };
    }

    const body = await readBoundedText(response.body?.getReader() || null, MAX_CT_RESPONSE_BYTES);
    if (body.truncated) {
      return { attempted: 1, successful: 0, failed: 1, skipped: 0, subdomains: [], total: 0, truncated: true, error: `Certificate Transparency response exceeded the ${MAX_CT_RESPONSE_BYTES / (1024 * 1024)} MiB inspection cap.` };
    }
    let data: Array<{ name_value: string; common_name?: string; not_before?: string; not_after?: string }>;
    try {
      data = JSON.parse(body.text) as typeof data;
    } catch {
      return { attempted: 1, successful: 0, failed: 1, skipped: 0, subdomains: [], total: 0, error: "Certificate Transparency response was not valid JSON." };
    }
    const certificates = data
      .filter((entry) => entry.not_before && entry.not_after)
      .sort((a, b) => new Date(b.not_before!).getTime() - new Date(a.not_before!).getTime());
    const subdomains = new Set<string>();
    for (const entry of data) {
      const names = (entry.name_value || "").split(/\n/);
      for (const name of names) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
        if (clean && clean !== apex && clean.endsWith(`.${apex}`)) {
          subdomains.add(clean);
        }
      }
    }

    // Collect every unique name the payload contains, then slice: `truncated`
    // then truthfully means "more names exist than are shown", and `total`
    // always describes the full discovery instead of a cap-dependent count.
    const sorted = [...subdomains].sort();
    return {
      attempted: 1,
      successful: 1,
      failed: 0,
      skipped: 0,
      subdomains: sorted.slice(0, MAX_CT_RESULTS),
      total: sorted.length,
      truncated: sorted.length > MAX_CT_RESULTS,
      latest: certificates[0] ? { notBefore: certificates[0].not_before!, notAfter: certificates[0].not_after! } : undefined,
    };
  } catch (error) {
    if (error instanceof Error && error.name === "BudgetExceededError") {
      return { attempted: 0, successful: 0, failed: 0, skipped: 1, subdomains: [], total: 0, truncated: false, error: "Certificate Transparency stage skipped by the request budget." };
    }
    return {
      attempted: 1,
      successful: 0,
      failed: 1,
      skipped: 0,
      subdomains: [],
      total: 0,
      error: error instanceof Error ? error.message : "Certificate Transparency query failed",
    };
  }
}

function addDomain(
  map: Map<string, MappedDomain>,
  sources: Map<string, Set<MappedDomain["source"]>>,
  domain: string,
  source: MappedDomain["source"],
  evidence: string,
): void {
  let sourceSet = sources.get(domain);
  if (!sourceSet) {
    sourceSet = new Set<MappedDomain["source"]>();
    sources.set(domain, sourceSet);
  }
  sourceSet.add(source);

  const existing = map.get(domain);
  if (existing) {
    existing.occurrences += 1;
    if (existing.source !== source && !existing.source.includes(source)) {
      existing.source = "multiple";
    }
    if (!existing.evidence.includes(evidence)) {
      existing.evidence.push(evidence);
    }
  } else {
    map.set(domain, {
      domain,
      category: "unknown",
      serviceName: null,
      source,
      piiRisk: false,
      postAuthOnly: false,
      occurrences: 1,
      evidence: [evidence],
    });
  }
}

/** Read a response body as text up to `limit` bytes. `truncated` marks a body
 * that reached the cap before EOF; the reader is cancelled so the remainder
 * is never buffered. */
async function readBoundedText(reader: ReadableStreamDefaultReader<Uint8Array> | null, limit: number): Promise<{ text: string; truncated: boolean }> {
  if (!reader) return { text: "", truncated: false };
  const decoder = new TextDecoder();
  let text = "";
  let total = 0;
  try {
    while (total < limit) {
      const { done, value } = await reader.read();
      if (done) return { text: text + decoder.decode(), truncated: false };
      const remaining = limit - total;
      const accepted = Math.min(remaining, value.byteLength);
      text += decoder.decode(value.subarray(0, accepted), { stream: accepted === value.byteLength });
      total += accepted;
      if (accepted < value.byteLength) {
        await reader.cancel();
        return { text, truncated: true };
      }
    }
    await reader.cancel();
    return { text, truncated: true };
  } finally {
    reader.releaseLock();
  }
}
