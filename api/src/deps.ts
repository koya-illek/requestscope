import { getDomain } from "tldts";
import type {
  CertTransparencyAnalysis,
  CspAnalysis,
  DependencyMap,
  DomainCategory,
  JsBundleAnalysis,
  MappedDomain,
} from "./types";

const MAX_JS_BUNDLES = 15;
const MAX_BUNDLE_BYTES = 512 * 1024;
const MAX_CT_RESULTS = 100;
const FETCH_TIMEOUT = 8_000;
const CT_TIMEOUT = 12_000;

const DOMAIN_PATTERNS: Array<[RegExp, DomainCategory]> = [
  [/google-analytics\.com|googletagmanager\.com|hotjar\.com|mixpanel\.com|amplitude\.com|segment\.(?:io|com)|posthog\.com|plausible\.io|clarity\.ms|matomo\./i, "analytics"],
  [/doubleclick\.net|googlesyndication\.com|googleadservices\.com|facebook\.(?:net|com)|fbcdn\.net|amazon-adsystem\.com|criteo\.(?:com|net)|taboola\.com|outbrain\.com|adservice\.google\./i, "advertising"],
  [/cloudflare(?:insights|cdn)?\.com|jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|bootstrapcdn\.com|googleapis\.com|gstatic\.com|gravatar\.com|fastly\./i, "cdn"],
  [/stripe\.(?:com|network)|paypal\.com|squareup\.com|adyen\.com|checkout\.com|revenuewire\./i, "payment"],
  [/pusher\.(?:com|app)|pusherapp\.com|socket\.io|ably\.(?:io|com)|pubnub\.com|firebaseio\.com|deepstream\.io/i, "communication"],
  [/sentry\.(?:io|cdn\.com)|datadoghq\.com|rollbar\.com|logflare\.app|bugsnag\.com/i, "monitoring"],
  [/recaptcha\.net|hcaptcha\.com|challenges\.cloudflare\.com|turnstile\.site/i, "security"],
];

const PII_RISK_PATTERNS = [
  /google-analytics|googletagmanager|doubleclick|facebook|hotjar|mixpanel|segment|amplitude|posthog/i,
  /stripe|paypal|adyen|squareup/i,
  /pusher|socket\.io|ably|pubnub|firebaseio/i,
];

const URL_PATTERN = /(?:https?:)?\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?::\d+)?(?:\/[^\s"'<>`)]*)?/gi;
const WS_PATTERN = /wss?:\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?::\d+)?(?:\/[^\s"'<>`)]]*)?/gi;
const FETCH_CALL_PATTERN = /(?:fetch|axios|XMLHttpRequest|\.open)\s*\(\s*['"`]?(?:https?:)?\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)/gi;

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
): Promise<DependencyMap> {
  const started = performance.now();

  onProgress({ stage: "deps-csp", message: "Analysing Content-Security-Policy" });
  const csp = analyseCsp(responseHeaders["content-security-policy"]);

  onProgress({ stage: "deps-js", message: "Scanning JavaScript bundles" });
  const jsBundles = await scrapeJsBundles(scriptDeps);

  onProgress({ stage: "deps-ct", message: "Querying Certificate Transparency logs" });
  const certT = await queryCertTransparency(hostname);

  const domainMap = new Map<string, MappedDomain>();

  for (const domain of csp.domains) {
    addDomain(domainMap, domain, "csp", "CSP directive");
  }

  for (const finding of jsBundles.patterns) {
    addDomain(domainMap, finding.domain, "js-bundle", finding.context);
  }

  for (const subdomain of certT.subdomains) {
    addDomain(domainMap, subdomain, "cert-transparency", "Certificate Transparency log");
  }

  const domains = [...domainMap.values()];
  for (const d of domains) {
    d.category = classifyDomain(d.domain);
    d.piiRisk = assessPiiRisk(d.domain, d.category);
    d.postAuthOnly = !csp.domains.includes(d.domain) &&
      !scriptDeps.some((s) => s.host === d.domain) &&
      d.source !== "cert-transparency";
  }

  const byCategory = domains.reduce((acc, d) => {
    acc[d.category] = (acc[d.category] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  onProgress({ stage: "deps-complete", message: "Dependency map complete" });

  return {
    createdAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - started),
    sources: { csp, jsBundles, certTransparency: certT },
    domains: domains.sort((a, b) => a.domain.localeCompare(b.domain)),
    summary: {
      totalDomains: domains.length,
      byCategory,
      piiRisk: domains.filter((d) => d.piiRisk).length,
      postAuthOnly: domains.filter((d) => d.postAuthOnly).length,
    },
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
    const sources = parts.slice(1);
    directives[name] = sources;

    for (const source of sources) {
      const host = extractHostFromCspSource(source);
      if (host) domains.add(host);
    }
  }

  return {
    present: true,
    raw: raw.slice(0, 4096),
    directives,
    domains: [...domains].sort(),
  };
}

function extractHostFromCspSource(source: string): string | null {
  const trimmed = source.trim().replace(/^["']/, "").replace(/["']$/, "");

  // Skip keywords
  if (/^(?:self|none|unsafe-inline|unsafe-eval|strict-dynamic|unsafe-hashes|wasm-unsafe-eval|report-sample|all|dynamic)$/i.test(trimmed)) {
    return null;
  }
  if (trimmed.startsWith("nonce-") || trimmed.startsWith("sha")) return null;
  if (trimmed === "*") return null;

  // Scheme sources
  const schemeMatch = trimmed.match(/^(?:https?|wss?|data|blob|filesystem|mediastream):/i);
  if (schemeMatch && !trimmed.includes("://")) return null;

  // Host source with optional scheme
  const hostMatch = trimmed.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?([^:/\s*]+)/i);
  if (!hostMatch) return null;

  let host = hostMatch[1].toLowerCase().replace(/^\*/, "");
  if (!host || !host.includes(".")) return null;

  // Wildcard subdomain — normalise to the registrable domain
  if (host.startsWith(".")) host = host.slice(1);

  return host;
}

async function scrapeJsBundles(scriptDeps: Array<{ url: string; host: string }>): Promise<JsBundleAnalysis> {
  const bundles = scriptDeps
    .filter((d) => d.url.match(/\.m?js(?:\?|$)/i) || d.url.match(/\/js\//i))
    .slice(0, MAX_JS_BUNDLES);

  const domains = new Set<string>();
  const patterns: Array<{ domain: string; pattern: string; context: string }> = [];

  for (const bundle of bundles) {
    try {
      const response = await fetch(bundle.url, {
        method: "GET",
        redirect: "follow",
        cache: "no-store",
        headers: { "User-Agent": "RequestScope/1.0 (+https://requestscope.pages.dev)" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      });

      if (!response.ok) continue;

      const reader = response.body?.getReader();
      if (!reader) continue;

      const chunks: Uint8Array[] = [];
      let total = 0;
      let truncated = false;

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (total + value.byteLength > MAX_BUNDLE_BYTES) {
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
      const text = new TextDecoder("utf-8", { fatal: false }).decode(merged);

      const found = extractDomainsFromJs(text);
      for (const { domain, pattern, context } of found) {
        domains.add(domain);
        patterns.push({ domain, pattern, context: `${bundle.url.slice(0, 80)} → ${context}` });
      }
    } catch {
      // Network errors and timeouts are expected — skip the bundle.
    }
  }

  return {
    bundlesFetched: bundles.length,
    totalBytes: 0,
    domains: [...domains].sort(),
    patterns,
  };
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

async function queryCertTransparency(hostname: string): Promise<CertTransparencyAnalysis> {
  const apex = getDomain(hostname, { allowPrivateDomains: true }) || hostname;
  const url = `https://crt.sh/?q=%.${encodeURIComponent(apex)}&output=json`;

  try {
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(CT_TIMEOUT),
      cache: "no-store",
    });

    if (!response.ok) {
      return { subdomains: [], total: 0, error: `crt.sh returned HTTP ${response.status}` };
    }

    const data = await response.json<Array<{ name_value: string; common_name?: string }>>();
    const subdomains = new Set<string>();

    for (const entry of data) {
      const names = (entry.name_value || "").split(/\n/);
      for (const name of names) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
        if (clean && clean.includes(apex) && clean !== apex) {
          subdomains.add(clean);
        }
      }
      if (subdomains.size >= MAX_CT_RESULTS) break;
    }

    return {
      subdomains: [...subdomains].sort().slice(0, MAX_CT_RESULTS),
      total: subdomains.size,
    };
  } catch (error) {
    return {
      subdomains: [],
      total: 0,
      error: error instanceof Error ? error.message : "Certificate Transparency query failed",
    };
  }
}

function addDomain(
  map: Map<string, MappedDomain>,
  domain: string,
  source: MappedDomain["source"],
  evidence: string,
): void {
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
      source,
      piiRisk: false,
      postAuthOnly: false,
      occurrences: 1,
      evidence: [evidence],
    });
  }
}

function classifyDomain(domain: string): DomainCategory {
  for (const [pattern, category] of DOMAIN_PATTERNS) {
    if (pattern.test(domain)) return category;
  }
  return "unknown";
}

function assessPiiRisk(domain: string, _category: DomainCategory): boolean {
  for (const pattern of PII_RISK_PATTERNS) {
    if (pattern.test(domain)) return true;
  }
  return false;
}
