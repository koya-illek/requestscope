import type { SubdomainTakeoverCheck } from "./types";
import { queryDns } from "./dns";
import { fetchPublicUrl, type PublicResolution } from "./egress";
import { requireBudget, type RequestBudget } from "./budget";

const MAX_PROBES = 20;
const PROBE_TIMEOUT = 5_000;
const MAX_BODY_BYTES = 102_400; // 100 KB — enough for signature matching

// Known vulnerable CNAME patterns that indicate potential takeover
const VULNERABLE_PATTERNS: Array<{ pattern: RegExp; service: string; evidence: string }> = [
  // GitHub Pages
  { pattern: /\.github\.io$/i, service: "GitHub Pages", evidence: "CNAME points to GitHub Pages - verify the repo exists" },
  // AWS S3: global, regional REST, dualstack, and legacy dash forms
  { pattern: /\.s3(?:-[a-z0-9-]+|\.[a-z0-9-]+)*\.amazonaws\.com$/i, service: "AWS S3", evidence: "CNAME points to S3 - verify the bucket exists" },
  { pattern: /\.s3-website[\.-].*\.amazonaws\.com$/i, service: "AWS S3", evidence: "CNAME points to S3 website endpoint - verify bucket exists" },
  // Heroku
  { pattern: /\.herokuapp\.com$/i, service: "Heroku", evidence: "CNAME points to Heroku - verify the app exists" },
  { pattern: /\.herokudns\.com$/i, service: "Heroku", evidence: "CNAME points to Heroku DNS - verify the app exists" },
  // Azure
  { pattern: /\.azurewebsites\.net$/i, service: "Azure", evidence: "CNAME points to Azure Websites - verify the site exists" },
  { pattern: /\.cloudapp\.net$/i, service: "Azure", evidence: "CNAME points to Azure Cloud App - verify it exists" },
  { pattern: /\.trafficmanager\.net$/i, service: "Azure Traffic Manager", evidence: "CNAME points to Azure Traffic Manager - verify it exists" },
  // Shopify
  { pattern: /\.myshopify\.com$/i, service: "Shopify", evidence: "CNAME points to Shopify - verify the shop exists" },
  // Fastly
  { pattern: /\.fastly\.net$/i, service: "Fastly", evidence: "CNAME points to Fastly - verify the service exists" },
  // Ghost
  { pattern: /\.ghost\.io$/i, service: "Ghost", evidence: "CNAME points to Ghost - verify the blog exists" },
  // Cargo
  { pattern: /\.cargocollective\.com$/i, service: "Cargo", evidence: "CNAME points to Cargo - verify the site exists" },
  // Tumblr
  { pattern: /\.tumblr\.com$/i, service: "Tumblr", evidence: "CNAME points to Tumblr - verify the blog exists" },
  // WordPress
  { pattern: /\.wordpress\.com$/i, service: "WordPress", evidence: "CNAME points to WordPress.com - verify the blog exists" },
  // Squarespace
  { pattern: /\.squarespace\.com$/i, service: "Squarespace", evidence: "CNAME points to Squarespace - verify the site exists" },
  // Webflow
  { pattern: /\.webflow\.io$/i, service: "Webflow", evidence: "CNAME points to Webflow - verify the site exists" },
  // Netlify
  { pattern: /\.netlify\.app$/i, service: "Netlify", evidence: "CNAME points to Netlify - verify the site exists" },
  // Vercel
  { pattern: /\.vercel\.app$/i, service: "Vercel", evidence: "CNAME points to Vercel - verify the site exists" },
  // Surfshark
  { pattern: /\.surfshark\.com$/i, service: "Surfshark", evidence: "CNAME points to Surfshark - verify it exists" },
  // Tilda
  { pattern: /\.tilda\.ws$/i, service: "Tilda", evidence: "CNAME points to Tilda - verify the site exists" },
  // Smartling
  { pattern: /\.smartling\.com$/i, service: "Smartling", evidence: "CNAME points to Smartling - verify it exists" },
  // Acquia
  { pattern: /\.acquia-sites\.com$/i, service: "Acquia", evidence: "CNAME points to Acquia - verify the site exists" },
  // Pantheon
  { pattern: /\.pantheonsite\.io$/i, service: "Pantheon", evidence: "CNAME points to Pantheon - verify the site exists" },
];

// HTTP response body signatures that strongly indicate a dangling resource.
// Each entry maps a service name to substrings seen when the upstream
// resource has been deleted or is unclaimed.
const TAKEOVER_SIGNATURES: Array<{ service: string; patterns: RegExp[] }> = [
  {
    service: "GitHub Pages",
    patterns: [
      /There isn't a GitHub Pages site here/i,
      /For root URLs.*like.*your-pages-url/i,
    ],
  },
  {
    service: "AWS S3",
    patterns: [
      /NoSuchBucket/i,
      /The specified bucket does not exist/i,
    ],
  },
  {
    service: "Heroku",
    patterns: [
      /No such app/i,
      /herokucdn\.com\/error-pages\/no-such-app\.html/i,
    ],
  },
  {
    service: "Azure",
    patterns: [
      /404 Web Site not found/i,
    ],
  },
  {
    service: "Shopify",
    patterns: [
      /Sorry, this shop is currently unavailable/i,
    ],
  },
  {
    service: "Fastly",
    patterns: [
      /Fastly error.*unknown domain/i,
    ],
  },
  {
    service: "Ghost",
    // Verified against a live unclaimed *.ghost.io host: the platform answers
    // with its "Domain error" page.
    patterns: [
      /<h1[^>]*>\s*Domain error/i,
      /<title[^>]*>\s*Domain error/i,
    ],
  },
  {
    service: "Cargo",
    // Only the cargo-marked variant is used; the bare "page not found"
    // phrasing is ordinary custom-404 copy and accused live sites.
    patterns: [
      /404 Not Found.*cargo/i,
    ],
  },
  {
    service: "Tumblr",
    // Verified against a live removed-blog page.
    patterns: [
      /Whatever you were looking for doesn't currently exist at this address/i,
    ],
  },
  {
    service: "WordPress",
    patterns: [
      /Do you want to register/i,
    ],
  },
  {
    service: "Squarespace",
    // "No Such Website" verified as the platform title on an unclaimed name.
    patterns: [
      /No Such Website/i,
      /No Such Site/i,
    ],
  },
  {
    service: "Webflow",
    // The full sentence is what an unclaimed *.webflow.io host serves; the
    // shorter prefix is generic custom-404 copy that accused live sites. The
    // platform page encodes the apostrophe as &#x27;, so both forms match.
    patterns: [
      /The page you are looking for doesn(?:'|&#x?27;|&#39;)t exist or has been moved/i,
    ],
  },
  {
    service: "Netlify",
    patterns: [
      /Not Found - Request ID/i,
    ],
  },
  {
    service: "Pantheon",
    patterns: [
      /The gods are wise, but do not know of the site which you seek/i,
      /404 error unknown site/i,
    ],
  },
  {
    service: "Tilda",
    patterns: [
      /Please renew your subscription/i,
    ],
  },
  {
    service: "Smartling",
    patterns: [
      /Domain is not configured/i,
    ],
  },
  {
    service: "Acquia",
    patterns: [
      /Web Site Not Found/i,
    ],
  },
  {
    service: "Vercel",
    patterns: [
      /The deployment could not be found/i,
    ],
  },
];

/**
 * Match a CNAME target against known vulnerable patterns.
 * Returns the first match or null.
 */
export function matchVulnerablePattern(
  cname: string,
): { service: string; evidence: string } | null {
  for (const entry of VULNERABLE_PATTERNS) {
    if (entry.pattern.test(cname)) {
      return { service: entry.service, evidence: entry.evidence };
    }
  }
  return null;
}

/**
 * Check an HTTP response body for known takeover signatures.
 * Only checks signatures for the matching service to avoid false positives.
 */
export function matchTakeoverSignature(service: string, body: string): boolean {
  for (const entry of TAKEOVER_SIGNATURES) {
    if (entry.service !== service) continue;
    for (const pattern of entry.patterns) {
      if (pattern.test(body)) return true;
    }
  }
  return false;
}

/**
 * Decide a takeover verdict from the probe outcome.
 *
 * A body signature only upgrades to `vulnerable: true` when the response also
 * has a failure status (4xx/5xx). Platforms serve custom error content on
 * soft-404s too, so the same phrases inside an active 2xx/3xx page are not
 * proof of a dangling resource; they stay non-vulnerable with a manual
 * verification note rather than an actionable accusation.
 */
export function evaluateTakeoverVerdict(
  service: string,
  httpStatus: number,
  signatureMatched: boolean,
  hostname: string,
): { vulnerable: boolean; evidence: string } {
  if (signatureMatched && httpStatus >= 400) {
    return {
      vulnerable: true,
      evidence: `${service} takeover signature found in HTTP response (status ${httpStatus}) at ${hostname}`,
    };
  }
  if (signatureMatched) {
    return {
      vulnerable: false,
      evidence: `${service} takeover signature observed on an active HTTP ${httpStatus} response at ${hostname} — manual verification recommended`,
    };
  }
  if (httpStatus === 404 || httpStatus === 410) {
    return {
      vulnerable: false,
      evidence: `${service} CNAME with HTTP ${httpStatus} — potential dangling resource (manual verification recommended)`,
    };
  }
  return {
    vulnerable: false,
    evidence: `${service} CNAME resolves and HTTP returned ${httpStatus} — resource appears active`,
  };
}

/**
 * Read up to MAX_BODY_BYTES from a Response body as text.
 */
async function readBodyLimited(response: Response, budget?: RequestBudget): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";

  const decoder = new TextDecoder();
  let body = "";
  let bytesRead = 0;

  try {
    while (bytesRead < MAX_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) {
        body += decoder.decode();
        return body;
      }
      const remaining = MAX_BODY_BYTES - bytesRead;
      const requested = Math.min(value.byteLength, remaining);
      const accepted = budget ? budget.inspectBytes(requested) : requested;
      if (accepted > 0) {
        body += decoder.decode(value.subarray(0, accepted), { stream: true });
        bytesRead += accepted;
      }
      if (accepted < value.byteLength) {
        await reader.cancel();
        break;
      }
    }
    await reader.cancel();
    body += decoder.decode();
    return body;
  } finally {
    reader.releaseLock();
  }
}

/**
 * Probe a single subdomain for takeover potential.
 *
 * 1. Query CNAME record
 * 2. Return null unless the CNAME target matches a known vulnerable service
 *    — non-qualifying outcomes (failed or absent CNAME lookups, unrelated
 *    CNAME targets) stay out of the report entirely, exactly as the
 *    probeTakeover contract promises.
 * 3. Otherwise do an HTTP GET; if the response body contains the service's
 *    takeover signature, evaluateTakeoverVerdict decides the claim.
 */
async function probeSubdomain(
  subdomain: string,
  budget?: RequestBudget,
  validatedHosts?: Map<string, PublicResolution>,
): Promise<SubdomainTakeoverCheck | null> {
  const dnsResult = await queryDns(subdomain, "CNAME", "cloudflare", budget);
  const cname = dnsResult.answers.find((a) => a.type === "CNAME")?.data;
  if (!cname) return null;

  const match = matchVulnerablePattern(cname);
  if (!match) return null;

  // HTTP probe to look for takeover signatures
  try {
    const { response, url } = await fetchPublicUrl(
      `https://${subdomain}`,
      requireBudget(budget),
      { signal: AbortSignal.timeout(PROBE_TIMEOUT), resource: "takeover" },
      2,
      validatedHosts,
    );

    const httpStatus = response.status;

    // Read response body for signature matching
    let body = "";
    try {
      body = await readBodyLimited(response, budget);
    } catch {
      // Body read failed — we still have the status code
    }

    const outcome = evaluateTakeoverVerdict(
      match.service,
      httpStatus,
      matchTakeoverSignature(match.service, body),
      url.hostname,
    );
    return {
      subdomain,
      cname,
      resolvable: true,
      httpStatus,
      ...outcome,
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : "HTTP probe failed";
    return {
      subdomain,
      cname,
      resolvable: true,
      httpStatus: null,
      vulnerable: false,
      evidence: `${match.service} CNAME present but HTTP probe failed: ${msg}`,
    };
  }
}

/**
 * Probe discovered subdomains for potential subdomain takeover.
 *
 * Takes CT-discovered subdomains (up to MAX_PROBES) and checks each for:
 * - CNAME records matching known vulnerable services
 * - HTTP response signatures indicating dangling resources
 *
 * Returns an array of SubdomainTakeoverCheck results. Only subdomains with
 * a matching CNAME pattern are included — clean subdomains are filtered out
 * to keep the signal-to-noise ratio high.
 */
export async function probeTakeover(
  subdomains: string[],
  budget?: RequestBudget,
  validatedHosts?: Map<string, PublicResolution>,
): Promise<SubdomainTakeoverCheck[]> {
  const gated = requireBudget(budget);
  const targets = subdomains.slice(0, MAX_PROBES);
  const results: SubdomainTakeoverCheck[] = [];
  for (const subdomain of targets) {
    if (!gated.canStart()) break;
    try {
      const check = await probeSubdomain(subdomain, gated, validatedHosts);
      if (check) results.push(check);
    } catch {
      // Rejected probes (blocked derived target, exhausted budget) carry no
      // CNAME evidence; they stay out of the results like the other
      // cname-less outcomes. Phase coverage counters record the shortfall.
    }
  }
  return results;
}
