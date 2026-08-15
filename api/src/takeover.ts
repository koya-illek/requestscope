import type { SubdomainTakeoverCheck } from "./types";
import { queryDns } from "./dns";
import { fetchPublicUrl } from "./egress";
import type { RequestBudget } from "./budget";

const MAX_PROBES = 20;
const PROBE_TIMEOUT = 5_000;
const MAX_BODY_BYTES = 102_400; // 100 KB — enough for signature matching

// Known vulnerable CNAME patterns that indicate potential takeover
const VULNERABLE_PATTERNS: Array<{ pattern: RegExp; service: string; evidence: string }> = [
  // GitHub Pages
  { pattern: /\.github\.io$/i, service: "GitHub Pages", evidence: "CNAME points to GitHub Pages - verify the repo exists" },
  // AWS S3
  { pattern: /\.s3\.amazonaws\.com$/i, service: "AWS S3", evidence: "CNAME points to S3 - verify the bucket exists" },
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
      /The web site you have accessed is not available/i,
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
    patterns: [
      /The page you are looking for doesn't exist or has been moved/i,
    ],
  },
  {
    service: "Cargo",
    patterns: [
      /404 Not Found.*cargo/i,
      /The page you were looking for doesn't exist/i,
    ],
  },
  {
    service: "Tumblr",
    patterns: [
      /Whatever you were looking for doesn't currently exist at this address/i,
      /There's nothing here/i,
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
    patterns: [
      /No Such Site/i,
      /domain not found/i,
    ],
  },
  {
    service: "Webflow",
    patterns: [
      /The page you are looking for doesn't exist/i,
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
function matchVulnerablePattern(
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
function matchTakeoverSignature(service: string, body: string): boolean {
  for (const entry of TAKEOVER_SIGNATURES) {
    if (entry.service !== service) continue;
    for (const pattern of entry.patterns) {
      if (pattern.test(body)) return true;
    }
  }
  return false;
}

/**
 * Read up to MAX_BODY_BYTES from a Response body as text.
 */
async function readBodyLimited(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    return (await response.text()).slice(0, MAX_BODY_BYTES);
  }

  const decoder = new TextDecoder();
  let body = "";
  let bytesRead = 0;

  while (bytesRead < MAX_BODY_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = MAX_BODY_BYTES - bytesRead;
    const chunk = value.byteLength > remaining ? value.slice(0, remaining) : value;
    bytesRead += chunk.byteLength;
    body += decoder.decode(chunk, { stream: bytesRead < MAX_BODY_BYTES });
    if (chunk.byteLength < value.byteLength) {
      await reader.cancel();
      break;
    }
  }
  body += decoder.decode(); // flush

  return body;
}

/**
 * Probe a single subdomain for takeover potential.
 *
 * 1. Query CNAME record
 * 2. If CNAME matches a known vulnerable service, do an HTTP GET
 * 3. If the HTTP response body contains a takeover signature, mark vulnerable
 */
async function probeSubdomain(
  subdomain: string,
  budget?: RequestBudget,
): Promise<SubdomainTakeoverCheck> {
  // Step 1: Query CNAME
  const dnsResult = await queryDns(subdomain, "CNAME", "cloudflare", budget);

  if (dnsResult.error || dnsResult.answers.length === 0) {
    return {
      subdomain,
      cname: null,
      resolvable: false,
      httpStatus: null,
      vulnerable: false,
      evidence: "No CNAME record found",
    };
  }

  const cnameRecord = dnsResult.answers.find((a) => a.type === "CNAME");
  if (!cnameRecord) {
    return {
      subdomain,
      cname: null,
      resolvable: true,
      httpStatus: null,
      vulnerable: false,
      evidence: "DNS resolved but no CNAME record present",
    };
  }

  const cname = cnameRecord.data;

  // Step 2: Check against vulnerable patterns
  const match = matchVulnerablePattern(cname);
  if (!match) {
    return {
      subdomain,
      cname,
      resolvable: true,
      httpStatus: null,
      vulnerable: false,
      evidence: `CNAME points to ${cname} — no known takeover pattern`,
    };
  }

  // Step 3: HTTP probe to look for takeover signatures
  try {
    const { response, url } = budget
      ? await fetchPublicUrl(`https://${subdomain}`, budget, { signal: AbortSignal.timeout(PROBE_TIMEOUT), resource: "takeover" }, 2)
      : { response: await fetch(`https://${subdomain}`, { redirect: "manual", signal: AbortSignal.timeout(PROBE_TIMEOUT) }), url: new URL(`https://${subdomain}`) };

    const httpStatus = response.status;
    const isErrorStatus = httpStatus === 404 || httpStatus === 410;

    // Read response body for signature matching
    let body = "";
    try {
      body = await readBodyLimited(response);
    } catch {
      // Body read failed — we still have the status code
    }

    // Step 4: Check for takeover signatures in the response body
    if (matchTakeoverSignature(match.service, body)) {
      return {
        subdomain,
        cname,
        resolvable: true,
        httpStatus,
        vulnerable: true,
        evidence: `${match.service} takeover signature found in HTTP response (status ${httpStatus}) at ${url.hostname}`,
      };
    }

    // Conservative: error status + matching CNAME pattern = potentially vulnerable
    if (isErrorStatus) {
      return {
        subdomain,
        cname,
        resolvable: true,
        httpStatus,
        vulnerable: false,
        evidence: `${match.service} CNAME with HTTP ${httpStatus} — potential dangling resource (manual verification recommended)`,
      };
    }

    return {
      subdomain,
      cname,
      resolvable: true,
      httpStatus,
      vulnerable: false,
      evidence: `${match.service} CNAME resolves and HTTP returned ${httpStatus} — resource appears active`,
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
): Promise<SubdomainTakeoverCheck[]> {
  const targets = subdomains.slice(0, MAX_PROBES);
  const results: SubdomainTakeoverCheck[] = [];
  for (const subdomain of targets) {
    if (budget && !budget.canStart()) break;
    try {
      const check = await probeSubdomain(subdomain, budget);
      if (check.cname !== null) results.push(check);
    } catch (error) {
      results.push({
        subdomain,
        cname: null,
        resolvable: false,
        httpStatus: null,
        vulnerable: false,
        evidence: `Probe rejected: ${error instanceof Error ? error.message : "unknown error"}`,
      });
    }
  }
  return results;
}
