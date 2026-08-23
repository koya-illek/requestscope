import { classifyHostname, registrableDomain, type DomainCategory } from "./classifier";
import type { ReputationAssessment, ScanReport, UrlRiskAssessment, UrlRiskFinding } from "./types";

const SHORTENERS = new Set([
  "1url.com", "amzn.to", "bit.do", "bit.ly", "buff.ly", "cutt.ly", "dub.sh", "goo.gl",
  "is.gd", "lnkd.in", "ow.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.co", "tiny.cc",
  "tinyurl.com", "trib.al", "urlz.fr", "youtu.be",
]);

const BRANDS: Array<{ organisation: string; domains: string[]; aliases: string[]; category: DomainCategory }> = [
  { organisation: "Microsoft", domains: ["microsoft.com", "microsoftonline.com", "office.com", "live.com"], aliases: ["microsoft", "office", "m365", "outlook"], category: "functional" },
  { organisation: "Google", domains: ["google.com", "gmail.com"], aliases: ["google", "gmail"], category: "functional" },
  { organisation: "Apple", domains: ["apple.com", "icloud.com"], aliases: ["apple", "icloud"], category: "functional" },
  { organisation: "Amazon", domains: ["amazon.com", "amazon.co.uk", "amazon.ie"], aliases: ["amazon", "aws"], category: "functional" },
  { organisation: "PayPal", domains: ["paypal.com"], aliases: ["paypal"], category: "payment" },
  { organisation: "Stripe", domains: ["stripe.com"], aliases: ["stripe"], category: "payment" },
  { organisation: "Meta", domains: ["facebook.com", "instagram.com", "meta.com"], aliases: ["facebook", "instagram", "meta"], category: "social" },
  { organisation: "DocuSign", domains: ["docusign.com", "docusign.net"], aliases: ["docusign"], category: "functional" },
  { organisation: "Dropbox", domains: ["dropbox.com"], aliases: ["dropbox"], category: "functional" },
  { organisation: "LinkedIn", domains: ["linkedin.com"], aliases: ["linkedin"], category: "social" },
  { organisation: "Adobe", domains: ["adobe.com"], aliases: ["adobe", "acrobat"], category: "functional" },
  { organisation: "Cloudflare", domains: ["cloudflare.com"], aliases: ["cloudflare"], category: "cdn" },
  { organisation: "Revenue Ireland", domains: ["revenue.ie"], aliases: ["revenue"], category: "functional" },
  { organisation: "Bank of Ireland", domains: ["bankofireland.com", "365online.com"], aliases: ["bankofireland", "boi", "365online"], category: "payment" },
  { organisation: "AIB", domains: ["aib.ie"], aliases: ["aib"], category: "payment" },
];

export interface UrlRiskContext {
  claimedOrganisation?: string;
  messageContext?: string;
}

export function assessUrlRisk(
  report: ScanReport,
  rawUrl: string,
  context: UrlRiskContext = {},
  reputation: ReputationAssessment = {
    status: "not_requested",
    detail: "External reputation checks were not requested for this trace.",
    consentRequired: true,
    providers: [],
  },
): UrlRiskAssessment {
  const findings: UrlRiskFinding[] = [];
  const initial = new URL(report.normalizedUrl);
  const hosts = [...new Set(report.http.hops.map((hop) => hop.hostname.toLowerCase()))];
  if (!hosts.includes(initial.hostname)) hosts.unshift(initial.hostname);
  const finalHost = report.finalUrl ? new URL(report.finalUrl).hostname : null;
  const claimed = context.claimedOrganisation?.trim().slice(0, 120) || null;

  if (SHORTENERS.has(registrableDomain(initial.hostname))) {
    add(findings, "known-shortener", "medium", 18, "Known URL shortener", "The submitted hostname is a known shortening service, so the destination was hidden until followed.", { hostname: initial.hostname });
  }

  const registrableHosts = [...new Set(hosts.map(registrableDomain))];
  if (registrableHosts.length > 1) {
    add(findings, "cross-domain-redirect", registrableHosts.length > 2 ? "medium" : "low", registrableHosts.length > 2 ? 18 : 10,
      "Redirect crossed organisational domains", `The trace traversed ${registrableHosts.length} registrable domains.`, { domains: registrableHosts });
  }

  const rawHost = extractRawHostname(rawUrl);
  const hasUnicode = /[^\x00-\x7f]/.test(rawHost);
  const mixedScript = /[a-z]/i.test(rawHost) && /[\u0370-\u03ff\u0400-\u04ff]/u.test(rawHost);
  if (hosts.some((host) => host.split(".").some((label) => label.startsWith("xn--"))) || hasUnicode) {
    add(findings, "internationalized-domain", mixedScript ? "high" : "medium", mixedScript ? 35 : 16,
      mixedScript ? "Mixed-script lookalike risk" : "Internationalized hostname", mixedScript
        ? "The hostname mixes Latin with Greek or Cyrillic characters, a common visual impersonation technique."
        : "The hostname contains an internationalized label. Verify how it is displayed before trusting it.",
      { asciiHostname: initial.hostname, suppliedHostname: rawHost.slice(0, 253), mixedScript }, mixedScript ? "high" : "medium");
  }

  const encodedCount = (rawUrl.match(/%[0-9a-f]{2}/gi) || []).length;
  const repeatedEncoding = /%25[0-9a-f]{2}/i.test(rawUrl);
  const queryCount = initial.searchParams.size;
  if (repeatedEncoding || encodedCount >= 4 || queryCount >= 8 || rawUrl.length > 300) {
    add(findings, "unusual-url-structure", "medium", repeatedEncoding ? 18 : 10, "Unusual URL structure",
      "The submitted URL uses unusually dense encoding, parameters, or length. This can obscure its purpose.",
      { encodedSequences: encodedCount, repeatedEncoding, queryParameterCount: queryCount, length: rawUrl.length }, "medium");
  }

  if (initial.hostname.split(".").length >= 5 || initial.hostname.length > 60) {
    add(findings, "deceptive-hostname-shape", "low", 8, "Complex hostname", "The hostname is unusually long or deeply nested and may be difficult to read accurately.",
      { hostname: initial.hostname, labels: initial.hostname.split(".").length });
  }

  const brand = resolveClaimedBrand(claimed);
  for (const host of registrableHosts) {
    const candidate = host.split(".")[0].replace(/[^a-z0-9]/g, "");
    for (const entry of brand ? [brand] : BRANDS) {
      if (entry.domains.some((domain) => host === domain || host.endsWith(`.${domain}`))) continue;
      const match = matchLookalike(host.split(".")[0], candidate, entry.aliases, Boolean(brand));
      if (!match) continue;
      const detail = match.matchType === "edit-distance"
        ? `${host} resembles a known ${entry.organisation} name but is not one of its recognised domains.`
        : match.matchType === "name-containment"
          ? `${host} combines a known ${entry.organisation} name with additional words, a common impersonation pattern.`
          : `${host} uses a known ${entry.organisation} name but is not one of its recognised domains; legitimate sibling or regional domains are possible.`;
      add(findings, "brand-lookalike", match.severity, brand ? match.score + 6 : match.score,
        `Possible ${entry.organisation} lookalike`, detail,
        { hostname: host, organisation: entry.organisation, expectedDomains: entry.domains, matchedName: match.matchedName, matchType: match.matchType },
        match.confidence);
      break;
    }
  }

  const signals = report.pageSecuritySignals;
  if (signals?.externalFormAction) {
    add(findings, "external-form-action", "high", 30, "Form submits to another site", "A form on the final page submits information to a different hostname.", { finalHostname: finalHost }, "high", "page_observation");
  }
  if (signals?.passwordForm) {
    const suspiciousHost = findings.some((item) => item.code === "brand-lookalike" || item.code === "internationalized-domain");
    add(findings, "password-form", suspiciousHost ? "high" : "medium", suspiciousHost ? 28 : 14, "Password field observed",
      "The inspected page contains a password input. This is expected on legitimate login pages but increases impact when combined with deceptive-domain indicators.",
      { finalHostname: finalHost }, "high", "page_observation");
  }
  if (signals && signals.matchedLanguage.length > 0) {
    const contextMatch = context.messageContext ? matchedContextTerms(context.messageContext) : [];
    add(findings, "sensitive-action-language", "low", 6, "Sensitive action language observed",
      `The page contains language associated with ${signals.matchedLanguage.join(", ")}.`,
      { pageSignals: signals.matchedLanguage, contextSignals: contextMatch }, "medium", "page_observation");
  }

  if (report.http.finalStatus === null || report.status === "failed") {
    add(findings, "incomplete-observation", "low", 0, "Destination could not be fully inspected", "A failed or blocked fetch limits the assessment; absence of other findings is not evidence of safety.", { scanStatus: report.status }, "medium");
  }

  for (const provider of reputation.providers.filter((item) => item.status === "matched")) {
    add(
      findings,
      `external-reputation-${provider.provider}-${provider.target}`,
      "high",
      60,
      `${provider.provider === "google_web_risk" ? "Google Web Risk" : provider.provider === "cloudflare_family_dns" ? "Cloudflare malware-filtering DNS" : "PhishTank"} reputation match`,
      provider.detail,
      {
        provider: provider.provider,
        target: provider.target,
        hostname: provider.hostname,
        threatTypes: provider.threatTypes,
        checkedAt: provider.checkedAt,
        expiresAt: provider.expiresAt,
      },
      "high",
      "reputation_provider",
    );
  }

  const services = hosts.flatMap((hostname) => {
    const registered = registrableDomain(hostname);
    const brandMatch = BRANDS.find((entry) => entry.domains.includes(registered));
    if (brandMatch) return [{ hostname, organisation: brandMatch.organisation, category: brandMatch.category }];
    const match = classifyHostname(hostname);
    return match.name ? [{ hostname, organisation: match.name, category: match.category }] : [];
  });
  const riskScore = Math.min(100, findings.reduce((total, item) => total + item.score, 0));
  const verdict = riskScore >= 60 ? "high" : riskScore >= 30 ? "medium" : "low";
  const confidence = report.status === "complete"
    && !findings.some((item) => item.confidence === "medium")
    && !["partial", "unavailable"].includes(reputation.status)
    ? "high"
    : "medium";
  return {
    schemaVersion: 1,
    verdict,
    riskScore,
    confidence,
    summary: reputation.status === "matched"
      ? "An external reputation provider identifies a checked URL as potentially unsafe. Avoid visiting it or entering information until it is independently verified."
      : verdict === "low"
        ? "No strong risk indicators were found; this does not prove the URL is safe."
        : `${verdict === "high" ? "Strong" : "Some"} risk indicators were observed. Review the evidence before visiting or entering information.`,
    requestedUrl: report.requestedUrl,
    finalUrl: report.finalUrl,
    traceId: report.id,
    reportPath: `/api/scans/${report.id}`,
    claimedOrganisation: claimed,
    services,
    findings,
    reputation,
    limitations: [
      "A low rating means no strong indicators were observed, not that the URL is safe.",
      "Page signals come from bounded static HTML and do not include browser-executed content.",
      reputation.status === "not_requested"
        ? "External reputation was not requested for this assessment."
        : "A provider not listing a URL is not proof that the URL is safe.",
    ],
  };
}

function add(findings: UrlRiskFinding[], code: string, severity: UrlRiskFinding["severity"], score: number, title: string,
  detail: string, evidence: Record<string, unknown>, confidence: UrlRiskFinding["confidence"] = "high",
  source: UrlRiskFinding["source"] = "requestscope"): void {
  findings.push({ code, severity, score, title, detail, evidence, confidence, source });
}

function resolveClaimedBrand(claimed: string | null) {
  if (!claimed) return null;
  const normalized = normalizeBrandName(claimed);
  // An exact match always resolves, no matter how short the name ("AIB",
  // "AWS"). Prefix matching keeps verbose real-world claims ("Microsoft
  // Corporation", "Bank of Ireland Group") effective but only from this
  // length so a short alias like "boi" cannot absorb unrelated claims
  // ("Boiler Repair Co").
  const MIN_PREFIX_NAME_LENGTH = 4;
  const matchesName = (name: string): boolean =>
    normalized === name || (name.length >= MIN_PREFIX_NAME_LENGTH && normalized.startsWith(name));
  return BRANDS.find((entry) =>
    entry.aliases.some((alias) => matchesName(normalizeBrandName(alias)))
    || matchesName(normalizeBrandName(entry.organisation)),
  ) || null;
}

function normalizeBrandName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

interface LookalikeMatch {
  matchedName: string;
  matchType: "exact-name-alt-tld" | "edit-distance" | "name-containment";
  severity: UrlRiskFinding["severity"];
  score: number;
  confidence: UrlRiskFinding["confidence"];
}

/** Aliases shorter than this are too collision-prone for containment matching
 * unless the caller explicitly claimed the brand: the claim itself then
 * provides the disambiguation that the length gate otherwise approximates. */
const MIN_CONTAINMENT_ALIAS_LENGTH = 5;

function matchLookalike(label: string, candidate: string, aliases: string[], claimedBrand = false): LookalikeMatch | null {
  const exact = aliases.find((alias) => candidate === alias);
  if (exact) {
    // An exact brand name on an unrecognised domain may be a legitimate
    // sibling TLD, so it is reported with reduced severity and confidence.
    return { matchedName: exact, matchType: "exact-name-alt-tld", severity: "medium", score: 14, confidence: "medium" };
  }
  const typo = aliases.find((alias) => editDistanceWithinOne(candidate, alias));
  if (typo) return { matchedName: typo, matchType: "edit-distance", severity: "high", score: 32, confidence: "high" };
  const contained = aliases.find((alias) =>
    (claimedBrand || alias.length >= MIN_CONTAINMENT_ALIAS_LENGTH) && containsBrandToken(label, alias));
  if (contained) return { matchedName: contained, matchType: "name-containment", severity: "medium", score: 16, confidence: "medium" };
  return null;
}

/** Tokens that, when combined with a brand name in the same hostname label,
 * suggest impersonation rather than an ordinary compound word. Without this
 * gate, benign domains like `apple-orchard.com` or `office-supplies.ie`
 * would earn brand-lookalike findings for everyday English aliases such as
 * "apple" or "office". */
const RISK_CONTEXT_TOKENS: ReadonlySet<string> = new Set([
  "login", "logins", "signin", "signins", "signup", "secure", "security",
  "verify", "verification", "account", "accounts", "auth", "confirm",
  "billing", "payment", "payments", "update", "recovery", "reset",
  "wallet", "invoice", "alert", "alerts", "notice", "notification",
  "support", "helpdesk", "mail", "webmail", "id", "session",
]);

/** Match a brand name as a whole separator-delimited word inside the first
 * hostname label, e.g. "microsoft-login" or "secure-paypal". At least one of
 * the remaining tokens must be risk-related so that ordinary compound words
 * are not reported as impersonation. */
function containsBrandToken(label: string, alias: string): boolean {
  const tokens = label.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (tokens.length < 2 || !tokens.includes(alias)) return false;
  return tokens.some((token) => token !== alias && RISK_CONTEXT_TOKENS.has(token));
}

function editDistanceWithinOne(candidate: string, brand: string): boolean {
  if (candidate.length < 4 || brand.length < 4 || Math.abs(candidate.length - brand.length) > 1) return false;
  return editDistance(candidate, brand) <= 1;
}

function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    let previous = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const saved = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
      previous = saved;
    }
  }
  return row[b.length];
}

function extractRawHostname(rawUrl: string): string {
  const value = rawUrl.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  return (value.split(/[/?#]/, 1)[0] || "").replace(/^.*@/, "").replace(/:\d+$/, "").toLowerCase();
}

function matchedContextTerms(context: string): string[] {
  const lower = context.slice(0, 1000).toLowerCase();
  return [
    ["login", /\b(?:log[ -]?in|sign[ -]?in)\b/],
    ["verification", /\bverif(?:y|ication)\b/],
    ["password-reset", /\b(?:reset|expired|change) (?:your )?password\b/],
    ["payment", /\b(?:payment|invoice|billing|credit card)\b/],
  ].filter(([, pattern]) => (pattern as RegExp).test(lower)).map(([name]) => name as string);
}
