export type EvidenceKind =
  | "dns_observation"
  | "edge_http_observation"
  | "derived_finding"
  | "unavailable";

export interface DnsAnswer {
  name: string;
  type: string;
  ttl: number;
  data: string;
}

export interface DnsQueryResult {
  resolver: string;
  name: string;
  type: string;
  status: number;
  authenticatedData: boolean;
  answers: DnsAnswer[];
  elapsedMs: number;
  error?: string;
  evidenceKind: "dns_observation";
}

export interface RedirectHop {
  index: number;
  url: string;
  hostname: string;
  status: number;
  statusText: string;
  elapsedMs: number;
  location: string | null;
  responseHeaders: Record<string, string>;
  cf: {
    colo?: string;
    country?: string;
    httpProtocol?: string;
    tlsVersion?: string;
  };
  error?: string;
  evidenceKind: "edge_http_observation";
}

export interface Dependency {
  url: string;
  host: string;
  type: "script" | "stylesheet" | "image" | "font" | "media" | "frame" | "preload" | "other";
  party: "first-party" | "third-party";
}

export interface Finding {
  code: string;
  severity: "positive" | "info" | "warning" | "critical";
  title: string;
  detail: string;
  evidencePath: string;
  confidence: "high" | "medium";
  evidenceKind: "derived_finding";
}

export interface PageSecuritySignals {
  passwordForm: boolean;
  forms: number;
  externalFormAction: boolean;
  matchedLanguage: Array<"login" | "verification" | "password-reset" | "payment">;
}

export interface UrlRiskFinding {
  code: string;
  severity: "low" | "medium" | "high";
  score: number;
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
  confidence: "high" | "medium";
  source: "requestscope" | "page_observation" | "reputation_provider";
}

export type ReputationProviderName = "google_web_risk" | "phishtank" | "cloudflare_family_dns";

export interface ReputationProviderResult {
  provider: ReputationProviderName;
  target: "requested" | "final";
  hostname: string;
  status: "matched" | "not_listed" | "inconclusive" | "unavailable" | "quota_limited" | "not_configured";
  threatTypes: string[];
  detail: string;
  checkedAt: string;
  expiresAt: string | null;
  advisoryUrl: string;
  attribution: string;
}

export interface ReputationAssessment {
  status: "matched" | "not_listed" | "partial" | "unavailable" | "not_configured" | "not_requested";
  detail: string;
  consentRequired: true;
  providers: ReputationProviderResult[];
}

export interface UrlRiskAssessment {
  schemaVersion: 1;
  verdict: "low" | "medium" | "high";
  riskScore: number;
  confidence: "high" | "medium";
  summary: string;
  requestedUrl: string;
  finalUrl: string | null;
  traceId: string;
  reportPath: string;
  claimedOrganisation: string | null;
  services: Array<{ hostname: string; organisation: string; category: DomainCategory }>;
  findings: UrlRiskFinding[];
  reputation: ReputationAssessment;
  limitations: string[];
}

export type DomainCategory =
  | "functional"
  | "analytics"
  | "advertising"
  | "cdn"
  | "payment"
  | "communication"
  | "monitoring"
  | "security"
  | "marketing"
  | "social"
  | "testing"
  | "video"
  | "auth"
  | "consent"
  | "hosting"
  | "unknown";

export interface MappedDomain {
  domain: string;
  category: DomainCategory;
  serviceName: string | null;
  source: "csp" | "js-bundle" | "cert-transparency" | "multiple";
  piiRisk: boolean;
  postAuthOnly: boolean;
  occurrences: number;
  evidence: string[];
}

export interface SdkDetection {
  name: string;
  domain: string;
  category: DomainCategory;
  match: string;
}

export interface SslDetail {
  source: "certificate_transparency";
  protocol: string | null;
  cipher: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysUntilExpiry: number | null;
  authorityKeyIdentifier: string | null;
}

export type CoverageStatus = "complete" | "partial" | "failed" | "unavailable" | "skipped";

export interface PhaseCoverage {
  status: CoverageStatus;
  attempted: number;
  successful: number;
  failed: number;
  skipped: number;
  bytesInspected: number;
  truncated: boolean;
  durationMs: number;
  detail?: string;
}

export interface ScanCoverage {
  status: CoverageStatus;
  budget: {
    maxSubrequests: number;
    subrequestsStarted: number;
    subrequestsSucceeded: number;
    subrequestsFailed: number;
    maxBodyBytes: number;
    bodyBytesInspected: number;
    maxConcurrent: number;
    peakConcurrent: number;
    deadlineMs: number;
    elapsedMs: number;
    exhausted: boolean;
    exhaustionReason?: string;
  };
  phases: {
    core: PhaseCoverage;
    dependencies: PhaseCoverage;
    reputation: PhaseCoverage;
  };
}

export interface SubdomainTakeoverCheck {
  subdomain: string;
  cname: string | null;
  resolvable: boolean;
  httpStatus: number | null;
  vulnerable: boolean;
  evidence: string;
}

export interface ConsentPlatform {
  name: string;
  detectedVia: string;
}

export interface CspAnalysis {
  present: boolean;
  raw?: string;
  directives: Record<string, string[]>;
  domains: string[];
}

export interface JsBundleAnalysis {
  attempted: number;
  successful: number;
  failed: number;
  skipped: number;
  bundlesFetched: number;
  totalBytes: number;
  truncated: boolean;
  domains: string[];
  patterns: Array<{ domain: string; pattern: string; context: string }>;
}

export interface CertTransparencyAnalysis {
  attempted?: number;
  successful?: number;
  failed?: number;
  skipped?: number;
  subdomains: string[];
  total: number;
  truncated?: boolean;
  latest?: { notBefore: string; notAfter: string };
  error?: string;
}

export interface DependencyMap {
  createdAt: string;
  durationMs: number;
  sources: {
    csp: CspAnalysis;
    jsBundles: JsBundleAnalysis;
    certTransparency: CertTransparencyAnalysis;
  };
  domains: MappedDomain[];
  sdks: SdkDetection[];
  ssl: SslDetail;
  takeover: SubdomainTakeoverCheck[];
  summary: {
    totalDomains: number;
    byCategory: Record<string, number>;
    piiRisk: number;
    postAuthOnly: number;
  };
  coverage?: PhaseCoverage;
}

export interface ScanReport {
  schemaVersion: 1;
  id: string;
  requestedUrl: string;
  normalizedUrl: string;
  finalUrl: string | null;
  hostname: string;
  status: "complete" | "partial" | "failed";
  createdAt: string;
  expiresAt: string;
  totalDurationMs: number;
  observation: {
    vantage: "cloudflare-edge";
    colo?: string;
    country?: string;
    disclaimer: string;
    sourceRevision?: string;
  };
  dns: {
    queries: DnsQueryResult[];
    addresses: string[];
    dnssecAuthenticated: boolean;
  };
  http: {
    hops: RedirectHop[];
    finalStatus: number | null;
    contentType: string | null;
    contentBytesInspected: number;
    truncated: boolean;
  };
  pageSecuritySignals?: PageSecuritySignals;
  dependencies: {
    total: number;
    firstParty: number;
    thirdParty: number;
    uniqueHosts: string[];
    items: Dependency[];
  };
  dependencyMap?: DependencyMap;
  urlRisk?: UrlRiskAssessment;
  coverage?: ScanCoverage;
  provenance?: {
    apiVersion: string;
    sourceRevision: string;
    reportSchemaVersion: number;
    databaseSchemaVersion: number;
  };
  findings: Finding[];
  summary: {
    critical: number;
    warning: number;
    positive: number;
    info: number;
  };
}

export interface Env {
  DB: D1Database;
  ALLOWED_ORIGINS: string;
  REPORT_RETENTION_DAYS: string;
  DAILY_SCAN_LIMIT: string;
  MCP_DAILY_LIMIT: string;
  REPORT_DAILY_LIMIT: string;
  SOURCE_REVISION?: string;
  RATE_LIMIT_BYPASS_IPS?: string;
  COPILOT_API_KEY?: string;
  GOOGLE_WEB_RISK_API_KEY?: string;
  PHISHTANK_APP_KEY?: string;
  PHISHTANK_KEYLESS_ENABLED?: string;
  CLOUDFLARE_FAMILY_DNS_ENABLED?: string;
  WEB_RISK_MONTHLY_LIMIT?: string;
  PHISHTANK_DAILY_LIMIT?: string;
  CLOUDFLARE_FAMILY_DNS_DAILY_LIMIT?: string;
}
