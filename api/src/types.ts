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
  dependencies: {
    total: number;
    firstParty: number;
    thirdParty: number;
    uniqueHosts: string[];
    items: Dependency[];
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
  ENVIRONMENT: string;
  TURNSTILE_SECRET?: string;
}
