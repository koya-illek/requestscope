import type { RequestBudget } from "./budget";
import type {
  ReputationAssessment,
  ReputationProviderName,
  ReputationProviderResult,
} from "./types";

const PROVIDER_TIMEOUT_MS = 2_500;
const NEGATIVE_CACHE_SECONDS = 15 * 60;
const POSITIVE_CACHE_SECONDS = 30 * 60;
const MAX_CACHE_SECONDS = 24 * 60 * 60;

export interface ReputationConfig {
  enabled: boolean;
  googleWebRiskApiKey?: string;
  phishTankAppKey?: string;
  phishTankEnabled?: boolean;
  cloudflareFamilyDnsEnabled?: boolean;
  consumeQuota?: (provider: ReputationProviderName) => Promise<boolean>;
  now?: () => Date;
  budget?: RequestBudget;
}

interface Target {
  kind: "requested" | "final";
  url: string;
}

export async function checkExternalReputation(
  requestedUrl: string,
  finalUrl: string | null,
  config: ReputationConfig,
): Promise<ReputationAssessment> {
  if (!config.enabled) {
    return {
      status: "not_requested",
      detail: "External reputation checks were not requested for this trace.",
      consentRequired: true,
      providers: [],
    };
  }

  const targets = uniqueTargets(requestedUrl, finalUrl);
  const configured = [
    config.googleWebRiskApiKey ? "google_web_risk" : null,
    phishTankConfigured(config) ? "phishtank" : null,
    config.cloudflareFamilyDnsEnabled ? "cloudflare_family_dns" : null,
  ].filter(Boolean);
  if (configured.length === 0) {
    return {
      status: "not_configured",
      detail: "External reputation was requested, but no provider credentials are configured.",
      consentRequired: true,
      providers: [],
    };
  }

  const results = await Promise.all(targets.flatMap((target) => [
    ...(config.googleWebRiskApiKey
      ? [cachedLookup("google_web_risk", target, config, () => lookupGoogleWebRisk(target, config))]
      : []),
    ...(phishTankConfigured(config)
      ? [cachedLookup("phishtank", target, config, () => lookupPhishTank(target, config))]
      : []),
    ...(config.cloudflareFamilyDnsEnabled
      ? [cachedLookup("cloudflare_family_dns", target, config, () => lookupCloudflareFamilyDns(target, config))]
      : []),
  ]));

  return summarize(results);
}

async function cachedLookup(
  provider: ReputationProviderName,
  target: Target,
  config: ReputationConfig,
  lookup: () => Promise<ReputationProviderResult>,
): Promise<ReputationProviderResult> {
  const key = await cacheKey(provider, target.url);
  let cache: Cache | null = null;
  try {
    cache = await caches.open("requestscope-reputation-v1");
    const cached = await cache.match(key);
    if (cached) return { ...await cached.json<ReputationProviderResult>(), target: target.kind };
  } catch {
    // Reputation remains available if edge caching is temporarily unavailable.
  }

  if (config.consumeQuota) {
    try {
      if (!await config.consumeQuota(provider)) {
        return result(provider, target, config, "quota_limited", [], "The configured RequestScope provider quota has been reached.");
      }
    } catch {
      return result(provider, target, config, "unavailable", [], "RequestScope could not verify the provider quota safely, so the lookup was not sent.");
    }
  }

  const value = await lookup();
  if (value.status === "matched" || value.status === "not_listed" || value.status === "inconclusive") {
    const ttl = cacheSeconds(value);
    if (cache) {
      try {
        await cache.put(key, new Response(JSON.stringify(value), {
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": `public, max-age=${ttl}`,
          },
        }));
      } catch {
        // A cache write failure must not erase a completed provider observation.
      }
    }
  }
  return value;
}

async function lookupGoogleWebRisk(target: Target, config: ReputationConfig): Promise<ReputationProviderResult> {
  try {
    const endpoint = new URL("https://webrisk.googleapis.com/v1/uris:search");
    endpoint.searchParams.append("threatTypes", "MALWARE");
    endpoint.searchParams.append("threatTypes", "SOCIAL_ENGINEERING");
    endpoint.searchParams.append("threatTypes", "UNWANTED_SOFTWARE");
    endpoint.searchParams.set("uri", target.url);
    endpoint.searchParams.set("key", config.googleWebRiskApiKey || "");
    const response = await (config.budget ? config.budget.fetch(endpoint, {
      method: "GET",
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      headers: { Accept: "application/json" },
      resource: "provider",
    }) : fetch(endpoint, {
      method: "GET",
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      headers: { Accept: "application/json" },
    }));
    if (response.status === 429) {
      return result("google_web_risk", target, config, "quota_limited", [], "Google Web Risk rate-limited this lookup.");
    }
    if (!response.ok) {
      return result("google_web_risk", target, config, "unavailable", [], `Google Web Risk returned HTTP ${response.status}.`);
    }
    const payload = await response.json() as { threat?: { threatTypes?: unknown; expireTime?: unknown } };
    const threatTypes = Array.isArray(payload.threat?.threatTypes)
      ? payload.threat.threatTypes.filter((item): item is string => typeof item === "string")
      : [];
    const expiresAt = typeof payload.threat?.expireTime === "string" ? payload.threat.expireTime : null;
    return {
      ...result(
        "google_web_risk",
        target,
        config,
        threatTypes.length ? "matched" : "not_listed",
        threatTypes,
        threatTypes.length
          ? `Google Web Risk lists this URL for ${threatTypes.map(readableThreat).join(", ")}.`
          : "This URL was not present on the Google Web Risk lists checked at this time; that is not proof of safety.",
      ),
      expiresAt,
    };
  } catch (error) {
    return result(
      "google_web_risk",
      target,
      config,
      "unavailable",
      [],
      error instanceof DOMException && error.name === "TimeoutError"
        ? "Google Web Risk did not respond within 2.5 seconds."
        : "Google Web Risk could not be reached.",
    );
  }
}

async function lookupPhishTank(target: Target, config: ReputationConfig): Promise<ReputationProviderResult> {
  try {
    const body = new URLSearchParams({
      url: target.url,
      format: "json",
    });
    if (config.phishTankAppKey) body.set("app_key", config.phishTankAppKey);
    const response = await (config.budget ? config.budget.fetch("https://checkurl.phishtank.com/checkurl/", {
      method: "POST",
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        // PhishTank's edge challenge requires its documented phishtank/<identifier> form.
        "User-Agent": "phishtank/requestscope (+https://requestscope.illek.ie)",
      },
      body,
      resource: "provider",
    }) : fetch("https://checkurl.phishtank.com/checkurl/", {
      method: "POST",
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "phishtank/requestscope (+https://requestscope.illek.ie)",
      },
      body,
    }));
    if (response.status === 429 || response.status === 509) {
      return result("phishtank", target, config, "quota_limited", [], "PhishTank rate-limited this lookup.");
    }
    if (!response.ok) {
      return result("phishtank", target, config, "unavailable", [], `PhishTank returned HTTP ${response.status}.`);
    }
    const payload = await response.json() as { results?: Record<string, unknown> };
    const value = payload.results || {};
    const inDatabase = truthy(value.in_database);
    const verified = truthy(value.verified);
    const valid = truthy(value.valid);
    if (inDatabase && verified && valid) {
      return result("phishtank", target, config, "matched", ["PHISHING"], "PhishTank lists this URL as a verified, active phishing page.");
    }
    if (inDatabase) {
      return result("phishtank", target, config, "inconclusive", [], "PhishTank has a record for this URL, but it is not currently both verified and active.");
    }
    return result("phishtank", target, config, "not_listed", [], "This URL was not listed by PhishTank at this time; that is not proof of safety.");
  } catch (error) {
    return result(
      "phishtank",
      target,
      config,
      "unavailable",
      [],
      error instanceof DOMException && error.name === "TimeoutError"
        ? "PhishTank did not respond within 2.5 seconds."
        : "PhishTank could not be reached.",
    );
  }
}

function phishTankConfigured(config: ReputationConfig): boolean {
  return config.phishTankEnabled === true || Boolean(config.phishTankAppKey);
}

async function lookupCloudflareFamilyDns(target: Target, config: ReputationConfig): Promise<ReputationProviderResult> {
  try {
    const endpoint = new URL("https://security.cloudflare-dns.com/dns-query");
    endpoint.searchParams.set("name", new URL(target.url).hostname);
    endpoint.searchParams.set("type", "A");
    const response = await (config.budget ? config.budget.fetch(endpoint, {
      method: "GET",
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      headers: { Accept: "application/dns-json" },
      resource: "provider",
    }) : fetch(endpoint, {
      method: "GET",
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      headers: { Accept: "application/dns-json" },
    }));
    if (response.status === 429) {
      return result("cloudflare_family_dns", target, config, "quota_limited", [], "Cloudflare's malware-filtering resolver rate-limited this lookup.");
    }
    if (!response.ok) {
      return result("cloudflare_family_dns", target, config, "unavailable", [], `Cloudflare's malware-filtering resolver returned HTTP ${response.status}.`);
    }
    const payload = await response.json() as { Status?: unknown; Answer?: Array<{ type?: unknown; data?: unknown }> };
    const addresses = Array.isArray(payload.Answer)
      ? payload.Answer.filter((item) => item.type === 1 && typeof item.data === "string").map((item) => item.data as string)
      : [];
    if (addresses.includes("0.0.0.0")) {
      return result(
        "cloudflare_family_dns",
        target,
        config,
        "matched",
        ["MALWARE_OR_PHISHING_DOMAIN"],
        "Cloudflare's malware-filtering DNS resolver blocks this hostname as associated with malware or phishing.",
      );
    }
    if (payload.Status === 0 && addresses.length > 0) {
      return result(
        "cloudflare_family_dns",
        target,
        config,
        "not_listed",
        [],
        "Cloudflare's malware-filtering DNS resolver did not block this hostname at this time; that is not proof of safety.",
      );
    }
    return result(
      "cloudflare_family_dns",
      target,
      config,
      "inconclusive",
      [],
      "Cloudflare's malware-filtering DNS resolver returned no IPv4 classification signal for this hostname.",
    );
  } catch (error) {
    return result(
      "cloudflare_family_dns",
      target,
      config,
      "unavailable",
      [],
      error instanceof DOMException && error.name === "TimeoutError"
        ? "Cloudflare's malware-filtering DNS resolver did not respond within 2.5 seconds."
        : "Cloudflare's malware-filtering DNS resolver could not be reached.",
    );
  }
}

function result(
  provider: ReputationProviderName,
  target: Target,
  config: ReputationConfig,
  status: ReputationProviderResult["status"],
  threatTypes: string[],
  detail: string,
): ReputationProviderResult {
  const now = (config.now || (() => new Date()))();
  return {
    provider,
    target: target.kind,
    hostname: new URL(target.url).hostname,
    status,
    threatTypes,
    detail,
    checkedAt: now.toISOString(),
    expiresAt: null,
    advisoryUrl: provider === "google_web_risk"
      ? "https://docs.cloud.google.com/web-risk/docs/advisory"
      : provider === "cloudflare_family_dns"
        ? "https://developers.cloudflare.com/1.1.1.1/setup/"
        : "https://phishtank.org/",
    attribution: provider === "google_web_risk"
      ? "Advisory provided by Google"
      : provider === "cloudflare_family_dns"
        ? "Domain filtering signal provided by Cloudflare"
        : "Reputation provided by PhishTank",
  };
}

function summarize(providers: ReputationProviderResult[]): ReputationAssessment {
  const active = providers.filter((item) => item.status !== "not_configured");
  if (providers.some((item) => item.status === "matched")) {
    return {
      status: "matched",
      detail: "At least one external provider identifies a checked URL as potentially unsafe.",
      consentRequired: true,
      providers,
    };
  }
  if (active.length === 0) {
    return { status: "not_configured", detail: "No external reputation provider is configured.", consentRequired: true, providers };
  }
  if (active.every((item) => item.status === "not_listed")) {
    return {
      status: "not_listed",
      detail: "No configured provider listed the checked URLs at this time; this is not proof of safety.",
      consentRequired: true,
      providers,
    };
  }
  if (active.every((item) => item.status === "unavailable" || item.status === "quota_limited")) {
    return { status: "unavailable", detail: "External reputation providers were unavailable or quota-limited.", consentRequired: true, providers };
  }
  return { status: "partial", detail: "External reputation coverage was partial; review each provider result.", consentRequired: true, providers };
}

function uniqueTargets(requestedUrl: string, finalUrl: string | null): Target[] {
  const targets: Target[] = [{ kind: "requested", url: requestedUrl }];
  // Compare the raw URLs: redaction collapses differing query values into the
  // same string, which would silently skip a final URL whose only change is
  // exactly the per-victim parameter phishing kits vary. Redaction is a
  // storage concern; providers receive full URLs by consent.
  if (finalUrl && finalUrl !== requestedUrl) {
    targets.push({ kind: "final", url: finalUrl });
  }
  return targets;
}

async function cacheKey(provider: ReputationProviderName, url: string): Promise<Request> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(url));
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request(`https://reputation-cache.invalid/${provider}/${hash}`);
}

function cacheSeconds(value: ReputationProviderResult): number {
  if (!value.expiresAt) return value.status === "matched" ? POSITIVE_CACHE_SECONDS : NEGATIVE_CACHE_SECONDS;
  const seconds = Math.floor((Date.parse(value.expiresAt) - Date.parse(value.checkedAt)) / 1000);
  if (!Number.isFinite(seconds)) return POSITIVE_CACHE_SECONDS;
  return Math.max(60, Math.min(MAX_CACHE_SECONDS, seconds));
}

function readableThreat(value: string): string {
  return value.toLowerCase().replaceAll("_", " ");
}

function truthy(value: unknown): boolean {
  return value === true || value === "true" || value === "yes" || value === "y" || value === 1 || value === "1";
}
