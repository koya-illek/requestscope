import { queryDns } from "./dns";
import { RequestBudget, BudgetExceededError, type BudgetFetchInit } from "./budget";
import {
  BlockedTargetError,
  isIpLiteral,
  isValidHostname,
  isPublicIp,
  normalizeUrl,
  safeRedirect,
} from "./security";
import type { DnsQueryResult } from "./types";

const MAX_DERIVED_REDIRECTS = 3;

export interface PublicResolution {
  hostname: string;
  addresses: string[];
  queries: DnsQueryResult[];
}

/** Resolve a hostname through both configured public resolvers and fail closed.
 * When a validatedHosts map is supplied, an already-validated hostname is not
 * re-resolved; the memo lives for one request only, so it never outlives the
 * request deadline or the DNS TTLs involved. */
export async function assertPublicTarget(
  hostname: string,
  budget?: RequestBudget,
  validatedHosts?: Map<string, PublicResolution>,
): Promise<PublicResolution> {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  if (!normalized || normalized.includes("/") || normalized.includes(":") || isIpLiteral(normalized) || !isValidHostname(normalized)) {
    throw new BlockedTargetError("The derived target is not a public hostname.");
  }
  const cached = validatedHosts?.get(normalized);
  if (cached) return cached;
  const [cloudflare, google] = await Promise.all([
    Promise.all([queryDns(normalized, "A", "cloudflare", budget), queryDns(normalized, "AAAA", "cloudflare", budget)]),
    Promise.all([queryDns(normalized, "A", "google", budget), queryDns(normalized, "AAAA", "google", budget)]),
  ]);
  const queries = [...cloudflare, ...google];
  assertResolutionHealthy(normalized, queries);
  const addresses = uniqueAddresses(queries);
  const blocked = addresses.filter((address) => !isPublicIp(address));
  if (blocked.length) throw new BlockedTargetError("The hostname resolves to a private or reserved network address.");
  const resolution: PublicResolution = { hostname: normalized, addresses, queries };
  validatedHosts?.set(normalized, resolution);
  return resolution;
}

/** Validate the original hostname and the final target of each manual redirect.
 * When a per-request `validatedHosts` memo is supplied, host resolutions are
 * shared across every derived fetch of the same trace instead of being
 * re-paid per hop. */
export async function fetchPublicUrl(
  input: string | URL,
  budget: RequestBudget,
  init: BudgetFetchInit = {},
  maxRedirects = MAX_DERIVED_REDIRECTS,
  validatedHosts?: Map<string, PublicResolution>,
): Promise<{ response: Response; url: URL; redirects: number }> {
  let current = normalizeUrl(input.toString());
  await assertPublicTarget(current.hostname, budget, validatedHosts);
  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    const response = await budget.fetch(current.toString(), { ...init, redirect: "manual" });
    const location = response.headers.get("location");
    if (!location || ![301, 302, 303, 307, 308].includes(response.status)) {
      return { response, url: current, redirects };
    }
    if (redirects === maxRedirects) {
      response.body?.cancel();
      throw new BlockedTargetError(`Derived redirect limit of ${maxRedirects} reached.`);
    }
    const next = safeRedirect(current, location);
    await assertPublicTarget(next.hostname, budget, validatedHosts);
    response.body?.cancel();
    current = next;
  }
  throw new BlockedTargetError("Derived redirect could not be validated.");
}

export function assertResolutionHealthy(hostname: string, queries: DnsQueryResult[]): void {
  const failures = queries.filter((query) => query.status < 0 || Boolean(query.error));
  if (failures.length) throw new BlockedTargetError(`Public DNS resolution for ${hostname} was inconclusive.`);
  const addresses = uniqueAddresses(queries);
  if (!addresses.length) throw new BlockedTargetError(`No public A or AAAA address could be confirmed for ${hostname}.`);
}

export function uniqueAddresses(queries: DnsQueryResult[]): string[] {
  return [...new Set(queries.flatMap((query) => query.answers
    .filter((answer) => answer.type === "A" || answer.type === "AAAA")
    .map((answer) => answer.data)))];
}

export { BudgetExceededError };
