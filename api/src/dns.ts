import type { DnsAnswer, DnsQueryResult } from "./types";
import { getDomain } from "tldts";

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const GOOGLE_DOH_ENDPOINT = "https://dns.google/resolve";
const TYPE_NAMES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  257: "CAA",
};

interface DnsJson {
  Status?: number;
  AD?: boolean;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

export async function queryDns(
  name: string,
  type: string,
  provider: "cloudflare" | "google" = "cloudflare",
): Promise<DnsQueryResult> {
  const started = performance.now();
  const endpoint = provider === "google" ? GOOGLE_DOH_ENDPOINT : DOH_ENDPOINT;
  const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&do=true`;

  try {
    const response = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`Resolver returned HTTP ${response.status}`);
    const payload = await response.json<DnsJson>();
    const answers: DnsAnswer[] = (payload.Answer || []).map((answer) => ({
      name: answer.name.replace(/\.$/, ""),
      type: TYPE_NAMES[answer.type] || String(answer.type),
      ttl: answer.TTL,
      data: answer.data.replace(/\.$/, ""),
    }));
    return {
      resolver: provider === "google" ? "Google Public DNS" : "Cloudflare DNS",
      name,
      type,
      status: payload.Status ?? -1,
      authenticatedData: Boolean(payload.AD),
      answers,
      elapsedMs: Math.round(performance.now() - started),
      evidenceKind: "dns_observation",
    };
  } catch (error) {
    return {
      resolver: provider === "google" ? "Google Public DNS" : "Cloudflare DNS",
      name,
      type,
      status: -1,
      authenticatedData: false,
      answers: [],
      elapsedMs: Math.round(performance.now() - started),
      error: error instanceof Error ? error.message : "DNS query failed",
      evidenceKind: "dns_observation",
    };
  }
}

export async function inspectDns(hostname: string): Promise<DnsQueryResult[]> {
  const apex = registrableApproximation(hostname);
  const targets: Array<[string, string]> = [
    [hostname, "A"],
    [hostname, "AAAA"],
    [hostname, "CNAME"],
    [apex, "NS"],
    [apex, "CAA"],
  ];
  return Promise.all(targets.map(([name, type]) => queryDns(name, type)));
}

function registrableApproximation(hostname: string): string {
  return getDomain(hostname, { allowPrivateDomains: true }) || hostname;
}
