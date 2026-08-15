import type { SslDetail } from "./types";

interface CfTlsInfo {
  tlsVersion?: string;
  tlsCipher?: string;
  certIssuer?: string;
  certSubject?: string;
  certFingerprint?: string;
  certSerialNumber?: string;
}

interface CrtShEntry {
  not_before?: string;
  not_after?: string;
}

/**
 * Extract SSL/TLS connection and certificate details for a hostname.
 *
 * Combines Cloudflare edge TLS metadata (from a fetch Response's `.cf` property)
 * with certificate transparency data from crt.sh for validity dates.
 */
export async function inspectSsl(
  hostname: string,
  fetchResponse: Response | null,
): Promise<SslDetail> {
  // --- 1. Extract TLS info from the Cloudflare fetch response ---
  let protocol: string | null = null;
  let cipher: string | null = null;
  let issuer: string | null = null;
  let subject: string | null = null;

  if (fetchResponse) {
    // The `cf` property on Worker fetch responses carries edge TLS metadata.
    const cf = (fetchResponse as Response & { cf?: CfTlsInfo }).cf;
    if (cf) {
      protocol = cf.tlsVersion ?? null;
      cipher = cf.tlsCipher ?? null;
      issuer = cf.certIssuer ?? null;
      subject = cf.certSubject ?? null;
    }

    // Some origins expose cert info via a response header.
    const certHeader = fetchResponse.headers.get("x-cert-info");
    if (certHeader) {
      const parsed = parseCertHeader(certHeader);
      issuer ??= parsed.issuer;
      subject ??= parsed.subject;
    }
  }

  // --- 2. Query crt.sh for certificate validity dates ---
  let validFrom: string | null = null;
  let validTo: string | null = null;
  let authorityKeyIdentifier: string | null = null;

  try {
    const crtResult = await queryCrtSh(hostname);
    if (crtResult) {
      validFrom = crtResult.not_before ?? null;
      validTo = crtResult.not_after ?? null;
    }
  } catch {
    // crt.sh is best-effort; failures are non-fatal.
  }

  // --- 3. Calculate days until expiry ---
  let daysUntilExpiry: number | null = null;
  if (fetchResponse && validTo) {
    const expiry = new Date(validTo);
    if (!Number.isNaN(expiry.getTime())) {
      daysUntilExpiry = Math.ceil(
        (expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24),
      );
    }
  }

  return {
    source: "certificate_transparency",
    protocol,
    cipher,
    issuer,
    subject,
    validFrom,
    validTo,
    daysUntilExpiry,
    authorityKeyIdentifier,
  };
}

/**
 * Query crt.sh certificate transparency log for the most recent cert entry.
 * Returns `null` if the query fails or yields no usable data.
 */
async function queryCrtSh(
  hostname: string,
): Promise<CrtShEntry | null> {
  const url = `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`;
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) return null;

  const entries = await response.json<CrtShEntry[]>();
  if (!Array.isArray(entries) || entries.length === 0) return null;

  // crt.sh returns newest-first in practice, but sort to be safe.
  const sorted = entries
    .filter((e) => e.not_before && e.not_after)
    .sort((a, b) => {
      const aTime = new Date(a.not_before!).getTime();
      const bTime = new Date(b.not_before!).getTime();
      return bTime - aTime;
    });

  return sorted[0] ?? entries[0] ?? null;
}

/**
 * Parse an `x-cert-info` header value for issuer/subject.
 * Format varies widely; we do a best-effort key=value extraction.
 */
function parseCertHeader(
  header: string,
): { issuer: string | null; subject: string | null } {
  const parts = header.split(/[;,]/);
  let issuer: string | null = null;
  let subject: string | null = null;

  for (const part of parts) {
    const [key, ...valueParts] = part.split("=");
    const value = valueParts.join("=").trim().replace(/^"|"$/g, "");
    const lowerKey = key.trim().toLowerCase();
    if (lowerKey === "issuer" && !issuer) issuer = value;
    else if (lowerKey === "subject" && !subject) subject = value;
  }

  return { issuer, subject };
}
