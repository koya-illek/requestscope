const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export class InputError extends Error {
  status = 400;
}

export class BlockedTargetError extends Error {
  status = 403;
}

export function normalizeUrl(input: unknown): URL {
  if (typeof input !== "string" || input.trim().length === 0 || input.length > 2048) {
    throw new InputError("Enter a URL of no more than 2,048 characters.");
  }

  let value = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = `https://${value}`;

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new InputError("Enter a valid public URL.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new InputError("Only HTTP and HTTPS URLs are supported.");
  }
  if (url.username || url.password) throw new InputError("URLs containing credentials are not supported.");
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new InputError("Only standard web ports 80 and 443 are supported.");
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isIpLiteral(hostname)) throw new BlockedTargetError("Direct IP address targets are not supported.");
  if (!isValidHostname(hostname)) throw new InputError("Enter a valid public hostname.");

  url.hostname = hostname;
  url.hash = "";
  return url;
}

export function redactUrlForStorage(input: string): string {
  try {
    const url = new URL(input);
    // Fragments are never sent to an origin, but they commonly contain bearer
    // tokens and access state. Remove them before any report field is stored.
    url.hash = "";
    if (url.search) {
      for (const key of [...url.searchParams.keys()]) {
        url.searchParams.set(key, "[redacted]");
      }
    }
    return url.toString();
  } catch {
    return "[invalid URL]";
  }
}

/** Sanitize a stored header or other text that may contain URL-shaped data. */
export function redactTextForStorage(input: string): string {
  return input
    .replace(/https?:\/\/[^\s"'<>]+/gi, (value) => {
      const trailing = value.match(/[),.;]+$/)?.[0] || "";
      const candidate = trailing ? value.slice(0, -trailing.length) : value;
      return `${redactUrlForStorage(candidate)}${trailing}`;
    })
    .replace(/([?&#](?:token|secret|signature|sig|api[_-]?key|access[_-]?token|auth|code|state|nonce|key)=)[^&#\s"'<>]*/gi, "$1[redacted]")
    .replace(/\b(token|secret|signature|api[_-]?key|access[_-]?token|auth|nonce)\s*[:=]\s*["']?[^,;\s"'`}]+/gi, "$1=[redacted]");
}

/** Sanitize URL-bearing response headers without retaining raw report targets. */
export function redactHeaderForStorage(name: string, value: string, baseUrl?: URL): string {
  const lower = name.toLowerCase();
  if (lower === "location") {
    try { return redactUrlForStorage(new URL(value, baseUrl).toString()); } catch { return "[invalid redirect URL]"; }
  }
  if (lower === "content-security-policy") {
    return redactTextForStorage(value).replace(/#[^\s;]+/g, "");
  }
  if (lower === "nel" || lower === "report-to") {
    try {
      const parsed = JSON.parse(value) as unknown;
      return redactTextForStorage(JSON.stringify(parsed));
    } catch {
      return redactTextForStorage(value);
    }
  }
  return redactTextForStorage(value);
}

export function isValidHostname(hostname: string): boolean {
  if (hostname.length > 253 || hostname.length < 4 || !hostname.includes(".")) return false;
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local")) return false;
  const labels = hostname.split(".");
  return labels.every((label) => HOST_LABEL.test(label));
}

export function isIpLiteral(host: string): boolean {
  const value = host.replace(/^\[|\]$/g, "");
  return isIPv4(value) || value.includes(":");
}

export function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

export function isPublicIp(address: string): boolean {
  const value = address.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (isIPv4(value)) return isPublicIPv4(value);
  if (value.includes(":")) return isPublicIPv6(value);
  return false;
}

function isPublicIPv4(value: string): boolean {
  const [a, b, c] = value.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function isPublicIPv6(value: string): boolean {
  if (!/^[0-9a-f:]+$/.test(value)) return false;
  const hextets = expandIpv6(value);
  if (!hextets) return false;
  const [first, second, third] = hextets;
  // Public DNS targets for this service must use IPv6 global unicast (2000::/3).
  if (first < 0x2000 || first > 0x3fff) return false;
  // Unique-local (fc00::/7), link-local (fe80::/10), and multicast (ff00::/8).
  if ((first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00) return false;
  if (first === 0x2001) {
    // Teredo tunneling (2001:0000::/32).
    if (second === 0x0000) return false;
    // Documentation (2001:db8::/32), benchmarking (2001:0002::/48),
    // ORCHID and ORCHIDv2 (2001:0010::/28, 2001:0020::/28).
    if (second === 0x0db8) return false;
    if (second === 0x0002 && third === 0x0000) return false;
    if ((second & 0xfff0) === 0x0010 || (second & 0xfff0) === 0x0020) return false;
  }
  return true;
}

/** Expand an IPv6 address into its eight 16-bit groups, or null when malformed. */
function expandIpv6(value: string): number[] | null {
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const parseGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const groups: number[] = [];
    for (const group of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      groups.push(Number.parseInt(group, 16));
    }
    return groups;
  };
  if (halves.length === 2) {
    const head = parseGroups(halves[0]);
    const tail = parseGroups(halves[1]);
    if (!head || !tail) return null;
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    return [...head, ...new Array<number>(fill).fill(0), ...tail];
  }
  const groups = parseGroups(value);
  return groups && groups.length === 8 ? groups : null;
}

export function safeRedirect(current: URL, location: string): URL {
  let next: URL;
  try {
    next = new URL(location, current);
  } catch {
    throw new InputError("The server returned an invalid redirect target.");
  }
  return normalizeUrl(next.toString());
}

export function allowedOrigin(request: Request, configured: string): string | null {
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  const allowlist = configured.split(",").map((item) => item.trim()).filter(Boolean);
  return allowlist.includes(origin) ? origin : null;
}
