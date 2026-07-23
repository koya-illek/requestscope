import type { Finding, ScanReport } from "./types";

function finding(
  code: string,
  severity: Finding["severity"],
  title: string,
  detail: string,
  evidencePath: string,
  confidence: Finding["confidence"] = "high",
): Finding {
  return { code, severity, title, detail, evidencePath, confidence, evidenceKind: "derived_finding" };
}

export function buildFindings(report: Omit<ScanReport, "findings" | "summary">): Finding[] {
  const findings: Finding[] = [];
  const hops = report.http.hops;
  const final = hops.at(-1);
  const finalHeaders = final?.responseHeaders || {};
  const redirectCount = hops.filter((hop) =>
    [301, 302, 303, 307, 308].includes(hop.status) && Boolean(hop.location),
  ).length;

  if (redirectCount > 2) {
    findings.push(finding(
      "redirect-chain-long",
      "warning",
      "Long redirect chain",
      `${redirectCount} redirects were followed before the final response. Each hop adds another network round trip.`,
      "http.hops",
    ));
  } else if (redirectCount > 0) {
    findings.push(finding(
      "redirect-chain",
      "info",
      "Redirects observed",
      `${redirectCount} redirect${redirectCount === 1 ? " was" : "s were"} followed before the final response.`,
      "http.hops",
    ));
  }

  if (report.finalUrl?.startsWith("https://")) {
    findings.push(finding(
      "https-final",
      "positive",
      "Final response uses HTTPS",
      "The observed redirect path ended on an HTTPS URL.",
      "finalUrl",
    ));
  } else if (report.finalUrl?.startsWith("http://")) {
    findings.push(finding(
      "http-final",
      "critical",
      "Final response does not use HTTPS",
      "The observed request path ended on an unencrypted HTTP URL.",
      "finalUrl",
    ));
  }

  if (report.requestedUrl.startsWith("http://") && report.finalUrl?.startsWith("https://")) {
    findings.push(finding(
      "http-upgrade",
      "positive",
      "HTTP upgrades to HTTPS",
      "The HTTP entry point redirected to an HTTPS destination.",
      "http.hops",
    ));
  }

  if (final && final.status >= 400) {
    findings.push(finding(
      "http-error",
      final.status >= 500 ? "critical" : "warning",
      `Final response returned HTTP ${final.status}`,
      "The request path did not finish with a successful page response.",
      `http.hops.${hops.length - 1}.status`,
    ));
  }

  const cacheControl = finalHeaders["cache-control"];
  if (final && final.status > 0 && !cacheControl) {
    findings.push(finding(
      "cache-control-missing",
      "info",
      "No Cache-Control header observed",
      "Shared and browser cache behaviour is not explicitly described by Cache-Control on the final response.",
      `http.hops.${Math.max(0, hops.length - 1)}.responseHeaders.cache-control`,
    ));
  } else if (/\b(no-store|private)\b/i.test(cacheControl)) {
    findings.push(finding(
      "cache-restricted",
      "info",
      "Shared caching is restricted",
      `The final response declares “${cacheControl}”. This may be intentional for personalized content.`,
      `http.hops.${hops.length - 1}.responseHeaders.cache-control`,
    ));
  } else if (/\b(max-age|s-maxage)\b/i.test(cacheControl)) {
    findings.push(finding(
      "cache-explicit",
      "positive",
      "Explicit cache policy observed",
      `The final response declares “${cacheControl}”.`,
      `http.hops.${hops.length - 1}.responseHeaders.cache-control`,
    ));
  }

  const requiredSecurityHeaders: Array<[string, string]> = [
    ["strict-transport-security", "Strict-Transport-Security"],
    ["content-security-policy", "Content-Security-Policy"],
    ["x-content-type-options", "X-Content-Type-Options"],
    ["referrer-policy", "Referrer-Policy"],
  ];
  const missing = requiredSecurityHeaders.filter(([key]) => !finalHeaders[key]).map(([, label]) => label);
  if (final && final.status > 0 && missing.length > 0) {
    findings.push(finding(
      "security-headers-missing",
      "warning",
      "Recommended response headers not observed",
      `The final response did not include: ${missing.join(", ")}. Applicability depends on the application.`,
      `http.hops.${Math.max(0, hops.length - 1)}.responseHeaders`,
      "medium",
    ));
  } else if (final && final.status > 0) {
    findings.push(finding(
      "security-headers-present",
      "positive",
      "Core response headers observed",
      "The final response included HSTS, CSP, X-Content-Type-Options, and Referrer-Policy.",
      `http.hops.${hops.length - 1}.responseHeaders`,
    ));
  }

  if (report.dependencies.thirdParty > 10) {
    findings.push(finding(
      "third-party-heavy",
      "warning",
      "Many third-party resource references",
      `${report.dependencies.thirdParty} third-party resource references were found in the inspected HTML.`,
      "dependencies.items",
      "medium",
    ));
  } else if (report.dependencies.thirdParty > 0) {
    findings.push(finding(
      "third-party-present",
      "info",
      "Third-party resource references observed",
      `${report.dependencies.thirdParty} third-party resource reference${report.dependencies.thirdParty === 1 ? " was" : "s were"} found.`,
      "dependencies.items",
      "medium",
    ));
  }

  if (report.http.truncated) {
    findings.push(finding(
      "body-truncated",
      "info",
      "Response inspection was bounded",
      "Only the first 256 KiB of the response body was inspected.",
      "http.truncated",
    ));
  }

  return findings;
}
