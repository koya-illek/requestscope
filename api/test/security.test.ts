import { describe, expect, it } from "vitest";
import {
  BlockedTargetError,
  InputError,
  isPublicIp,
  normalizeUrl,
  redactHeaderForStorage,
  redactTextForStorage,
  redactUrlForStorage,
  safeRedirect,
} from "../src/security";

describe("normalizeUrl", () => {
  it("adds HTTPS and removes fragments", () => {
    expect(normalizeUrl("Example.COM/path#section").toString()).toBe("https://example.com/path");
  });

  it.each([
    "file:///etc/passwd",
    "ftp://example.com/file",
    "https://user:pass@example.com",
    "https://example.com:8443",
  ])("rejects unsupported input %s", (value) => {
    expect(() => normalizeUrl(value)).toThrow(InputError);
  });

  it.each([
    "http://127.0.0.1",
    "http://10.0.0.1",
    "http://[::1]",
  ])("rejects IP-literal input %s", (value) => {
    expect(() => normalizeUrl(value)).toThrow(BlockedTargetError);
  });
});

describe("report URL redaction", () => {
  it("redacts every query value while preserving parameter names", () => {
    const redacted = new URL(redactUrlForStorage("https://example.com/reset?token=secret&next=%2Fhome"));
    expect(redacted.searchParams.get("token")).toBe("[redacted]");
    expect(redacted.searchParams.get("next")).toBe("[redacted]");
    expect(redacted.pathname).toBe("/reset");
  });

  it("does not change URLs without query parameters", () => {
    expect(redactUrlForStorage("https://example.com/path")).toBe("https://example.com/path");
  });

  it("removes fragments and URL-bearing header secrets", () => {
    const location = redactHeaderForStorage("location", "https://example.com/continue?token=secret#access_token=fragment", new URL("https://example.com"));
    const csp = redactHeaderForStorage("content-security-policy", "default-src 'self'; report-uri https://collector.example/report?sig=header-secret#fragment");
    const nel = redactHeaderForStorage("nel", '{"report_to":"x","endpoint":"https://collector.example/report?secret=nel-secret"}');
    expect(location).not.toContain("secret");
    expect(location).not.toContain("#");
    expect(csp).not.toContain("header-secret");
    expect(csp).not.toContain("#fragment");
    expect(nel).not.toContain("nel-secret");
  });

  it("redacts token-shaped values in derived text", () => {
    expect(redactTextForStorage('fetch("https://cdn.example/app.js?sig=secret"); const token = "js-secret";')).not.toMatch(/secret/);
  });
});

describe("public address classification", () => {
  it.each([
    "1.1.1.1",
    "8.8.8.8",
    "2606:4700:4700::1111",
  ])("accepts public address %s", (address) => {
    expect(isPublicIp(address)).toBe(true);
  });

  it.each([
    "0.0.0.0",
    "10.1.2.3",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.16.2.3",
    "192.168.1.1",
    "192.0.2.1",
    "198.51.100.2",
    "203.0.113.3",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
    "::ffff:127.0.0.1",
    "64:ff9b::127.0.0.1",
  ])("rejects non-public address %s", (address) => {
    expect(isPublicIp(address)).toBe(false);
  });
});

describe("safeRedirect", () => {
  it("resolves relative paths", () => {
    expect(safeRedirect(new URL("https://example.com/a"), "/next").toString()).toBe("https://example.com/next");
  });

  it("reapplies port and protocol restrictions", () => {
    expect(() => safeRedirect(new URL("https://example.com"), "http://example.net:8080")).toThrow(InputError);
  });
});
