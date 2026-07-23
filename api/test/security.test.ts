import { describe, expect, it } from "vitest";
import {
  BlockedTargetError,
  InputError,
  isPublicIp,
  normalizeUrl,
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
