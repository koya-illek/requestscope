/** Fixed request identities for the edge observer. Callers choose a profile,
 * never a literal header value, so no client-supplied string can reach an
 * outbound request and every report's provenance is one of these constants. */
export type DeviceProfile = "desktop" | "mobile";

export const USER_AGENTS: Record<DeviceProfile, string> = {
  desktop: "RequestScope/1.0 (+https://requestscope.illek.ie)",
  mobile: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
};
