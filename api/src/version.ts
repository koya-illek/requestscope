/** Single source for the deployed version identifiers. `api/package.json`
 * carries the same API version; scripts/static.test.mjs asserts the two stay
 * in lockstep so a bump cannot drift. */
export const API_VERSION = "1.8.0";
export const MCP_SERVER_VERSION = "2.3.0";
