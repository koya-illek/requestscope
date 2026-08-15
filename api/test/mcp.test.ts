import { describe, expect, it, vi } from "vitest";
import { handleMcp } from "../src/mcp";
import type { UrlRiskAssessment } from "../src/types";

const assessment = {
  schemaVersion: 1, verdict: "low", riskScore: 0, confidence: "high", summary: "No strong indicators were found; this does not prove the URL is safe.",
  requestedUrl: "https://example.com/", finalUrl: "https://example.com/", traceId: "abcdefghijklmnop", reportPath: "/api/scans/abcdefghijklmnop",
  claimedOrganisation: null, services: [], findings: [], reputation: { status: "not_configured", detail: "Not configured", consentRequired: true, providers: [] }, limitations: ["Not proof of safety"],
} satisfies UrlRiskAssessment;

function request(method: string, params: unknown = {}, id: number | undefined = 1) {
  return new Request("https://api.example/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
}

describe("MCP Streamable HTTP endpoint", () => {
  it("negotiates the current protocol without requiring server state", async () => {
    const response = await handleMcp(request("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "test", version: "1" } }), async () => assessment);
    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-protocol-version")).toBe("2025-11-25");
    await expect(response.json()).resolves.toMatchObject({ result: { protocolVersion: "2025-11-25", serverInfo: { name: "requestscope" } } });
  });

  it("publishes full trace, URL risk, and report retrieval tools with schemas", async () => {
    const response = await handleMcp(request("tools/list"), async () => assessment);
    const body = await response.json<{ result: { tools: Array<{ name: string; description: string; inputSchema: object; outputSchema: object }> } }>();
    expect(body.result.tools.map(tool => tool.name)).toEqual(["trace_request", "assess_url_risk", "get_requestscope_report"]);
    const risk = body.result.tools.find(tool => tool.name === "assess_url_risk") as { inputSchema: { properties: Record<string, unknown> } };
    expect(risk.inputSchema.properties.externalReputation).toBeDefined();
    const trace = body.result.tools.find(tool => tool.name === "trace_request") as { inputSchema: { properties: Record<string, unknown> } };
    expect(trace.inputSchema.properties).toMatchObject({
      mapDependencies: expect.any(Object),
      claimedOrganisation: expect.any(Object),
      messageContext: expect.any(Object),
      externalReputation: expect.any(Object),
    });
    const riskOutput = body.result.tools.find(tool => tool.name === "assess_url_risk") as {
      outputSchema: { properties: { reputation: { properties: { providers: { items: { properties: { provider: { enum: string[] } } } } } } } };
    };
    expect(riskOutput.outputSchema.properties.reputation.properties.providers.items.properties.provider.enum)
      .toEqual(["google_web_risk", "phishtank", "cloudflare_family_dns"]);
    expect(Object.keys((trace as unknown as { outputSchema: { properties: Record<string, unknown> } }).outputSchema.properties))
      .toEqual(expect.arrayContaining(["normalizedUrl", "createdAt", "expiresAt", "totalDurationMs", "observation", "dependencyMap", "urlRisk"]));
    expect(body.result.tools.every(tool => tool.inputSchema && tool.outputSchema)).toBe(true);
    expect(body.result.tools[1].description).toContain("Never describe a low result");
  });

  it("calls the shared assessment engine and returns structured content", async () => {
    const execute = vi.fn(async () => assessment);
    const response = await handleMcp(request("tools/call", { name: "assess_url_risk", arguments: { url: "https://example.com", claimedOrganisation: "Example" } }), execute);
    const body = await response.json<{ result: { structuredContent: UrlRiskAssessment } }>();
    expect(execute).toHaveBeenCalledWith("assess_url_risk", { url: "https://example.com", claimedOrganisation: "Example" });
    expect(body.result.structuredContent.verdict).toBe("low");
  });

  it("acknowledges notifications without a JSON-RPC body", async () => {
    const response = await handleMcp(request("notifications/initialized", {}, undefined), async () => assessment);
    expect(response.status).toBe(202);
    expect(await response.text()).toBe("");
  });

  it("rejects non-boolean external reputation consent", async () => {
    const response = await handleMcp(request("tools/call", {
      name: "assess_url_risk",
      arguments: { url: "https://example.com", externalReputation: "yes" },
    }), async () => assessment);
    await expect(response.json()).resolves.toMatchObject({ error: { code: -32602, message: "externalReputation must be a boolean" } });
  });

  it("enforces bounded risk context for full traces", async () => {
    const response = await handleMcp(request("tools/call", {
      name: "trace_request",
      arguments: { url: "https://example.com", messageContext: "x".repeat(1001) },
    }), async () => assessment);
    await expect(response.json()).resolves.toMatchObject({ error: { code: -32602, message: "messageContext is too long" } });
  });

  it("rejects arguments that are not published for the selected tool", async () => {
    const response = await handleMcp(request("tools/call", {
      name: "assess_url_risk",
      arguments: { url: "https://example.com", mapDependencies: true },
    }), async () => assessment);
    await expect(response.json()).resolves.toMatchObject({ error: { code: -32602, message: "Unsupported argument: mapDependencies" } });
  });

  it("returns 405 for an optional standalone GET stream", async () => {
    const response = await handleMcp(new Request("https://api.example/mcp"), async () => assessment);
    expect(response.status).toBe(405);
  });
});
