import { describe, expect, it, vi } from "vitest";
import { handleMcp } from "../src/mcp";
import { RateLimitError, retryAfterSeconds } from "../src/security";
import type { UrlRiskAssessment } from "../src/types";

const assessment = {
  schemaVersion: 1, verdict: "low", riskScore: 0, confidence: "high", summary: "No strong indicators were found; this does not prove the URL is safe.",
  requestedUrl: "https://example.com/", finalUrl: "https://example.com/", traceId: "abcdefghijklmnop", reportPath: "/api/scans/abcdefghijklmnop",
  claimedOrganisation: null, services: [], findings: [], reputation: { status: "not_configured", detail: "Not configured", consentRequired: true, providers: [] }, limitations: ["Not proof of safety"],
} satisfies UrlRiskAssessment;

function request(method: string, params: unknown = {}, id: number | string | undefined = 1) {
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
    expect(response.headers.get("strict-transport-security")).toContain("max-age=31536000");
    expect(response.headers.get("permissions-policy")).toBe("camera=(), microphone=(), geolocation=()");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
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
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("strict-transport-security")).toContain("max-age=31536000");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("surfaces rate limits as an HTTP 429 JSON-RPC error instead of a tool result", async () => {
    const response = await handleMcp(request("tools/call", { name: "assess_url_risk", arguments: { url: "https://example.com" } }), async () => assessment, {
      beforeToolCall: async () => { throw new RateLimitError("Daily MCP request limit of 200 reached."); },
    });
    expect(response.status).toBe(429);
    // Back-off runs until the UTC-daily MCP window rolls over.
    expect(response.headers.get("retry-after")).toBe(String(retryAfterSeconds()));
    await expect(response.json()).resolves.toMatchObject({ error: { code: -32000, message: /Daily MCP request limit/ } });
  });

  it("masks unexpected tool failures instead of echoing internal messages", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const response = await handleMcp(request("tools/call", { name: "assess_url_risk", arguments: { url: "https://example.com" } }), async () => {
      throw new TypeError("Cannot read properties of undefined (reading 'query') D1_EXEC_ERROR");
    });
    const body = await response.json<{ result: { isError: boolean; content: Array<{ text: string }> } }>();
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).not.toContain("D1");
    expect(body.result.content[0].text).toContain("could not be completed");
    expect(consoleError).toHaveBeenCalled();
    consoleError.mockRestore();
  });

  it("answers malformed-but-parseable envelopes with -32600 and syntax failures with -32700", async () => {
    const shape = await handleMcp(new Request("https://api.example/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify([1, 2, 3]),
    }), async () => assessment);
    expect(shape.status).toBe(400);
    await expect(shape.json()).resolves.toMatchObject({ error: { code: -32600 } });

    const syntax = await handleMcp(new Request("https://api.example/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not json",
    }), async () => assessment);
    expect(syntax.status).toBe(400);
    await expect(syntax.json()).resolves.toMatchObject({ error: { code: -32700 } });
  });

  it("normalises unusable JSON-RPC ids to null instead of reflecting them", async () => {
    for (const id of [{ nested: true }, ["array"]]) {
      const response = await handleMcp(new Request("https://api.example/mcp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "resources/list", id }),
      }), async () => assessment);
      const body = await response.json<{ id: string | number | null }>();
      expect(body.id).toBeNull();
    }
    // A well-formed id keeps its value on both success and error paths.
    const known = await handleMcp(request("ping", {}, 7), async () => assessment);
    await expect(known.json()).resolves.toMatchObject({ id: 7 });
    const unknown = await handleMcp(request("resources/list", {}, "req-9"), async () => assessment);
    await expect(unknown.json()).resolves.toMatchObject({ id: "req-9", error: { code: -32601 } });
  });

  it("echoes allowed-origin CORS headers on JSON-RPC responses", async () => {
    const response = await handleMcp(request("initialize", {}), async () => assessment, {
      corsHeaders: { "Access-Control-Allow-Origin": "https://app.example" },
    });
    expect(response.headers.get("access-control-allow-origin")).toBe("https://app.example");
  });
});
