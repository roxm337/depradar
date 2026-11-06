import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { ApiToken, AssistantCall } from "../../lib/api.ts";
import { callLabel, callOutcome, clientSnippets, mcpEndpoint, tokensFor } from "./assistants-logic.ts";
import { accessLabel } from "./format.ts";

const token = (id: string, extra: Partial<ApiToken> = {}) => ({ id, name: id, display_prefix: "depradar_x", scopes: ["projects:read"], project_id: null, created_at: "", expires_at: "", last_used_at: null, revoked_at: null, audience: "api", ...extra }) as ApiToken;

describe("assistant access", () => {
  test("the endpoint is the API's /api/mcp on the dashboard origin", () => {
    assert.equal(mcpEndpoint("https://radar.agency.example/"), "https://radar.agency.example/api/mcp");
    assert.equal(mcpEndpoint(""), "https://depradar.example.com/api/mcp");
  });

  test("snippets never inline a secret", () => {
    const { claudeCode, json } = clientSnippets("https://radar.example/api/mcp");
    assert.equal(JSON.parse(claudeCode).mcpServers.depradar.headers.Authorization, "Bearer ${DEPRADAR_MCP_TOKEN}");
    assert.equal(JSON.parse(json).mcpServers.depradar.headers.Authorization, "Bearer ${env:DEPRADAR_MCP_TOKEN}");
    assert.doesNotMatch(claudeCode + json, /depradar_[A-Za-z0-9]{10}/);
  });

  test("tokens split by audience, and older tokens count as REST tokens", () => {
    const rows = [token("a"), token("b", { audience: "mcp" }), { ...token("c"), audience: undefined } as unknown as ApiToken];
    assert.deepEqual(tokensFor(rows, "api").map((row) => row.id), ["a", "c"]);
    assert.deepEqual(tokensFor(rows, "mcp").map((row) => row.id), ["b"]);
  });

  test("assistant presets have labels", () => {
    assert.equal(accessLabel(["projects:read", "findings:read", "scans:read", "components:read"]), "Read");
    assert.equal(accessLabel(["inventories:check", "projects:read", "findings:read", "scans:read", "components:read"]), "Read + lockfile checks");
  });

  test("allowed changes are counted on top of the preset", () => {
    assert.equal(accessLabel(["projects:read", "findings:read", "scans:read", "components:read", "scans:write"]), "Read + 1 change");
    assert.equal(accessLabel(["inventories:check", "projects:read", "findings:read", "scans:read", "components:read", "monitoring:tighten", "projects:write"]), "Read + lockfile checks + 2 changes");
    assert.equal(accessLabel(["projects:read", "scans:write"]), "2 custom scopes");
  });

  test("calls read as words with a clear outcome", () => {
    assert.equal(callLabel("get_portfolio_overview"), "Get portfolio overview");
    const call = { outcome: "denied" } as AssistantCall;
    assert.deepEqual(callOutcome(call), { label: "Denied", tone: "dot-bad" });
  });
});
