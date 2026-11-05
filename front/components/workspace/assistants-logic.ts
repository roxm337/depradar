import type { ApiToken, AssistantCall, TokenAudience } from "@/lib/api";

/** The MCP endpoint assistants connect to. It is served by the API, not the dashboard proxy. */
export function mcpEndpoint(origin: string) {
  return `${(origin || "https://depradar.example.com").replace(/\/+$/, "")}/api/mcp`;
}

/**
 * Client configuration that reads the token from an environment variable when the client starts,
 * so it is never inlined in a file or passed as a command-line argument.
 */
export function clientSnippets(url: string) {
  return {
    claudeCode: JSON.stringify({ mcpServers: { depradar: { type: "http", url, headers: { Authorization: "Bearer ${DEPRADAR_MCP_TOKEN}" } } } }, null, 2),
    json: JSON.stringify({ mcpServers: { depradar: { url, headers: { Authorization: "Bearer ${env:DEPRADAR_MCP_TOKEN}" } } } }, null, 2),
  };
}

/** Tokens for one interface. Tokens from servers older than the audience field are REST tokens. */
export function tokensFor(tokens: ApiToken[], audience: TokenAudience) {
  return tokens.filter((token) => (token.audience ?? "api") === audience);
}

export function callOutcome(call: AssistantCall): { label: string; tone: "dot-ok" | "dot-warn" | "dot-bad" } {
  if (call.outcome === "ok") return { label: "Done", tone: "dot-ok" };
  if (call.outcome === "denied") return { label: "Denied", tone: "dot-bad" };
  return { label: "Failed", tone: "dot-warn" };
}

/** Tool names read as words: get_portfolio_overview → Get portfolio overview. */
export function callLabel(name: string) {
  const words = name.replace(/_/g, " ").trim();
  return words ? words[0].toUpperCase() + words.slice(1) : name;
}
