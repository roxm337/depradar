# AI assistants (MCP)

DepRadar serves the [Model Context Protocol](https://modelcontextprotocol.io/specification/latest)
at `/api/mcp`. AI assistants that support remote MCP servers, such as Claude Code, Cursor, and
VS Code, can use it to answer questions like these:

- "What is most urgent across our clients?"
- "Why did the gate fail on this pull request?"
- "Does this lockfile have known vulnerabilities?"

Assistants can read findings, scans, gate decisions, and package search, and run check scans on
lockfiles. Nothing an assistant does changes findings, alerts, monitored manifests, policies, or
settings.

## Before you enable it

- **The model provider sees what the assistant reads.** Tool results are sent to the assistant's
  model provider, for example Anthropic or OpenAI. That includes package names, versions,
  manifest paths, branch names, and finding details of every project the token can see. Check
  that this is acceptable under your agreements with each client.
- **Use project-restricted tokens for client work.** A token restricted to one project cannot see
  any other project through any tool, so a conversation about one client cannot leak another
  client's data.
- **Lockfiles you check pass through the conversation.** `check_manifest` takes the lockfile text
  as a tool argument, so it becomes part of the model's context. Scan large lockfiles, or ones
  you would not paste into a chat, with the [CI client](CI_CD.md) instead.

## Enable the endpoint

The endpoint is off by default and answers `404` until you turn it on.

- **Server installed with `depradarctl`:** add `DEPRADAR_MCP_ENABLED=true` to
  `/etc/depradar/depradar.env`, then run `sudo depradarctl restart`. `depradarctl configure`
  keeps this setting.
- **Docker Compose:** set `DEPRADAR_MCP_ENABLED=true` in `.env`, then run
  `docker compose up -d api`.

The endpoint lives under `/api/`, so the bundled Caddy proxy and any reverse proxy that already
routes `/api/*` to the API reach it without changes. Settings → **AI assistants** shows whether
it is on.

| Setting | Default | Purpose |
| --- | --- | --- |
| `DEPRADAR_MCP_ENABLED` | `false` | Serve `/api/mcp`. |
| `DEPRADAR_MCP_RATE_LIMIT_PER_MINUTE` | `120` | Requests per token in any 60-second window; beyond it, `429` with `Retry-After`. |
| `DEPRADAR_MCP_ALLOWED_ORIGINS` | `[]` | Browser origins allowed besides the dashboard, as a JSON list. Assistants that run in a terminal or on a server send no `Origin` and need nothing here. |

## Create an assistant token

In Settings → **AI assistants**, choose **New token**:

- **Read only:** `projects:read`, `findings:read`, `scans:read`, `components:read`.
- **Read + lockfile checks:** the same, plus `inventories:check`.

Give each person and assistant their own token, and restrict it to one project for client work.

Assistant tokens work on `/api/mcp` only, and REST tokens never work there. Each kind is refused
with `401` on the other interface, so a token copied out of an assistant's configuration cannot
be used against the REST API. Assistant tokens cannot hold `projects:write` or
`inventories:write`.

Through the API, create one with `POST /api/tokens` and `"audience": "mcp"`.

## Connect a client

Set the token as the `DEPRADAR_MCP_TOKEN` environment variable where the assistant runs, and
replace `https://depradar.example.com` with your installation's address. These configurations
read the token from the environment when the client starts, so it never sits in a file you might
share or appears on a command line.

**Claude Code** (`.mcp.json` in your project, or the same entry in your user configuration)

```json
{
  "mcpServers": {
    "depradar": {
      "type": "http",
      "url": "https://depradar.example.com/api/mcp",
      "headers": { "Authorization": "Bearer ${DEPRADAR_MCP_TOKEN}" }
    }
  }
}
```

**Cursor** (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "depradar": {
      "url": "https://depradar.example.com/api/mcp",
      "headers": { "Authorization": "Bearer ${env:DEPRADAR_MCP_TOKEN}" }
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`). VS Code asks for the token once and stores it securely:

```json
{
  "inputs": [
    { "type": "promptString", "id": "depradar-token", "description": "DepRadar AI assistant token", "password": true }
  ],
  "servers": {
    "depradar": {
      "type": "http",
      "url": "https://depradar.example.com/api/mcp",
      "headers": { "Authorization": "Bearer ${input:depradar-token}" }
    }
  }
}
```

**Other clients:** any client that connects to a remote Streamable HTTP server with a custom
`Authorization` header works. To try the tools by hand, use the
[MCP Inspector](https://github.com/modelcontextprotocol/inspector) with transport
"Streamable HTTP" and the same header.

**Development stack:** connect to the API port directly, for example
`http://localhost:8000/api/mcp`. The dashboard's `/api/backend` proxy does not forward MCP
headers.

**ChatGPT and claude.ai** connect from their own servers and sign in with OAuth, which DepRadar
does not offer yet. Support for them is planned as a separate change.

## Tools

| Tool | Scopes | What it returns |
| --- | --- | --- |
| `get_portfolio_overview` | `projects:read`, `findings:read` | Open risk per project, most at risk first, and the findings to fix first: known exploited, then by severity and EPSS. Accepted risk is excluded. |
| `list_projects` | `projects:read` | Projects, with an exact-name filter. |
| `get_project_overview` | `projects:read`, `findings:read` | One project's open findings by severity and the health of each monitored manifest. |
| `list_findings` | `findings:read` | A project's findings, filtered by status, minimum severity, or KEV. |
| `get_finding` | `findings:read` | One finding with advisories, fixed versions, and the owner's triage history. |
| `list_scans`, `get_scan` | `scans:read` | Scan status and coverage. |
| `search_packages` | `components:read` | Which projects use a package, and at which version, in current monitored manifests. |
| `preview_gate` | `scans:read` | Whether finished scans would pass a gate, without recording a decision. Central policies apply. |
| `list_gate_decisions`, `get_gate_decision` | `scans:read` | Recorded CI gate decisions and the evidence behind them. |
| `check_manifest` | `inventories:check` | Queues a check scan of a lockfile and returns its scan ID. |

- **Hidden tools:** `tools/list` shows only the tools the token's scopes allow. A hidden tool that
  is called anyway returns an error naming the missing scope.
- **Read-only annotations:** every tool except `check_manifest` is marked read-only.
- **Check scans run in the background:**
  1. `check_manifest` returns a scan ID right away.
  2. The assistant calls `get_scan` until `finished` is true.
  3. It then calls `preview_gate` with that scan ID.
- **Check-scan rules:** check scans follow the same rules as pull request pipelines. They never
  change findings, alerts, or monitored manifests. Unchanged content reuses the stored snapshot.
  The upload limit is the same 10 MiB.
- **Failed scans:** failed or superseded scans never pass `preview_gate`.

## Prompts

Clients that support MCP prompts list these as starting points:

| Prompt | Argument | Purpose |
| --- | --- | --- |
| `triage_project` | `project_id` | Rank a project's open findings into an order of work. |
| `explain_finding` | `finding_id` | Explain one vulnerability and its smallest fix. |
| `investigate_gate_failure` | `decision_id` | Explain why a gate decision failed and what would make it pass. |
| `client_risk_report` | `project_id`, optional `audience` (`client` or `internal`) | Draft a short status report. |

Prompts take DepRadar IDs only, and they are listed only to tokens with the scopes they need.

## Security model

- **Authentication on every request:** each request carries the token; there are no server-side
  sessions. The owner's dashboard session does not open `/api/mcp`.
- **Same permission checks as the REST API:** scopes and project restrictions apply exactly as
  they do there, because tools call the same application code. A project-restricted token gets
  "not found" for every other project.
- **Untrusted text is labelled:** values DepRadar did not write itself sit under an `untrusted`
  key in every result. That covers package names, versions, manifest paths, revisions, advisory
  summaries, and scan errors. These values come from uploaded manifests (a pull request author
  controls those) or from public advisory feeds. They are stripped of control and
  bidirectional-override characters and capped in length. The server instructions and every
  prompt tell the assistant to treat them as data, never as instructions.
- **Audit:** every tool call is recorded with the token, the assistant's self-reported client
  name, the tool, the project, the outcome, and the duration. Arguments and results are never
  recorded; even a hash of a short value such as a package name could be guessed. Settings → **AI
  assistants** shows recent activity, and Settings → **Data retention** sets how long it is kept
  (90 days by default). Activity is included in backups; tokens are not.
- **Rate limit and Origin check:** each token is rate-limited. Requests with an `Origin` other
  than the dashboard or `DEPRADAR_MCP_ALLOWED_ORIGINS` are refused, which blocks DNS rebinding
  from a browser.
- **What assistants cannot do:** manage tokens, identities, connectors, policies, retention, or
  backups; create, delete, or reconfigure projects; triage findings; or read raw manifest
  content. Triage tools may follow in a later change.

## Protocol

The endpoint is built on the official MCP Python SDK. It serves the 2026-07-28 revision and
earlier revisions such as 2025-11-25.

- **Transport:** Streamable HTTP, stateless, with JSON responses.
- **Methods:** only `POST` is accepted; `GET` and `DELETE` return `405`.
- **Errors:**

  | Status | When |
  | --- | --- |
  | `401` | A missing or invalid token, with `WWW-Authenticate: Bearer` |
  | `403` | A disallowed `Origin` |
  | `404` | The endpoint is turned off |
  | `429` | The token is over its rate limit |

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `404` | `DEPRADAR_MCP_ENABLED` is not `true` for the API, or the API was not restarted. |
| `401 This token is for the REST API only` | Create a token under Settings → **AI assistants**, not **CI/CD access**. |
| `403 Origin is not allowed` | A browser-based client sent its own origin. Add it to `DEPRADAR_MCP_ALLOWED_ORIGINS`. |
| A tool is missing from the client | The token lacks the scope for it. |
| `preview_gate` says a scan is still running | The worker has not finished the check scan yet. Call `get_scan` again. |
