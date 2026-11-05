"use client";

import { useCallback, useEffect, useState } from "react";
import { Icon } from "@/components/icon";
import { callLabel, callOutcome, clientSnippets, mcpEndpoint, tokensFor } from "@/components/workspace/assistants-logic";
import { useWorkspace } from "@/components/workspace/context";
import { accessLabel, formatGroups, projectName, relativeTime, shortDate, tokenState } from "@/components/workspace/format";
import { IdentitiesSection } from "@/components/workspace/identities";
import { CopyButton, Empty, PageHead, Sheet } from "@/components/workspace/ui";
import { api, type ApiToken, type AssistantActivity, type RetentionPolicy } from "@/lib/api";

const sections = [
  { id: "ci", label: "CI/CD access", icon: "branch" },
  { id: "identities", label: "Trusted identities", icon: "lock" },
  { id: "assistants", label: "AI assistants", icon: "terminal" },
  { id: "health", label: "Service health", icon: "activity" },
  { id: "retention", label: "Data retention", icon: "clock" },
  { id: "backups", label: "Backups", icon: "server" },
  { id: "coverage", label: "Coverage", icon: "file" },
] as const;
type Section = (typeof sections)[number]["id"];

export default function SettingsPage() {
  const [section, setSection] = useState<Section>("ci");
  useEffect(() => {
    const read = () => {
      const hash = window.location.hash.slice(1);
      if (sections.some((item) => item.id === hash)) setSection(hash as Section);
    };
    const timer = window.setTimeout(read, 0);
    // Links to another section of this page change only the hash.
    window.addEventListener("hashchange", read);
    return () => { window.clearTimeout(timer); window.removeEventListener("hashchange", read); };
  }, []);
  function choose(id: Section) {
    setSection(id);
    window.history.replaceState(null, "", `#${id}`);
  }
  return (
    <>
      <PageHead title="Settings" lede="Pipeline and AI assistant access, the health of the scanning services, and how long DepRadar keeps history."/>
      <div className="settings">
        <nav className="subnav" aria-label="Settings sections">{sections.map((item) => <button key={item.id} aria-current={section === item.id} onClick={() => choose(item.id)}><Icon name={item.icon} size={16}/>{item.label}</button>)}</nav>
        <div className="settings-panel" key={section}>
          {section === "ci" && <CiSection onIdentities={() => choose("identities")}/>}
          {section === "identities" && <IdentitiesSection/>}
          {section === "assistants" && <AssistantsSection/>}
          {section === "health" && <HealthSection/>}
          {section === "retention" && <RetentionSection/>}
          {section === "backups" && <BackupSection/>}
          {section === "coverage" && <CoverageSection/>}
        </div>
      </div>
    </>
  );
}

function TokenSheet({ tokens, onCreate, emptyText, revokeWarning }: { tokens: ApiToken[]; onCreate: () => void; emptyText: string; revokeWarning: string }) {
  const { projects, now, actions } = useWorkspace();
  return (
    <Sheet title="Tokens" meta={`${tokens.filter((token) => tokenState(token, now) === "Active").length} active`} actions={<button className="btn btn-primary btn-sm" onClick={onCreate}><Icon name="plus" size={14}/>New token</button>}>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Name</th><th className="col-optional">Access</th><th className="col-optional">Project</th><th className="col-optional">Last used</th><th className="col-optional">Expires</th><th>Status</th><th aria-label="Actions"/></tr></thead>
          <tbody>{tokens.map((token) => {
            const state = tokenState(token, now);
            return (
              <tr key={token.id}>
                <td><div className="cell-main"><b>{token.name}</b><small className="mono">{token.display_prefix}…</small></div></td>
                <td className="col-optional"><span className="tag" title={token.scopes.join(", ")}>{accessLabel(token.scopes)}</span></td>
                <td className="col-optional">{projectName(projects, token.project_id)}</td>
                <td className="col-optional muted">{token.last_used_at ? relativeTime(now, token.last_used_at) : "Never"}</td>
                <td className="col-optional muted">{shortDate(token.expires_at)}</td>
                <td><span className="status"><i className={`dot ${state === "Active" ? "dot-ok" : ""}`}/>{state}</span></td>
                <td className="right">{state === "Active" && <button className="btn btn-ghost btn-sm" onClick={() => { if (window.confirm(`Revoke “${token.name}”? ${revokeWarning}`)) void actions.revokeToken(token); }}>Revoke</button>}</td>
              </tr>
            );
          })}</tbody>
        </table>
        {!tokens.length && <Empty title="No tokens yet" text={emptyText} action={<button className="btn btn-primary" onClick={onCreate}><Icon name="key" size={15}/>Create the first token</button>}/>}
      </div>
    </Sheet>
  );
}

function CiSection({ onIdentities }: { onIdentities: () => void }) {
  const workspace = useWorkspace();
  const { tokens, origin } = workspace;
  const url = `${origin || "https://depradar.example.com"}/api/backend`;
  const github = `- uses: <org>/depradar/integrations/github-action@<commit-sha>\n  with:\n    url: ${url}\n    token: \${{ secrets.DEPRADAR_TOKEN }}\n    fail-on: high`;
  const shell = `curl -fsSL ${url}/ci/client.py -o depradar_ci.py\nDEPRADAR_URL=${url} python3 depradar_ci.py scan --fail-on high`;
  return (
    <>
      <div className="section-intro"><h2>CI/CD access</h2><p>Each client pipeline gets its own scoped token. Pull and merge requests run check scans that gate the change; default-branch runs keep monitored manifests current. Give pull request jobs a check-only token so they can never change monitored state.</p></div>
      <div className="callout"><Icon name="lock" size={16}/><span>On GitHub Actions or GitLab CI, skip long-lived secrets: a <button className="link" onClick={onIdentities}>trusted identity</button> lets each job sign in with its own short-lived OIDC token, and only your trusted branch and workflow can update monitored state.</span></div>
      <TokenSheet tokens={tokensFor(tokens, "api")} onCreate={() => workspace.setModal({ kind: "token" })} emptyText="Create one per client pipeline. Tokens are shown once, expire within a year, and are never included in backups." revokeWarning="Pipelines using it will fail until they get a new token."/>
      <Sheet title="Connect a pipeline" meta="Exit codes: 0 pass · 1 policy violation · 2 error">
        <div className="sheet-body form-grid">
          <div className="field"><span className="field-label">GitHub Actions<CopyButton value={github}/></span><code className="code">{github}</code></div>
          <div className="field"><span className="field-label">GitLab, Bitbucket, Jenkins, Azure, or any shell with Python 3.9+<CopyButton value={shell}/></span><code className="code">{shell}</code></div>
          <p className="field-hint">Central policies on the Policies page are enforced on every run: pipelines can tighten the gate but never relax it. Accepted risk is honored until it expires; failed or replaced scans never pass. Full options, SARIF upload, and the GitLab template are in docs/CI_CD.md.</p>
        </div>
      </Sheet>
    </>
  );
}

function AssistantsSection() {
  const workspace = useWorkspace();
  const { tokens, origin, now, projects } = workspace;
  const [activity, setActivity] = useState<AssistantActivity | null>(null);
  const [failed, setFailed] = useState(false);
  const load = useCallback(async () => {
    try { setActivity(await api<AssistantActivity>("mcp/activity?limit=50")); setFailed(false); }
    catch { setFailed(true); }
  }, []);
  useEffect(() => { const timer = window.setTimeout(() => void load(), 0); return () => window.clearTimeout(timer); }, [load]);
  const url = mcpEndpoint(origin);
  const snippets = clientSnippets(url);
  const create = () => workspace.setModal({ kind: "token", audience: "mcp" });
  return (
    <>
      <div className="section-intro"><h2>AI assistants</h2><p>Claude, ChatGPT, Cursor, and other MCP clients can read findings, scans, gate decisions, and package search, and run check scans on lockfiles. Nothing they do changes findings, alerts, or monitored manifests.</p></div>
      {activity && !activity.enabled && <div className="callout is-danger"><Icon name="warning" size={16}/><span>The MCP endpoint is turned off. Set <span className="inline-code">DEPRADAR_MCP_ENABLED=true</span> for the API and restart it.</span></div>}
      <div className="callout"><Icon name="shield" size={16}/><span>Everything an assistant reads is sent to its model provider. Give each assistant its own token, and restrict it to one project for client work.</span></div>
      <TokenSheet tokens={tokensFor(tokens, "mcp")} onCreate={create} emptyText="Create one per person and assistant. Tokens work on the MCP endpoint only, are shown once, and are never included in backups." revokeWarning="The assistant loses access immediately."/>
      <Sheet title="Connect an assistant" meta={url}>
        <div className="sheet-body form-grid">
          <div className="field"><span className="field-label">Claude Code: <span className="inline-code">.mcp.json</span><CopyButton value={snippets.claudeCode}/></span><code className="code">{snippets.claudeCode}</code></div>
          <div className="field"><span className="field-label">Cursor: <span className="inline-code">~/.cursor/mcp.json</span><CopyButton value={snippets.json}/></span><code className="code">{snippets.json}</code></div>
          <p className="field-hint">Set the token as <span className="inline-code">DEPRADAR_MCP_TOKEN</span> where the assistant runs; these files read it from there. Assistants connect to the API at <span className="inline-code">/api/mcp</span> with the token in the Authorization header. ChatGPT and claude.ai connectors need OAuth sign-in, which DepRadar does not offer yet. Setup for each client is in docs/MCP.md.</p>
        </div>
      </Sheet>
      <Sheet title="Recent activity" meta="Arguments and results are never recorded" actions={<button className="btn btn-ghost btn-sm" onClick={() => void load()}><Icon name="refresh" size={14}/>Refresh</button>}>
        {failed ? <Empty title="Activity is unavailable" text="The API did not return assistant activity. Check that it is running the current version." action={<button className="btn btn-secondary" onClick={() => void load()}>Retry</button>}/>
          : !activity ? <div className="sheet-body form-grid" aria-busy="true"><span className="skeleton" style={{ width: "60%" }}/><span className="skeleton" style={{ width: "45%" }}/><span className="skeleton" style={{ width: "52%" }}/></div>
          : !activity.events.length ? <Empty title="No assistant calls yet" text="Calls appear here once an assistant uses a token from this page."/>
          : <div className="table-wrap">
            <table className="table">
              <thead><tr><th>When</th><th>Call</th><th className="col-optional">Token</th><th className="col-optional">Project</th><th className="col-optional">Client</th><th>Outcome</th></tr></thead>
              <tbody>{activity.events.map((call) => {
                const outcome = callOutcome(call);
                return (
                  <tr key={call.id}>
                    <td className="muted">{relativeTime(now, call.created_at)}</td>
                    <td><div className="cell-main"><b>{callLabel(call.name)}</b>{call.detail && <small>{call.detail}</small>}</div></td>
                    <td className="col-optional">{call.token_name || "Deleted token"}</td>
                    <td className="col-optional">{call.project_id ? projectName(projects, call.project_id) : "—"}</td>
                    <td className="col-optional muted" title="Reported by the assistant">{call.client_name || "—"}</td>
                    <td><span className="status"><i className={`dot ${outcome.tone}`}/>{outcome.label}</span></td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>}
      </Sheet>
    </>
  );
}

function HealthSection() {
  const { health, now, actions } = useWorkspace();
  const cells: [string, string, string][] = health ? [
    ["Database", health.database === "ready" ? "Ready" : health.database, "dot-ok"],
    ["Worker", health.worker === "healthy" ? `Running · ${relativeTime(now, health.worker_heartbeat_at)}` : "Not reporting", health.worker === "healthy" ? "dot-ok" : "dot-bad"],
    ["OSV scanner", health.scanner === "healthy" ? `Ready · checked ${relativeTime(now, health.scanner_checked_at)}` : health.scanner === "unavailable" ? "Unavailable" : "Not reporting", health.scanner === "healthy" ? "dot-ok" : "dot-bad"],
    ["Scan queue", `${health.queued_jobs} queued · ${health.running_jobs} running`, health.queued_jobs > 20 ? "dot-warn" : "dot-ok"],
    ["Oldest queued scan", health.oldest_queued_job_at ? relativeTime(now, health.oldest_queued_job_at) : "None waiting", "dot-ok"],
    ["Failed scans", String(health.failed_jobs), health.failed_jobs ? "dot-warn" : "dot-ok"],
    ["Scheduled checks due", String(health.due_projects), health.due_projects ? "dot-warn" : "dot-ok"],
    ["Alert queue", `${health.queued_deliveries} queued · ${health.failed_deliveries} failed`, health.failed_deliveries ? "dot-bad" : "dot-ok"],
    ["KEV and EPSS data", health.intelligence_updated_at ? `Refreshed ${relativeTime(now, health.intelligence_updated_at)}` : "Not refreshed yet", health.intelligence_updated_at ? "dot-ok" : "dot-warn"],
  ] : [];
  return (
    <>
      <div className="section-intro"><h2>Service health</h2><p>Live status of the worker, the isolated scanner, the queues, and the vulnerability intelligence feeds. Monitoring stops while the host is off.</p></div>
      <Sheet title="Services" actions={<button className="btn btn-ghost btn-sm" onClick={() => void actions.refresh()}><Icon name="refresh" size={14}/>Refresh</button>}>
        {health ? <div className="ops-grid">{cells.map(([label, value, tone]) => <div className="ops-cell" key={label}><span><i className={`dot ${tone}`}/>{label}</span><b>{value}</b></div>)}</div> : <Empty title="Health data is unavailable" text="The API did not return service health. Check that the worker container is running."/>}
      </Sheet>
    </>
  );
}

function RetentionSection() {
  const { retention, actions } = useWorkspace();
  return (
    <>
      <div className="section-intro"><h2>Data retention</h2><p>Older scans, delivery records, and AI assistant activity are pruned daily. Each manifest’s latest snapshot, active work, and scans that changed a finding are always kept as evidence.</p></div>
      <RetentionForm key={JSON.stringify(retention)} retention={retention} onSave={actions.saveRetention} onRun={actions.runRetention}/>
    </>
  );
}

function RetentionForm({ retention, onSave, onRun }: { retention: RetentionPolicy; onSave: (value: RetentionPolicy) => Promise<boolean>; onRun: () => Promise<void> }) {
  const [draft, setDraft] = useState(retention);
  const dirty = draft.scan_days !== retention.scan_days || draft.delivery_days !== retention.delivery_days || draft.audit_days !== retention.audit_days;
  return (
    <Sheet title="History">
      <form className="sheet-body form-grid" onSubmit={(event) => { event.preventDefault(); void onSave(draft); }}>
        <div className="form-row">
          <label className="field"><span className="field-label">Keep scans for <span>days</span></span><input className="input" type="number" min={1} max={3650} required value={draft.scan_days} onChange={(event) => setDraft({ ...draft, scan_days: Number(event.target.value) })}/></label>
          <label className="field"><span className="field-label">Keep deliveries for <span>days</span></span><input className="input" type="number" min={1} max={3650} required value={draft.delivery_days} onChange={(event) => setDraft({ ...draft, delivery_days: Number(event.target.value) })}/></label>
          <label className="field"><span className="field-label">Keep AI assistant activity for <span>days</span></span><input className="input" type="number" min={1} max={3650} required value={draft.audit_days} onChange={(event) => setDraft({ ...draft, audit_days: Number(event.target.value) })}/></label>
        </div>
        <div className="page-actions"><button className="btn btn-primary" disabled={!dirty}>Save retention</button><button type="button" className="btn btn-secondary" onClick={() => { if (window.confirm("Remove scan and delivery history older than the retention periods now? This cannot be undone.")) void onRun(); }}>Run cleanup now</button></div>
      </form>
    </Sheet>
  );
}

function BackupSection() {
  const backup = "docker compose exec api depradar backup /data/backups/depradar-$(date +%Y%m%d-%H%M%S).tar.gz";
  return (
    <>
      <div className="section-intro"><h2>Backups</h2><p>Each backup takes a consistent snapshot and proves it by restoring into an isolated schema. Archives exclude sessions and API tokens.</p></div>
      <Sheet title="Create a verified backup">
        <div className="sheet-body form-grid">
          <div className="field"><span className="field-label">On the server<CopyButton value={backup}/></span><code className="code">{backup}</code></div>
          <div className="callout"><Icon name="shield" size={16}/><span>Copy archives off the host with <span className="inline-code">docker compose cp api:/data/backups/… .</span> and store them with the environment credentials kept separately. Restores need an empty, migrated installation; see docs/BACKUPS.md.</span></div>
        </div>
      </Sheet>
    </>
  );
}

function CoverageSection() {
  return (
    <>
      <div className="section-intro"><h2>Coverage</h2><p>Lockfiles are scanned by the pinned OSV-Scanner in an isolated container. Each format is verified with a fixture that pins a known vulnerable version.</p></div>
      <div className="format-grid">{formatGroups.map((group) => <div key={group.label}><b>{group.label}</b><span>{group.files}</span></div>)}</div>
      <div className="callout"><Icon name="warning" size={16}/><span>Local, workspace, or Git sources, unpinned requirements, and private registries mark a scan as partial. Partial and failed scans never resolve findings.</span></div>
    </>
  );
}
