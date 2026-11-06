"use client";

import { useEffect, useState } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { accessLabel, formatGroups, projectName, relativeTime, shortDate, tokenState } from "@/components/workspace/format";
import { IdentitiesSection } from "@/components/workspace/identities";
import { CopyButton, Empty, PageHead, Sheet } from "@/components/workspace/ui";
import type { RetentionPolicy } from "@/lib/api";

const sections = [
  { id: "ci", label: "CI/CD access", icon: "branch" },
  { id: "identities", label: "Trusted identities", icon: "lock" },
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
      <PageHead title="Settings" lede="Pipeline access, the health of the services that scan and send alerts, how long DepRadar keeps history, and backups."/>
      <div className="settings">
        <nav className="subnav" aria-label="Settings sections">{sections.map((item) => <button key={item.id} aria-current={section === item.id} onClick={() => choose(item.id)}><Icon name={item.icon} size={16}/>{item.label}</button>)}</nav>
        <div className="settings-panel" key={section}>
          {section === "ci" && <CiSection onIdentities={() => choose("identities")}/>}
          {section === "identities" && <IdentitiesSection/>}
          {section === "health" && <HealthSection/>}
          {section === "retention" && <RetentionSection/>}
          {section === "backups" && <BackupSection/>}
          {section === "coverage" && <CoverageSection/>}
        </div>
      </div>
    </>
  );
}

function CiSection({ onIdentities }: { onIdentities: () => void }) {
  const workspace = useWorkspace();
  const { tokens, projects, now, origin, actions } = workspace;
  const url = `${origin || "https://depradar.example.com"}/api/backend`;
  const github = `- uses: <org>/depradar/integrations/github-action@<commit-sha>\n  with:\n    url: ${url}\n    token: \${{ secrets.DEPRADAR_TOKEN }}\n    fail-on: high`;
  const shell = `curl -fsSL ${url}/ci/client.py -o depradar_ci.py\nDEPRADAR_URL=${url} python3 depradar_ci.py scan --fail-on high`;
  return (
    <>
      <div className="section-intro"><h2>CI/CD access</h2><p>Give each client pipeline its own token, with only the access it needs. Jobs on the default branch upload the manifests DepRadar keeps monitoring. Pull and merge request jobs only check the change: it passes or fails against your policies, and nothing DepRadar monitors changes. Give pull request jobs a “Pull request checks” token so they cannot change what is monitored.</p></div>
      <div className="callout"><Icon name="lock" size={16}/><span>On GitHub Actions or GitLab CI, you do not need to store a token: with a <button className="link" onClick={onIdentities}>trusted identity</button>, each job signs in with a temporary token (OIDC) issued by GitHub or GitLab, and only the branch and workflow you trust can update monitored manifests.</span></div>
      <Sheet title="Tokens" meta={`${tokens.filter((token) => tokenState(token, now) === "Active").length} active`} actions={<button className="btn btn-primary btn-sm" onClick={() => workspace.setModal({ kind: "token" })}><Icon name="plus" size={14}/>New token</button>}>
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
                  <td className="right">{state === "Active" && <button className="btn btn-ghost btn-sm" onClick={() => { if (window.confirm(`Revoke “${token.name}”? Pipelines using it will fail until they get a new token.`)) void actions.revokeToken(token); }}>Revoke</button>}</td>
                </tr>
              );
            })}</tbody>
          </table>
          {!tokens.length && <Empty title="No tokens yet" text="Create one per client pipeline. Tokens are shown once, expire within a year, and are never included in backups." action={<button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "token" })}><Icon name="key" size={15}/>Create the first token</button>}/>}
        </div>
      </Sheet>
      <Sheet title="Connect a pipeline" meta="Exit codes: 0 passed · 1 failed the policy · 2 error">
        <div className="sheet-body form-grid">
          <div className="field"><span className="field-label">GitHub Actions<CopyButton value={github}/></span><code className="code">{github}</code></div>
          <div className="field"><span className="field-label">GitLab, Bitbucket, Jenkins, Azure, or any shell with Python 3.9+<CopyButton value={shell}/></span><code className="code">{shell}</code></div>
          <p className="field-hint">Every run follows the rules on the Policies page. Pipeline options can make the check stricter, never looser. Findings with accepted risk do not fail the check until the acceptance expires, and a scan that failed or was replaced by a newer one never passes. All options, SARIF upload, and the GitLab template are described in docs/CI_CD.md.</p>
        </div>
      </Sheet>
    </>
  );
}

function HealthSection() {
  const { health, now, actions } = useWorkspace();
  const cells: [string, string, string][] = health ? [
    ["Database", health.database === "ready" ? "Ready" : health.database, "dot-ok"],
    ["Background worker", health.worker === "healthy" ? `Running · ${relativeTime(now, health.worker_heartbeat_at)}` : "Not reporting", health.worker === "healthy" ? "dot-ok" : "dot-bad"],
    ["OSV scanner", health.scanner === "healthy" ? `Ready · checked ${relativeTime(now, health.scanner_checked_at)}` : health.scanner === "unavailable" ? "Unavailable" : "Not reporting", health.scanner === "healthy" ? "dot-ok" : "dot-bad"],
    ["Scan queue", `${health.queued_jobs} queued · ${health.running_jobs} running`, health.queued_jobs > 20 ? "dot-warn" : "dot-ok"],
    ["Oldest queued scan", health.oldest_queued_job_at ? relativeTime(now, health.oldest_queued_job_at) : "None waiting", "dot-ok"],
    ["Failed scans", String(health.failed_jobs), health.failed_jobs ? "dot-warn" : "dot-ok"],
    ["Projects due for a scheduled scan", String(health.due_projects), health.due_projects ? "dot-warn" : "dot-ok"],
    ["Alert queue", `${health.queued_deliveries} queued · ${health.failed_deliveries} failed`, health.failed_deliveries ? "dot-bad" : "dot-ok"],
    ["KEV and EPSS data", health.intelligence_updated_at ? `Refreshed ${relativeTime(now, health.intelligence_updated_at)}` : "Not refreshed yet", health.intelligence_updated_at ? "dot-ok" : "dot-warn"],
  ] : [];
  return (
    <>
      <div className="section-intro"><h2>Service health</h2><p>Live status of the background worker that runs scans and sends alerts, the isolated scanner, the queues, and the KEV and EPSS data feeds. Nothing is scanned or sent while the server is off.</p></div>
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
      <div className="section-intro"><h2>Data retention</h2><p>Every day, DepRadar deletes scans and alert delivery records older than these limits. It always keeps each manifest’s latest upload, work still in progress, and every scan that opened or resolved a finding.</p></div>
      <RetentionForm key={JSON.stringify(retention)} retention={retention} onSave={actions.saveRetention} onRun={actions.runRetention}/>
    </>
  );
}

function RetentionForm({ retention, onSave, onRun }: { retention: RetentionPolicy; onSave: (value: RetentionPolicy) => Promise<boolean>; onRun: () => Promise<void> }) {
  const [draft, setDraft] = useState(retention);
  const dirty = draft.scan_days !== retention.scan_days || draft.delivery_days !== retention.delivery_days;
  return (
    <Sheet title="History">
      <form className="sheet-body form-grid" onSubmit={(event) => { event.preventDefault(); void onSave(draft); }}>
        <div className="form-row">
          <label className="field"><span className="field-label">Keep scans for <span>days</span></span><input className="input" type="number" min={1} max={3650} required value={draft.scan_days} onChange={(event) => setDraft({ ...draft, scan_days: Number(event.target.value) })}/></label>
          <label className="field"><span className="field-label">Keep alert deliveries for <span>days</span></span><input className="input" type="number" min={1} max={3650} required value={draft.delivery_days} onChange={(event) => setDraft({ ...draft, delivery_days: Number(event.target.value) })}/></label>
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
      <div className="section-intro"><h2>Backups</h2><p>Each backup saves a consistent copy of DepRadar’s data and checks it by restoring it into a separate, temporary area of the database. Backups never include sign-in sessions or API tokens.</p></div>
      <Sheet title="Create a verified backup">
        <div className="sheet-body form-grid">
          <div className="field"><span className="field-label">On the server<CopyButton value={backup}/></span><code className="code">{backup}</code></div>
          <div className="callout"><Icon name="shield" size={16}/><span>Copy archives off the host with <span className="inline-code">docker compose cp api:/data/backups/… .</span> and store the server’s credentials separately from them. A restore needs a fresh DepRadar installation with no data; see docs/BACKUPS.md.</span></div>
        </div>
      </Sheet>
    </>
  );
}

function CoverageSection() {
  return (
    <>
      <div className="section-intro"><h2>Coverage</h2><p>DepRadar scans manifests with a fixed version of OSV-Scanner, running in its own isolated container. Each supported format is tested with a sample file that contains a known vulnerable package.</p></div>
      <div className="format-grid">{formatGroups.map((group) => <div key={group.label}><b>{group.label}</b><span>{group.files}</span></div>)}</div>
      <div className="callout"><Icon name="warning" size={16}/><span>Packages from local folders, workspaces, Git repositories, or private registries, and requirements without an exact version, cannot be fully checked, so their scan is marked partial. Partial and failed scans never mark findings as resolved.</span></div>
    </>
  );
}
