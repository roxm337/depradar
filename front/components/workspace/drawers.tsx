"use client";

import { useEffect, useState } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { byPriority, cadence, countBySeverity, dateTime, monogram, primaryAdvisory, relativeTime, scanLabel, scanTone, shortDate } from "@/components/workspace/format";
import { CopyButton, Drawer, Empty, Pkg, Sev, StackBar, Switch } from "@/components/workspace/ui";
import { api, type Finding, type FindingDecision, type Project } from "@/lib/api";

function references(evidence: Array<Record<string, unknown>>) {
  const links = new Map<string, string>();
  for (const record of evidence) {
    if (!Array.isArray(record.references)) continue;
    for (const reference of record.references) {
      if (!reference || typeof reference !== "object" || !("url" in reference) || typeof reference.url !== "string") continue;
      try {
        const url = new URL(reference.url);
        if (url.protocol === "https:" || url.protocol === "http:") links.set(url.toString(), "type" in reference && typeof reference.type === "string" ? reference.type.toLowerCase() : url.hostname);
      } catch { /* Ignore malformed scanner reference URLs. */ }
    }
  }
  return [...links.entries()].slice(0, 12);
}

const workflowLabel: Record<string, string> = { open: "Needs review", acknowledged: "Acknowledged", risk_accepted: "Risk accepted" };

export function FindingDrawer() {
  const { findings, findingId, setFindingId } = useWorkspace();
  const finding = findings.find((row) => row.id === findingId);
  if (!finding) return null;
  return <FindingPanel key={finding.id} finding={finding} onClose={() => setFindingId(null)}/>;
}

function FindingPanel({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const workspace = useWorkspace();
  const { actions, now } = workspace;
  const [decisions, setDecisions] = useState<FindingDecision[] | null>(null);
  const project = workspace.projects.find((row) => row.id === finding.project_id);
  const links = references(finding.evidence);
  const open = finding.status === "open";

  useEffect(() => {
    let active = true;
    api<FindingDecision[]>(`findings/${finding.id}/decisions`).then((rows) => { if (active) setDecisions(rows); }).catch(() => { if (active) setDecisions([]); });
    return () => { active = false; };
  }, [finding.id, finding.workflow_status]);

  return (
    <Drawer label={`${finding.package_name} finding`} onClose={onClose}>
      <div className="drawer-head">
        <div className="drawer-top"><Sev value={finding.severity}/><span className={`tag ${open ? "" : "tag-ok"}`}>{open ? workflowLabel[finding.workflow_status] ?? finding.workflow_status : "Resolved"}</span>{finding.kev_known && <span className="tag tag-kev"><Icon name="target" size={12}/>Known exploited</span>}<button className="icon-btn" onClick={onClose} aria-label="Close details"><Icon name="close"/></button></div>
        <h2 className="drawer-title">{finding.package_name}</h2>
        <span className="drawer-sub">{finding.ecosystem} · {finding.package_version} · {primaryAdvisory(finding.advisory_ids)}</span>
      </div>
      <div className="drawer-body">
        <p className="drawer-lede">{finding.summary || "This package version is affected by a published advisory."}</p>

        <section className="block">
          <h3 className="block-title">Exploitability</h3>
          {finding.kev_known && <div className="callout is-danger"><Icon name="target" size={16}/><span><b>Listed in the CISA Known Exploited Vulnerabilities catalog.</b> Attackers have used this vulnerability in the wild; treat it as urgent regardless of severity.</span></div>}
          {finding.epss_score !== null ? (
            <div className="meter">
              <div className="meter-legend"><span>EPSS probability of exploitation in 30 days</span><b>{(finding.epss_score * 100).toFixed(2)}%</b></div>
              <div className="meter-track"><i style={{ width: `${Math.max(2, finding.epss_score * 100)}%` }}/></div>
              <div className="meter-legend"><span>{finding.epss_percentile !== null ? `Higher than ${(finding.epss_percentile * 100).toFixed(0)}% of scored CVEs` : "Percentile unavailable"}</span><span>{finding.intel_updated_at ? `Updated ${relativeTime(now, finding.intel_updated_at)}` : ""}</span></div>
            </div>
          ) : <p className="muted">No EPSS score is cached for these advisories. EPSS covers CVE identifiers only.</p>}
          {finding.cvss_vectors.map((vector) => <code key={vector} className="cvss">{vector}</code>)}
        </section>

        <section className="block">
          <h3 className="block-title">Remediation</h3>
          {finding.fixed_versions.length ? (
            <div className="fix">
              <b>Upgrade {finding.package_name} to a fixed release</b>
              <div className="version-list">{finding.fixed_versions.map((version) => <span key={version} className="version"><Icon name="check" size={13}/>{version}</span>)}</div>
              <p>Fixed versions come from the advisory. DepRadar does not check upgrade compatibility; run your tests before shipping.</p>
              <div><CopyButton value={finding.fixed_versions[0]} label={`Copy ${finding.fixed_versions[0]}`}/></div>
            </div>
          ) : <div className="fix is-none"><b>No fixed version is published yet</b><p>Watch the advisory, limit exposure of the affected code path, or record a time-boxed risk acceptance.</p></div>}
        </section>

        <section className="block">
          <h3 className="block-title">Location</h3>
          <dl className="kv">
            <dt>Project</dt><dd>{project ? <button className="link" onClick={() => { workspace.setFindingId(null); workspace.setProjectId(project.id); }}>{project.name}<Icon name="arrow" size={13}/></button> : "Removed project"}</dd>
            <dt>Manifest</dt><dd className="mono">{finding.target_path || finding.target_filename}</dd>
            {finding.revision && <><dt>Revision</dt><dd className="mono">{finding.revision}</dd></>}
            {finding.purl && <><dt>Package URL</dt><dd className="mono">{finding.purl}</dd></>}
            <dt>First detected</dt><dd>{dateTime(finding.first_seen_at)} <span className="muted">· {relativeTime(now, finding.first_seen_at)}</span></dd>
            <dt>{open ? "Last observed" : "Resolved"}</dt><dd>{dateTime(open ? finding.last_seen_at : finding.resolved_at)}</dd>
            {finding.risk_until && <><dt>Risk accepted until</dt><dd>{dateTime(finding.risk_until)}</dd></>}
          </dl>
        </section>

        <section className="block">
          <h3 className="block-title">Advisories</h3>
          {finding.advisory_ids.map((id) => <a key={id} className="advisory" href={`https://osv.dev/vulnerability/${encodeURIComponent(id)}`} target="_blank" rel="noopener noreferrer">{id}<Icon name="external" size={14}/></a>)}
          {links.length > 0 && <div className="chips">{links.map(([url, label]) => <a key={url} className="chip" href={url} target="_blank" rel="noopener noreferrer">{label}<Icon name="external" size={12}/></a>)}</div>}
        </section>

        <section className="block">
          <h3 className="block-title">Decision log</h3>
          {decisions === null ? <span className="skeleton" style={{ width: "60%" }}/> : decisions.length ? (
            <div className="timeline">{decisions.map((decision, index) => <div className="timeline-item" key={`${decision.created_at}-${index}`}><span className="dot dot-ok"/><div><b>{decision.action.replaceAll("_", " ")}</b>{decision.note && <p>{decision.note}</p>}{decision.expires_at && <p>Expires {dateTime(decision.expires_at)}</p>}</div><time>{relativeTime(now, decision.created_at)}</time></div>)}</div>
          ) : <p className="muted">No decisions recorded. Acknowledge the finding to mute alerts while you work on it.</p>}
        </section>
      </div>
      <div className="drawer-foot">
        {!open && <span className="foot-meta">Resolved by a complete scan on {shortDate(finding.resolved_at)}.</span>}
        {open && finding.workflow_status === "open" && <button className="btn btn-primary" onClick={() => void actions.acknowledge(finding)}><Icon name="check" size={16}/>Acknowledge</button>}
        {open && finding.workflow_status !== "open" && <button className="btn btn-secondary" onClick={() => void actions.clearDecision(finding)}>{finding.workflow_status === "risk_accepted" ? "Revoke risk acceptance" : "Reopen for review"}</button>}
        {open && finding.workflow_status !== "risk_accepted" && <button className="btn btn-ghost" onClick={() => workspace.setModal({ kind: "risk", findingId: finding.id })}>Accept risk temporarily…</button>}
      </div>
    </Drawer>
  );
}

type Tab = "overview" | "manifests" | "scans" | "settings";

export function ProjectDrawer() {
  const { projects, projectId, setProjectId } = useWorkspace();
  const project = projects.find((row) => row.id === projectId);
  if (!project) return null;
  return <ProjectPanel key={project.id} project={project} onClose={() => setProjectId(null)}/>;
}

function ProjectPanel({ project, onClose }: { project: Project; onClose: () => void }) {
  const workspace = useWorkspace();
  const { actions, now } = workspace;
  const [tab, setTab] = useState<Tab>("overview");
  const open = workspace.findings.filter((finding) => finding.project_id === project.id && finding.status === "open").sort(byPriority);
  const counts = countBySeverity(open);
  const manifests = [...new Map(workspace.inventories.filter((row) => row.project_id === project.id).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).map((row) => [row.target_path, row])).values()];
  const scans = workspace.scans.filter((scan) => scan.project_id === project.id);
  const latest = scans[0];

  return (
    <Drawer label={`${project.name} project`} onClose={onClose}>
      <div className="drawer-head">
        <div className="drawer-top"><span className="monogram">{monogram(project.name)}</span><span className={`tag ${project.monitoring_enabled ? "tag-ok" : ""}`}>{project.monitoring_enabled ? `Checked ${cadence(project.check_interval_hours)}` : "Monitoring paused"}</span><button className="icon-btn" onClick={onClose} aria-label="Close project"><Icon name="close"/></button></div>
        <h2 className="drawer-title">{project.name}</h2>
        <span className="drawer-desc">{project.description || "No description."}</span>
        <div className="drawer-tabs" role="tablist">{(["overview", "manifests", "scans", "settings"] as Tab[]).map((value) => <button key={value} role="tab" aria-selected={tab === value} onClick={() => setTab(value)}>{value[0].toUpperCase() + value.slice(1)}{value === "manifests" ? ` · ${manifests.length}` : value === "scans" ? ` · ${scans.length}` : ""}</button>)}</div>
      </div>
      <div className="drawer-body" key={tab}>
        {tab === "overview" && <>
          <div className="stat-row">
            <div className="stat"><span>Open findings</span><strong>{open.length}</strong></div>
            <div className="stat"><span>Critical + high</span><strong className={counts.critical + counts.high ? "is-hot" : ""}>{counts.critical + counts.high}</strong></div>
            <div className="stat"><span>Manifests</span><strong>{manifests.length}</strong></div>
            <div className="stat"><span>Last scan</span><strong className="is-text">{latest ? relativeTime(now, latest.created_at) : "Never"}</strong></div>
          </div>
          {open.length > 0 && <StackBar counts={counts} total={open.length}/>}
          <section className="block">
            <h3 className="block-title">Highest priority</h3>
            {open.length ? <div className="list">{open.slice(0, 6).map((finding) => <button key={finding.id} className="list-row" onClick={() => { workspace.setProjectId(null); workspace.setFindingId(finding.id); }}><Sev value={finding.severity}/><span className="cell-main"><Pkg name={finding.package_name} version={finding.package_version}/><small>{primaryAdvisory(finding.advisory_ids)} · {finding.target_path}</small></span><Icon name="chevron" size={15}/></button>)}</div> : <Empty title="No open findings" text={latest ? "The latest complete scans found no known vulnerabilities." : "Upload a lockfile or connect a pipeline to run the first scan."}/>}
          </section>
        </>}
        {tab === "manifests" && <section className="block">
          <h3 className="block-title">Monitored manifests</h3>
          {manifests.length ? <div className="list">{manifests.map((manifest) => <div key={manifest.id} className="list-row"><Icon name="file" size={17}/><span className="cell-main"><span className="mono">{manifest.target_path}</span><small>Uploaded {relativeTime(now, manifest.created_at)}{manifest.revision ? ` · ${manifest.revision}` : ""} · sha256 {manifest.sha256.slice(0, 12)}</small></span><button className="btn btn-secondary btn-sm" onClick={() => void actions.rescan(manifest.id, manifest.target_path)}><Icon name="refresh" size={14}/>Scan</button></div>)}</div> : <Empty title="No manifests yet" text="Upload a lockfile or SBOM, or let a CI pipeline upload one on every merge."/>}
          <button className="btn btn-secondary" onClick={() => workspace.setModal({ kind: "upload", projectId: project.id })}><Icon name="upload" size={15}/>Upload a manifest</button>
        </section>}
        {tab === "scans" && <section className="block">
          <h3 className="block-title">Scan history</h3>
          {scans.length ? <div className="timeline">{scans.slice(0, 40).map((scan) => <div className="timeline-item" key={scan.id}><span className={`dot ${scanTone(scan)}`}/><div><b>{scanLabel(scan)}</b>{scan.mode === "check" && <span className="tag tag-check"><Icon name="branch" size={12}/>CI check</span>}<p>{scan.package_count} packages · {scan.engine_version ?? "OSV-Scanner"}{scan.error ? ` · ${scan.error}` : ""}</p>{scan.coverage_notes.length > 0 && <p>{scan.coverage_notes.join(" · ")}</p>}</div><time>{relativeTime(now, scan.created_at)}</time></div>)}</div> : <Empty title="No scans yet" text="Scans appear here after an upload, a scheduled check, or a pipeline run."/>}
        </section>}
        {tab === "settings" && <>
          <section className="block">
            <h3 className="block-title">Monitoring</h3>
            <div className="toggle-row"><div><b>Scheduled rechecks</b><small>Rechecks the latest manifests against new advisories, even without code changes.</small></div><Switch checked={project.monitoring_enabled} label="Scheduled rechecks" onChange={(enabled) => void actions.setMonitoring(project, enabled, project.check_interval_hours)}/></div>
            <label className="field"><span className="field-label">Check every</span><select className="select" value={project.check_interval_hours} onChange={(event) => void actions.setMonitoring(project, project.monitoring_enabled, Number(event.target.value))}>{[1, 3, 6, 12, 24, 48, 72, 168].map((hours) => <option key={hours} value={hours}>{cadence(hours)[0].toUpperCase() + cadence(hours).slice(1)}</option>)}</select></label>
            {project.next_check_at && project.monitoring_enabled && <p className="field-hint">{Date.parse(project.next_check_at) > now ? `Next check ${relativeTime(now, project.next_check_at)}.` : "A check is due and runs on the worker’s next cycle."}</p>}
          </section>
          <section className="block">
            <h3 className="block-title">Alerts</h3>
            <div className="toggle-row"><div><b>Send alerts for this project</b><small>Email and Telegram deliveries follow the workspace policy unless overridden below.</small></div><Switch checked={project.notifications_enabled} label="Project alerts" onChange={(enabled) => void actions.setAlerts(project, enabled, project.alert_min_severity ?? "inherit")}/></div>
            <label className="field"><span className="field-label">Immediate alerts from</span><select className="select" value={project.alert_min_severity ?? "inherit"} onChange={(event) => void actions.setAlerts(project, project.notifications_enabled, event.target.value)}><option value="inherit">Workspace policy</option><option value="critical">Critical only</option><option value="high">High and above</option><option value="medium">Medium and above</option><option value="low">Every severity</option></select></label>
          </section>
          <section className="block">
            <h3 className="block-title">Danger zone</h3>
            <div className="danger-zone"><p><b>Delete this project</b>Removes its manifests, scans, findings, decisions, and project tokens. Backups are not changed.</p><button className="btn btn-danger" onClick={() => { if (window.confirm(`Delete “${project.name}” and all of its history? This cannot be undone.`)) void actions.deleteProject(project); }}><Icon name="trash" size={15}/>Delete</button></div>
          </section>
        </>}
      </div>
      <div className="drawer-foot">
        <button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "upload", projectId: project.id })}><Icon name="upload" size={15}/>Upload manifest</button>
        {manifests[0] && <button className="btn btn-secondary" onClick={() => void actions.rescanAll(manifests.map((manifest) => manifest.id), project.name)}><Icon name="refresh" size={15}/>Scan {manifests.length > 1 ? `${manifests.length} manifests` : "again"}</button>}
        {latest && <span className="foot-meta"><span className={`dot ${scanTone(latest)}`}/>{scanLabel(latest)} · {relativeTime(now, latest.created_at)}</span>}
      </div>
    </Drawer>
  );
}

