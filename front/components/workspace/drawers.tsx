"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { ConfirmDialog } from "@/components/workspace/drawer-dialog";
import { ageLabel, buildTimeline, percentileLabel } from "@/components/workspace/drawer-format";
import { DecisionTimeline, VersionChip } from "@/components/workspace/drawer-parts";
import { byPriority, bytes, cadence, countBySeverity, dateTime, monogram, primaryAdvisory, projectCoverage, relativeTime, retiredTargets, scanLabel, scanTone, SEVERITIES, shortDate, type CoverageState } from "@/components/workspace/format";
import { coverageBadge, plainDescription, scanDuration } from "@/components/workspace/projects-format";
import { Drawer, Empty, Pkg, Sev, StackBar, Switch } from "@/components/workspace/ui";
import { api, type Finding, type FindingDecision, type Project } from "@/lib/api";
import "./drawers.css";

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

const workflowLabel: Record<string, string> = { open: "Not reviewed", acknowledged: "Acknowledged", risk_accepted: "Risk accepted" };
const workflowTone: Record<string, string> = { open: "", acknowledged: "tag-info", risk_accepted: "tag-info" };

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
  // Retiring a manifest resolves its open findings at the moment of retirement.
  const retired = retiredTargets(workspace.inventories, finding.project_id).find((row) => row.target_path === finding.target_path);
  const resolvedByRetirement = !open && Boolean(retired?.retired_at && finding.resolved_at && Date.parse(finding.resolved_at) >= Date.parse(retired.retired_at) - 60_000);
  const timeline = useMemo(() => (decisions === null ? null : buildTimeline(finding, decisions)), [decisions, finding]);
  const epss = finding.epss_score;
  const epssTone = epss === null ? "" : epss >= 0.5 ? "is-critical" : epss >= 0.1 ? "is-high" : "is-low";

  useEffect(() => {
    let active = true;
    api<FindingDecision[]>(`findings/${finding.id}/decisions`).then((rows) => { if (active) setDecisions(rows); }).catch(() => { if (active) setDecisions([]); });
    return () => { active = false; };
  }, [finding.id, finding.workflow_status]);

  return (
    <Drawer label={`${finding.package_name} finding`} onClose={onClose}>
      <div className="drawer-head">
        <div className="drawer-top">
          <Sev value={finding.severity}/>
          <span className={`tag ${open ? workflowTone[finding.workflow_status] ?? "" : "tag-ok"}`}>{open ? workflowLabel[finding.workflow_status] ?? finding.workflow_status : "Resolved"}</span>
          {finding.kev_known && <span className="tag tag-kev"><Icon name="target" size={12}/>Known exploited</span>}
          <button className="icon-btn" onClick={onClose} aria-label="Close details"><Icon name="close"/></button>
        </div>
        <h2 className="drawer-title">{finding.package_name}</h2>
        <span className="drawer-sub">{finding.ecosystem} · {finding.package_version} · {primaryAdvisory(finding.advisory_ids)}</span>
      </div>
      <div className="drawer-body">
        <section className="block">
          <h3 className="block-title">Summary</h3>
          <p className="drawer-lede">{finding.summary || "This package version is affected by a published advisory."}</p>
          <div className="drawer-summary">
            <span>{open ? "Open for" : "Was open for"} <b>{ageLabel(now, finding.first_seen_at, open ? null : finding.resolved_at)}</b></span>
            {project && <span>in <b>{project.name}</b></span>}
          </div>
        </section>

        <section className="block">
          <h3 className="block-title">Exploitability</h3>
          {finding.kev_known && <div className="callout is-danger"><Icon name="target" size={16}/><span><b>Listed in CISA’s Known Exploited Vulnerabilities catalog.</b> Attackers have used this vulnerability in real attacks, so treat it as urgent whatever its severity.</span></div>}
          {epss !== null ? (
            <div className="meter">
              <div className="meter-legend"><span>Estimated probability of exploitation in the next 30 days (EPSS)</span><b className="epss-value">{(epss * 100).toFixed(epss < 0.1 ? 2 : 1)}%</b></div>
              <div className="meter-track"><i className={epssTone} style={{ width: `${Math.min(100, Math.max(1.5, epss * 100))}%` }}/></div>
              <div className="meter-legend"><span>{percentileLabel(finding.epss_percentile)}</span><span>{finding.intel_updated_at ? `Updated ${relativeTime(now, finding.intel_updated_at)}` : ""}</span></div>
            </div>
          ) : <p className="muted">No EPSS score is available. EPSS only scores vulnerabilities that have a CVE identifier.</p>}
          {finding.cvss_vectors.map((vector) => <code key={vector} className="cvss">{vector}</code>)}
        </section>

        <section className="block">
          <h3 className="block-title">Remediation</h3>
          {finding.fixed_versions.length ? (
            <div className="fix">
              <b>Upgrade {finding.package_name} to a fixed release</b>
              <div className="version-list">{finding.fixed_versions.map((version) => <VersionChip key={version} value={version}/>)}</div>
              <p>Select a version to copy it. Fixed versions come from the advisory; DepRadar does not check upgrade compatibility, so run your tests before shipping.</p>
            </div>
          ) : <div className="fix is-none"><b>No fixed version is published yet</b><p>Watch the advisory for a fix, limit use of the affected code, or accept the risk for a limited time.</p></div>}
        </section>

        <section className="block">
          <h3 className="block-title">Location</h3>
          <dl className="kv">
            <dt>Project</dt><dd>{project ? <button className="link" onClick={() => { workspace.setFindingId(null); workspace.setProjectId(project.id); }}>{project.name}<Icon name="arrow" size={13}/></button> : "Removed project"}</dd>
            <dt>Manifest</dt><dd className="mono">{finding.target_path || finding.target_filename}</dd>
            {finding.revision && <><dt>Revision</dt><dd className="mono">{finding.revision}</dd></>}
            {finding.purl && <><dt>Package URL</dt><dd className="mono">{finding.purl}</dd></>}
            <dt>First detected</dt><dd>{dateTime(finding.first_seen_at)} <span className="muted">· {relativeTime(now, finding.first_seen_at)}</span></dd>
            <dt>{open ? "Last observed" : "Resolved"}</dt><dd>{dateTime(open ? finding.last_seen_at : finding.resolved_at)} <span className="muted">· {relativeTime(now, open ? finding.last_seen_at : finding.resolved_at)}</span></dd>
            {finding.risk_until && <><dt>Risk accepted until</dt><dd>{dateTime(finding.risk_until)}</dd></>}
          </dl>
        </section>

        <section className="block">
          <h3 className="block-title">Advisories</h3>
          {finding.advisory_ids.map((id) => <a key={id} className="advisory" href={`https://osv.dev/vulnerability/${encodeURIComponent(id)}`} target="_blank" rel="noopener noreferrer">{id}<Icon name="external" size={14}/><span className="sr-only"> (opens in a new tab)</span></a>)}
          {links.length > 0 && <div className="chips">{links.map(([url, label]) => <a key={url} className="chip" href={url} target="_blank" rel="noopener noreferrer">{label}<Icon name="external" size={12}/><span className="sr-only"> (opens in a new tab)</span></a>)}</div>}
        </section>

        <section className="block">
          <h3 className="block-title">Review history</h3>
          {timeline === null ? <span className="skeleton" style={{ width: "60%" }}/> : <DecisionTimeline events={timeline} now={now}/>}
          {open && decisions?.length === 0 && <p className="muted">Not reviewed yet. Acknowledge the finding to stop alerts about it while you work on a fix.</p>}
        </section>
      </div>
      <div className="drawer-foot">
        {!open && <span className="foot-meta">{resolvedByRetirement ? `Resolved when its manifest was retired on ${shortDate(finding.resolved_at)}.` : `Resolved by a complete scan on ${shortDate(finding.resolved_at)}.`}</span>}
        {open && finding.workflow_status === "open" && <button className="btn btn-primary" onClick={() => void actions.acknowledge(finding)}><Icon name="check" size={16}/>Acknowledge</button>}
        {open && finding.workflow_status !== "open" && <button className="btn btn-secondary" onClick={() => void actions.clearDecision(finding)}>{finding.workflow_status === "risk_accepted" ? "Revoke risk acceptance" : "Reopen for review"}</button>}
        {open && finding.workflow_status !== "risk_accepted" && <button className="btn btn-ghost" onClick={() => workspace.setModal({ kind: "risk", findingId: finding.id })}>Accept risk temporarily…</button>}
      </div>
    </Drawer>
  );
}

type Tab = "overview" | "manifests" | "scans" | "settings";
const tabs: Tab[] = ["overview", "manifests", "scans", "settings"];

const quietProject: Record<CoverageState, (verified: number, total: number) => string> = {
  verified: () => "The latest complete scan of every monitored manifest found no known vulnerabilities.",
  pending: (verified, total) => `A scan is still running; ${verified} of ${total} manifests are confirmed clear so far.`,
  incomplete: (verified, total) => `Only ${verified} of ${total} manifests are confirmed clear. The latest scan of the others failed or could not check every package. Open Scans to see why, then rescan.`,
  unscanned: (verified, total) => `Only ${verified} of ${total} manifests are confirmed clear. The rest have not been scanned yet.`,
  unknown: () => "Your DepRadar server runs an older version that cannot report which manifests were scanned.",
  none: () => "Upload a lockfile or connect a pipeline to run the first scan.",
};

const capitalize = (text: string) => text.replace(/^./, (letter) => letter.toUpperCase());

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
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const open = workspace.findings.filter((finding) => finding.project_id === project.id && finding.status === "open").sort(byPriority);
  const counts = countBySeverity(open);
  const scans = useMemo(() => workspace.scans.filter((scan) => scan.project_id === project.id).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)), [workspace.scans, project.id]);
  const coverage = projectCoverage(project.id, workspace.inventories, scans);
  const badge = coverageBadge(coverage.state);
  const manifests = coverage.manifests;
  const retired = retiredTargets(workspace.inventories, project.id).filter((row) => !manifests.some((manifest) => manifest.target_path === row.target_path));
  const latest = coverage.latest ?? scans[0];
  const description = plainDescription(project.description);

  function onTabKeys(event: KeyboardEvent<HTMLDivElement>) {
    const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!step) return;
    event.preventDefault();
    const next = tabs[(tabs.indexOf(tab) + step + tabs.length) % tabs.length];
    setTab(next);
    requestAnimationFrame(() => document.getElementById(`project-tab-${next}`)?.focus());
  }

  return (
    <Drawer label={`${project.name} project`} onClose={onClose}>
      <div className="drawer-head">
        <div className="drawer-top">
          <span className="monogram" aria-hidden="true">{monogram(project.name)}</span>
          <span className={`tag ${badge.tone}`} title={`${coverage.verified} of ${manifests.length} manifests confirmed clear by a complete scan`}>{badge.label}</span>
          <span className={`tag ${project.monitoring_enabled ? "tag-muted" : "tag-warn"}`}>{project.monitoring_enabled ? `Scanned ${cadence(project.check_interval_hours)}` : "Monitoring paused"}</span>
          <button className="icon-btn" onClick={onClose} aria-label="Close project"><Icon name="close"/></button>
        </div>
        <h2 className="drawer-title">{project.name}</h2>
        <span className="drawer-desc">{description || "No description."}</span>
        <div className="drawer-tabs" role="tablist" aria-label="Project sections" onKeyDown={onTabKeys}>{tabs.map((value) => <button key={value} id={`project-tab-${value}`} role="tab" aria-selected={tab === value} aria-controls="project-panel" tabIndex={tab === value ? 0 : -1} onClick={() => setTab(value)}>{capitalize(value)}{value === "manifests" ? ` · ${manifests.length}` : value === "scans" ? ` · ${scans.length}` : ""}</button>)}</div>
      </div>
      <div className="drawer-body" key={tab} id="project-panel" role="tabpanel" aria-labelledby={`project-tab-${tab}`}>
        {tab === "overview" && <>
          <div className="stat-row">
            <div className="stat"><span>Open findings</span><strong>{open.length}</strong></div>
            <div className="stat"><span>Critical + high</span><strong className={counts.critical + counts.high ? "is-hot" : ""}>{counts.critical + counts.high}</strong></div>
            <div className="stat"><span>Manifests</span><strong>{manifests.length}</strong></div>
            <div className="stat"><span>Last scan</span><strong className="is-text">{latest ? relativeTime(now, latest.created_at) : "Never"}</strong></div>
          </div>
          {open.length > 0 && <div className="block">
            <StackBar counts={counts} total={open.length}/>
            <div className="legend">{SEVERITIES.filter((level) => counts[level]).map((level) => <span key={level}><i className={`bar-${level}`}/>{counts[level]} {level}</span>)}</div>
          </div>}
          <section className="block">
            <h3 className="block-title">Highest priority{open.length > 6 && <span className="block-count">Showing 6 of {open.length}</span>}</h3>
            {open.length ? <div className="list">{open.slice(0, 6).map((finding) => <button key={finding.id} className="list-row priority-row" onClick={() => { workspace.setProjectId(null); workspace.setFindingId(finding.id); }}><Sev value={finding.severity}/><span className="cell-main"><Pkg name={finding.package_name} version={finding.package_version}/><small>{primaryAdvisory(finding.advisory_ids)} · {finding.target_path}</small></span><Icon name="chevron" size={15}/></button>)}</div> : <Empty icon="check-circle" title={coverage.state === "verified" ? "No open findings" : "No known open findings"} text={quietProject[coverage.state](coverage.verified, manifests.length)}/>}
            {open.length > 6 && <Link className="link" href="/findings" onClick={() => { workspace.setFilters({ ...workspace.filters, project: project.id, status: "open" }); workspace.setProjectId(null); }}>View all {open.length} in Findings<Icon name="arrow" size={13}/></Link>}
          </section>
        </>}
        {tab === "manifests" && <section className="block">
          <h3 className="block-title">Monitored manifests</h3>
          {manifests.length ? <div className="list">{manifests.map((manifest) => {
            const scan = scans.find((row) => row.inventory_id === manifest.id && row.mode !== "check");
            return (
              <div key={manifest.id} className="manifest-row">
                <span className="manifest-path"><Icon name="file" size={15}/>{manifest.target_path}</span>
                <span className="manifest-meta">
                  <span className="status"><i className={`dot ${scanTone(scan)}`}/>{scan ? scanLabel(scan) : "Not scanned"}</span>
                  {manifest.revision && <span className="mono">{manifest.revision}</span>}
                  <span>{bytes(manifest.size_bytes)}</span>
                  <span>Uploaded {relativeTime(now, manifest.created_at)}</span>
                </span>
                <span className="manifest-actions">
                  <button className="btn btn-secondary btn-sm" onClick={() => void actions.rescan(manifest.id, manifest.target_path)}><Icon name="refresh" size={14}/>Rescan</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => workspace.setModal({ kind: "retire", projectId: project.id, targetPath: manifest.target_path })} aria-label={`Retire ${manifest.target_path}`}>Retire</button>
                </span>
              </div>
            );
          })}</div> : <Empty icon="file" title={retired.length ? "No monitored manifests" : "No manifests yet"} text="Upload a lockfile or SBOM, or let a CI pipeline upload it on every merge."/>}
          <button className="btn btn-secondary" onClick={() => workspace.setModal({ kind: "upload", projectId: project.id })}><Icon name="upload" size={15}/>Upload a manifest</button>
        </section>}
        {tab === "manifests" && retired.length > 0 && <section className="block retired-list">
          <h3 className="block-title">Retired manifests</h3>
          <div className="list">{retired.map((manifest) => <div key={manifest.id} className="manifest-row is-retired"><span className="manifest-path"><Icon name="file" size={15}/>{manifest.target_path}</span><span className="manifest-meta"><span>Retired {shortDate(manifest.retired_at)}</span><span>Upload it again to monitor it again</span></span></div>)}</div>
        </section>}
        {tab === "scans" && <section className="block">
          <h3 className="block-title">Scan history{scans.length > 40 && <span className="block-count">Latest 40 of {scans.length}</span>}</h3>
          {scans.length ? <div className="drawer-table-wrap"><table className="table">
            <thead><tr><th scope="col">Status</th><th scope="col">Type</th><th scope="col" className="right">Packages</th><th scope="col" className="right">Took</th><th scope="col" className="right">When</th></tr></thead>
            <tbody>{scans.slice(0, 40).map((scan) => (
              <tr key={scan.id}>
                <td><div className="cell-main"><span className="status"><i className={`dot ${scanTone(scan)}`}/>{scanLabel(scan)}</span>{(scan.error || scan.coverage_notes.length > 0) && <small className="scan-note">{scan.error ?? scan.coverage_notes.join(" · ")}</small>}</div></td>
                <td>{scan.mode === "check" ? <span className="tag tag-check" title="A pull request check: it never changes findings or alerts">CI check</span> : <span className="tag" title="A scan of a monitored manifest: it opens and resolves findings">Monitored</span>}</td>
                <td className="right">{scan.package_count.toLocaleString("en-GB")}</td>
                <td className="right muted">{scanDuration(scan.created_at, scan.completed_at)}</td>
                <td className="right muted"><time dateTime={scan.created_at} title={dateTime(scan.created_at)}>{relativeTime(now, scan.created_at)}</time></td>
              </tr>
            ))}</tbody>
          </table></div> : <Empty icon="clock" title="No scans yet" text="Scans appear here after an upload, a scheduled scan, or a pipeline run."/>}
        </section>}
        {tab === "settings" && <>
          <section className="block">
            <h3 className="block-title">Monitoring</h3>
            <div className="drawer-card">
              <div className="toggle-row"><div><b>Scheduled scans</b><small>Scans the latest manifests again on a schedule, so newly published vulnerabilities are caught even when the code has not changed.</small></div><Switch checked={project.monitoring_enabled} label="Scheduled scans" onChange={(enabled) => void actions.setMonitoring(project, enabled, project.check_interval_hours)}/></div>
              <label className="field"><span className="field-label">Scan every</span><select className="select" value={project.check_interval_hours} onChange={(event) => void actions.setMonitoring(project, project.monitoring_enabled, Number(event.target.value))}>{[1, 3, 6, 12, 24, 48, 72, 168].map((hours) => <option key={hours} value={hours}>{capitalize(cadence(hours))}</option>)}</select></label>
              {project.next_check_at && project.monitoring_enabled && <p className="field-hint">{Date.parse(project.next_check_at) > now ? `Next scan ${relativeTime(now, project.next_check_at)}.` : "A scan is due and starts shortly."}</p>}
            </div>
          </section>
          <section className="block">
            <h3 className="block-title">Alerts</h3>
            <div className="drawer-card">
              <div className="toggle-row"><div><b>Send alerts for this project</b><small>Sends email and Telegram alerts for this project, at the level set on the Notifications page unless you choose another below.</small></div><Switch checked={project.notifications_enabled} label="Project alerts" onChange={(enabled) => void actions.setAlerts(project, enabled, project.alert_min_severity ?? "inherit")}/></div>
              <label className="field"><span className="field-label">Send immediate alerts for</span><select className="select" value={project.alert_min_severity ?? "inherit"} onChange={(event) => void actions.setAlerts(project, project.notifications_enabled, event.target.value)}><option value="inherit">Notifications page setting</option><option value="critical">Critical only</option><option value="high">High and above</option><option value="medium">Medium and above</option><option value="low">Every severity</option></select></label>
            </div>
          </section>
          <section className="block">
            <h3 className="block-title">Danger zone</h3>
            <div className="danger-zone"><p><b>Delete this project</b>Removes its manifests, scans, findings and their reviews, gate decisions, project policy, trusted identities, and the tokens limited to it. Existing backups are not changed.</p><button className="btn btn-danger" onClick={() => setConfirming(true)}><Icon name="trash" size={15}/>Delete</button></div>
          </section>
        </>}
      </div>
      <div className="drawer-foot">
        <button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "upload", projectId: project.id })}><Icon name="upload" size={15}/>Upload manifest</button>
        {manifests[0] && <button className="btn btn-secondary" onClick={() => void actions.rescanAll(manifests.map((manifest) => manifest.id), project.name)}><Icon name="refresh" size={15}/>Scan {manifests.length > 1 ? `${manifests.length} manifests` : "again"}</button>}
        {latest && <span className="foot-meta"><span className={`dot ${scanTone(latest)}`}/>{scanLabel(latest)} · {relativeTime(now, latest.created_at)}</span>}
      </div>
      {confirming && (
        <ConfirmDialog title={`Delete ${project.name}?`} description="This cannot be undone." confirmLabel="Delete project" busy={deleting} onClose={() => setConfirming(false)} onConfirm={() => { setDeleting(true); void actions.deleteProject(project).finally(() => setDeleting(false)); }}>
          <ul className="retire-effects">
            <li>Its {manifests.length} monitored manifest{manifests.length === 1 ? "" : "s"}, scan history, findings and their reviews, gate decisions, and project policy are removed.</li>
            <li>CI tokens and trusted identities limited to this project stop working.</li>
            <li>Existing backups are not changed, so you can still restore from them.</li>
          </ul>
        </ConfirmDialog>
      )}
    </Drawer>
  );
}
