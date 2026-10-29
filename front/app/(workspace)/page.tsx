"use client";

import Link from "next/link";
import { Icon } from "@/components/icon";
import { Radar } from "@/components/radar";
import { useWorkspace } from "@/components/workspace/context";
import { byPriority, countBySeverity, primaryAdvisory, relativeTime, scanLabel, scanTone, SEVERITIES, severityOf, severityRank } from "@/components/workspace/format";
import { Empty, PageHead, Pkg, Sev, Sheet, SkeletonRows, StackBar } from "@/components/workspace/ui";

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;

export default function OverviewPage() {
  const workspace = useWorkspace();
  const { findings, projects, scans, deliveries, tokens, health, now, ready } = workspace;
  const open = findings.filter((finding) => finding.status === "open").sort(byPriority);
  const counts = countBySeverity(open);
  const tallest = Math.max(1, ...Object.values(counts));
  const kev = open.filter((finding) => finding.kev_known).length;
  const likely = open.filter((finding) => (finding.epss_score ?? 0) >= 0.1).length;
  const fixable = open.filter((finding) => finding.fixed_versions.length).length;
  const undecided = open.filter((finding) => finding.workflow_status === "open").length;
  const affected = new Set(open.map((finding) => finding.project_id)).size;
  const latest = scans[0];
  const exposure = projects.map((project) => {
    const rows = open.filter((finding) => finding.project_id === project.id);
    return { project, rows, counts: countBySeverity(rows), weight: rows.reduce((sum, finding) => sum + 10 ** severityRank(finding.severity), 0), scan: scans.find((scan) => scan.project_id === project.id) };
  }).sort((a, b) => b.weight - a.weight || a.project.name.localeCompare(b.project.name));
  const checks = scans.filter((scan) => scan.mode === "check" && now && now - Date.parse(scan.created_at) < 7 * 86_400_000).length;
  const activity = [
    ...scans.slice(0, 8).map((scan) => ({ id: scan.id, at: scan.created_at, tone: scanTone(scan), title: `${scanLabel(scan)}${scan.mode === "check" ? " · CI check" : ""}`, detail: `${projects.find((project) => project.id === scan.project_id)?.name ?? "Project"} · ${plural(scan.package_count, "package")}` })),
    ...deliveries.slice(0, 5).map((delivery) => ({ id: delivery.id, at: delivery.created_at, tone: delivery.status === "failed" ? "dot-bad" : delivery.status === "accepted" ? "dot-ok" : "dot-warn", title: `${delivery.kind.replaceAll("_", " ")} ${delivery.status === "accepted" ? "delivered" : delivery.status.replaceAll("_", " ")}`, detail: `${delivery.connector_id}${delivery.last_error ? ` · ${delivery.last_error}` : ""}` })),
    ...tokens.slice(0, 3).map((token) => ({ id: token.id, at: token.revoked_at ?? token.created_at, tone: token.revoked_at ? "" : "dot-ok", title: `CI/CD token ${token.revoked_at ? "revoked" : "created"}`, detail: token.name })),
  ].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 7);
  const date = now ? new Intl.DateTimeFormat("en-GB", { weekday: "long", day: "numeric", month: "long" }).format(now) : "Overview";
  const lede = !projects.length
    ? <>Create a project and upload a lockfile, or connect a pipeline, to start monitoring.</>
    : open.length
      ? <><strong>{plural(open.length, "open finding")}</strong> across {affected} of {plural(projects.length, "project")}. {undecided ? `${undecided} still need a decision.` : "Every finding has a decision."}</>
      : <>No open findings across {plural(projects.length, "project")}.{latest ? ` Last scan ${relativeTime(now, latest.created_at)}.` : ""}</>;

  return (
    <>
      <PageHead eyebrow={date} title="Risk overview" lede={lede} actions={<><button className="btn btn-secondary" onClick={() => workspace.setModal({ kind: "project" })}><Icon name="plus" size={15}/>New project</button><button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "upload" })}><Icon name="upload" size={15}/>Upload manifest</button></>}/>

      <section className="exposure" aria-label="Dependency exposure">
        <section>
          <span className="eyebrow"><span className={`dot dot-live ${open.length ? "dot-bad" : "dot-ok"}`}/>Open exposure</span>
          <div className="figure"><strong>{ready ? open.length : "–"}</strong><span><b>open findings</b>in {plural(affected, "project")}</span></div>
          <div className="ladder">{SEVERITIES.map((level) => <div className="ladder-row" key={level}><span>{level}</span><span className="track"><i className={`bar-${level}`} style={{ width: `${(counts[level] / tallest) * 100}%` }}/></span><b>{counts[level]}</b></div>)}</div>
        </section>
        <section>
          <span className="eyebrow">Signals that raise priority</span>
          <div className="signals">
            <div className={`signal ${kev ? "is-hot" : ""}`}><strong>{kev}</strong><span>Known exploited · CISA KEV</span></div>
            <div className="signal"><strong>{likely}</strong><span>EPSS ≥ 10% in 30 days</span></div>
            <div className="signal"><strong>{fixable}</strong><span>Have a fixed version</span></div>
            <div className="signal"><strong>{undecided}</strong><span>Awaiting a decision</span></div>
          </div>
          <p className="exposure-note">Severity comes from the advisories. Exploitation signals {health?.intelligence_updated_at ? `refreshed ${relativeTime(now, health.intelligence_updated_at)}` : "have not refreshed yet"}. <Link href="/findings">Triage findings →</Link></p>
        </section>
        <section className="exposure-radar">
          <Radar blips={open.map((finding) => ({ id: finding.id, severity: severityOf(finding.severity) }))}/>
          <div className="radar-legend">{(["critical", "high", "medium", "low"] as const).map((level) => <span key={level}><i className={`legend-${level}`}/>{level}</span>)}</div>
        </section>
      </section>

      {ready && !projects.length ? (
        <Sheet><Empty title="Nothing to monitor yet" text="Add a project for each client application, then upload its lockfile or let its CI pipeline do it on every merge." action={<div className="page-actions"><button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "project" })}><Icon name="plus" size={15}/>New project</button><Link className="btn btn-secondary" href="/settings#ci">Connect a pipeline</Link></div>}/></Sheet>
      ) : <>
        <div className="overview-grid">
          <Sheet title="Needs attention" meta="Ranked by severity, exploitation, and age" actions={<Link className="btn btn-ghost btn-sm" href="/findings">All findings<Icon name="arrow" size={14}/></Link>}>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Severity</th><th>Package</th><th className="col-optional">Project</th><th className="col-optional">Advisory</th><th>Fix</th></tr></thead>
                <tbody>
                  {!ready ? <SkeletonRows rows={5} columns={5}/> : open.slice(0, 8).map((finding) => (
                    <tr key={finding.id} className="is-link" onClick={() => workspace.setFindingId(finding.id)}>
                      <td><Sev value={finding.severity}/></td>
                      <td><div className="cell-main"><Pkg name={finding.package_name} version={finding.package_version}/>{finding.kev_known && <small><span className="tag tag-kev">Known exploited</span></small>}</div></td>
                      <td className="col-optional">{projects.find((project) => project.id === finding.project_id)?.name ?? "—"}</td>
                      <td className="col-optional"><span className="mono muted">{primaryAdvisory(finding.advisory_ids)}</span></td>
                      <td>{finding.fixed_versions[0] ? <span className="mono">{finding.fixed_versions[0]}</span> : <span className="muted">None yet</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {ready && !open.length && <Empty title="Nothing needs attention" text="Every monitored manifest is clear of known vulnerabilities. DepRadar keeps rechecking them as advisories are published."/>}
            </div>
          </Sheet>
          <Sheet title="Project exposure" actions={<Link className="btn btn-ghost btn-sm" href="/projects">All projects<Icon name="arrow" size={14}/></Link>}>
            <div className="risk-list">
              {exposure.slice(0, 5).map(({ project, rows, counts: projectCounts, scan }) => (
                <button key={project.id} className="risk-row" onClick={() => workspace.setProjectId(project.id)}>
                  <b>{project.name}</b><span className={`risk-count ${rows.length ? `sev-${SEVERITIES.find((level) => projectCounts[level]) ?? "unknown"}` : "muted"}`}>{rows.length ? `${rows.length} open` : "Clear"}</span>
                  <StackBar counts={projectCounts} total={rows.length}/>
                  <small>{scan ? `${scanLabel(scan)} ${relativeTime(now, scan.created_at)}` : "Not scanned yet"}{project.monitoring_enabled ? "" : " · monitoring paused"}</small>
                </button>
              ))}
              {!ready && <div className="sheet-body"><span className="skeleton"/></div>}
            </div>
            {exposure.length > 5 && <div className="sheet-foot"><Link className="link" href="/projects">{exposure.length - 5} more projects</Link></div>}
          </Sheet>
        </div>
        <div className="overview-grid">
          <Sheet title="Recent activity" meta="Scans, deliveries, and access changes">
            <div className="sheet-body">
              {activity.length ? <div className="timeline">{activity.map((item) => <div className="timeline-item" key={item.id}><span className={`dot ${item.tone}`}/><div><b>{item.title}</b><p>{item.detail}</p></div><time>{relativeTime(now, item.at)}</time></div>)}</div> : <p className="muted">Activity appears after the first upload, scan, or alert.</p>}
            </div>
          </Sheet>
          <Sheet title="Monitoring health" actions={<Link className="btn btn-ghost btn-sm" href="/settings#health">Details<Icon name="arrow" size={14}/></Link>}>
            <div className="health-grid">
              <div className="health-cell"><span><i className={`dot ${health?.worker === "healthy" ? "dot-ok" : "dot-warn"}`}/>Worker</span><b className={health?.worker === "healthy" ? "" : "is-warn"}>{health ? (health.worker === "healthy" ? "Running" : "Not reporting") : "—"}</b></div>
              <div className="health-cell"><span><i className={`dot ${health?.scanner === "healthy" ? "dot-ok" : "dot-bad"}`}/>OSV scanner</span><b className={health?.scanner === "healthy" ? "" : "is-warn"}>{health ? (health.scanner === "healthy" ? "Ready" : health.scanner === "unavailable" ? "Unavailable" : "Not reporting") : "—"}</b></div>
              <div className="health-cell"><span>Scan queue</span><b>{health ? `${health.queued_jobs} queued · ${health.running_jobs} running` : "—"}</b></div>
              <div className="health-cell"><span>Alert queue</span><b className={health?.failed_deliveries ? "is-warn" : ""}>{health ? `${health.queued_deliveries} queued · ${health.failed_deliveries} failed` : "—"}</b></div>
              <div className="health-cell"><span>Scheduled checks due</span><b>{health ? health.due_projects : "—"}</b></div>
              <div className="health-cell"><span>CI checks · last 7 days</span><b>{checks}</b></div>
            </div>
          </Sheet>
        </div>
      </>}
    </>
  );
}
