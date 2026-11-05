"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import "./overview.css";
import { Icon } from "@/components/icon";
import { AgeBars, TrendChart, WINDOWS } from "@/components/workspace/charts";
import { useWorkspace } from "@/components/workspace/context";
import { byPriority, countBySeverity, coverageLabel, projectCoverage, relativeTime, scanLabel, scanTone, severityRank, workspaceCoverage } from "@/components/workspace/format";
import { ageBuckets, change, DAY, medianResolveDays, openSeries, pastTarget, TARGET_DAYS, urgent } from "@/components/workspace/trend";
import { Empty, PageHead, Pkg, Segmented, Sev, Sheet, SkeletonRows, StackBar } from "@/components/workspace/ui";

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;
const ageLabel = (now: number, value: string) => {
  const days = Math.floor((now - Date.parse(value)) / DAY);
  return days >= 1 ? `${days}d` : `${Math.max(1, Math.floor((now - Date.parse(value)) / 3_600_000))}h`;
};

// Fewer open findings, or fewer urgent ones, is an improvement; the colour follows the direction of risk.
function Delta({ value }: { value: number | null }) {
  if (value === null) return <span>No history yet</span>;
  if (value === 0) return <span>No change in 7 days</span>;
  return <><span className={`delta ${value > 0 ? "is-worse" : "is-better"}`}><Icon name={value > 0 ? "arrow-up-right" : "sort-down"} size={12}/>{Math.abs(value)}</span><span>vs 7 days ago</span></>;
}

export default function OverviewPage() {
  const workspace = useWorkspace();
  const { findings, projects, scans, inventories, deliveries, tokens, health, now, ready } = workspace;
  const [windowDays, setWindowDays] = useState("90");
  const loaded = ready && now > 0;
  const open = useMemo(() => findings.filter((finding) => finding.status === "open").sort(byPriority), [findings]);
  const series = useMemo(() => (now ? openSeries(findings, now, Number(windowDays)) : []), [findings, now, windowDays]);
  const trend = useMemo(() => (now ? openSeries(findings, now, 8) : []), [findings, now]);
  const counts = countBySeverity(open);
  const kev = open.filter((finding) => finding.kev_known).length;
  const undecided = open.filter((finding) => finding.workflow_status === "open").length;
  const affected = new Set(open.map((finding) => finding.project_id)).size;
  const resolve = useMemo(() => (now ? medianResolveDays(findings, now) : { days: null, count: 0 }), [findings, now]);
  const buckets = useMemo(() => (now ? ageBuckets(open, now) : []), [open, now]);
  const overdue = now ? pastTarget(open, now) : 0;
  const names = useMemo(() => new Map(projects.map((project) => [project.id, project.name])), [projects]);
  const coverage = workspaceCoverage(projects, inventories, scans);
  const exposure = projects.map((project) => {
    const rows = open.filter((finding) => finding.project_id === project.id);
    const state = projectCoverage(project.id, inventories, scans);
    return { project, rows, counts: countBySeverity(rows), weight: rows.reduce((sum, finding) => sum + 10 ** severityRank(finding.severity), 0), state };
  }).sort((a, b) => b.weight - a.weight || a.project.name.localeCompare(b.project.name));
  const needsReview = exposure.filter((entry) => ["incomplete", "unscanned"].includes(entry.state.state)).length;
  const checks = scans.filter((scan) => scan.mode === "check" && now && now - Date.parse(scan.created_at) < 7 * DAY).length;
  const activity = [
    ...scans.slice(0, 8).map((scan) => ({ id: scan.id, at: scan.created_at, tone: scanTone(scan), title: `${scanLabel(scan)}${scan.mode === "check" ? " · CI check" : ""}`, detail: `${names.get(scan.project_id) ?? "Project"} · ${plural(scan.package_count, "package")}` })),
    ...deliveries.slice(0, 5).map((delivery) => ({ id: delivery.id, at: delivery.created_at, tone: delivery.status === "failed" ? "dot-bad" : delivery.status === "accepted" ? "dot-ok" : "dot-warn", title: `${delivery.kind.replaceAll("_", " ")} ${delivery.status === "accepted" ? "delivered" : delivery.status.replaceAll("_", " ")}`, detail: `${delivery.connector_id}${delivery.last_error ? ` · ${delivery.last_error}` : ""}` })),
    ...tokens.slice(0, 3).map((token) => ({ id: token.id, at: token.revoked_at ?? token.created_at, tone: token.revoked_at ? "" : "dot-ok", title: `CI/CD token ${token.revoked_at ? "revoked" : "created"}`, detail: token.name })),
  ].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 7);
  const lede = !projects.length
    ? "Create a project and upload a lockfile, or connect a pipeline, to start monitoring."
    : open.length
      ? <><strong>{plural(open.length, "open finding")}</strong> across {affected} of {plural(projects.length, "project")}. {undecided ? `${undecided} still need a decision.` : "Every finding has a decision."}</>
      : <>{coverage === "verified" ? "No open findings" : "No known open findings"} across {plural(projects.length, "project")}.</>;
  const services = [
    { label: "Worker", ok: health?.worker === "healthy", state: health ? (health.worker === "healthy" ? "Running" : "Not reporting") : "—" },
    { label: "OSV scanner", ok: health?.scanner === "healthy", state: health ? (health.scanner === "healthy" ? "Ready" : health.scanner === "unavailable" ? "Unavailable" : "Not reporting") : "—" },
  ];

  return (
    <>
      <PageHead title="Overview" lede={lede} actions={<><button className="btn btn-secondary" onClick={() => workspace.setModal({ kind: "project" })}><Icon name="plus" size={15}/>New project</button><button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "upload" })}><Icon name="upload" size={15}/>Upload manifest</button></>}/>

      {loaded && projects.length > 0 && coverage !== "verified" && coverage !== "none" && (
        <div className="callout coverage-note" role="status">
          <Icon name="info" size={15}/>
          <span>
            {coverage === "pending" ? "Some scans are still running, so these counts will change when they finish. "
              : coverage === "unknown" ? "Manifest coverage could not be determined from this API version, so these counts may be incomplete. "
              : `${plural(needsReview, "project")} ${needsReview === 1 ? "has" : "have"} a failed, partial, or missing scan, so these counts cover only what has been scanned. `}
            <Link href="/projects">Review projects</Link>
          </span>
        </div>
      )}

      <section className="kpis" aria-label="Key figures">
        <div className="kpi">
          <span className="kpi-label">Open findings</span>
          {loaded ? <span className="kpi-value">{open.length}</span> : <span className="skeleton"/>}
          <span className="kpi-note">{loaded && <Delta value={change(trend, 7, (point) => point.total)}/>}</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Critical and high</span>
          {loaded ? <span className={`kpi-value ${counts.critical ? "is-hot" : ""}`}>{counts.critical + counts.high}</span> : <span className="skeleton"/>}
          <span className="kpi-note">{loaded && <Delta value={change(trend, 7, urgent)}/>}</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Known exploited</span>
          {loaded ? <span className={`kpi-value ${kev ? "is-hot" : ""}`}>{kev}</span> : <span className="skeleton"/>}
          <span className="kpi-note">Listed in the CISA catalog</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Awaiting a decision</span>
          {loaded ? <span className="kpi-value">{undecided}</span> : <span className="skeleton"/>}
          <span className="kpi-note">{loaded && `of ${open.length} open`}</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Median time to resolve</span>
          {loaded ? <span className="kpi-value">{resolve.days === null ? "—" : <>{resolve.days < 10 ? resolve.days.toFixed(1) : Math.round(resolve.days)}<small>days</small></>}</span> : <span className="skeleton"/>}
          <span className="kpi-note">{loaded && (resolve.count ? `${plural(resolve.count, "resolution")} in 90 days` : "Nothing resolved in 90 days")}</span>
        </div>
      </section>

      {ready && !projects.length ? (
        <Sheet><Empty icon="box" title="Nothing to monitor yet" text="Add a project for each client application, then upload its lockfile or let its CI pipeline do it on every merge." action={<div className="page-actions"><button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "project" })}><Icon name="plus" size={15}/>New project</button><Link className="btn btn-secondary" href="/settings#ci">Connect a pipeline</Link></div>}/></Sheet>
      ) : <>
        <div className="overview-grid">
          <Sheet title="Open findings over time" meta="By severity" actions={<Segmented label="Time range" value={windowDays} onChange={setWindowDays} options={[...WINDOWS]}/>}>
            {loaded ? <TrendChart series={series}/> : <div className="chart-empty"><span className="spinner"/></div>}
          </Sheet>
          <Sheet title="Age of open findings" actions={overdue > 0 ? <span className="tag tag-kev" title={`Past common remediation targets: critical ${TARGET_DAYS.critical} days, high ${TARGET_DAYS.high}, medium ${TARGET_DAYS.medium}. Accepted risks are excluded.`}>{overdue} past target</span> : undefined}>
            {loaded ? <AgeBars buckets={buckets}/> : <div className="age-bars"><span className="skeleton"/><span className="skeleton"/><span className="skeleton"/></div>}
            <div className="age-foot">
              <span>Targets: critical <strong>{TARGET_DAYS.critical} days</strong>, high <strong>{TARGET_DAYS.high}</strong>, medium <strong>{TARGET_DAYS.medium}</strong>. Accepted risks are not counted.</span>
            </div>
          </Sheet>
        </div>

        <div className="overview-grid is-even">
          <Sheet title="Needs attention" meta="Ranked by severity, exploitation, and age" actions={<Link className="btn btn-ghost btn-sm" href="/findings">All findings<Icon name="arrow" size={14}/></Link>}>
            <div className="table-wrap">
              <table className="table attention">
                <thead><tr><th scope="col">Severity</th><th scope="col">Package</th><th scope="col" className="col-optional">Project</th><th scope="col" className="col-optional">Age</th><th scope="col">Fix</th></tr></thead>
                <tbody>
                  {!loaded ? <SkeletonRows rows={6} columns={5}/> : open.slice(0, 8).map((finding) => (
                    <tr key={finding.id} className="is-link" tabIndex={0} onClick={() => workspace.setFindingId(finding.id)} onKeyDown={(event) => { if (event.key === "Enter") workspace.setFindingId(finding.id); }}>
                      <td><Sev value={finding.severity}/></td>
                      <td><div className="cell-main"><Pkg name={finding.package_name} version={finding.package_version}/>{finding.kev_known && <small><span className="tag tag-kev">Known exploited</span></small>}</div></td>
                      <td className="col-optional">{names.get(finding.project_id) ?? "—"}</td>
                      <td className="col-optional muted" title={new Date(finding.first_seen_at).toLocaleString()}>{ageLabel(now, finding.first_seen_at)}</td>
                      <td>{finding.fixed_versions[0] ? <span className="mono">{finding.fixed_versions[0]}</span> : <span className="muted">None yet</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {loaded && !open.length && <Empty icon="check-circle" title={coverage === "verified" ? "Nothing needs attention" : "No known open findings"} text={coverage === "verified" ? "Every monitored manifest is clear as of its latest complete scan. DepRadar keeps rechecking as advisories are published." : "Some manifests are not confirmed clear yet. Open Projects to see which scans need attention."}/>}
            </div>
          </Sheet>
          <Sheet title="Projects by risk" actions={<Link className="btn btn-ghost btn-sm" href="/projects">All projects<Icon name="arrow" size={14}/></Link>}>
            <div className="risk-list">
              {exposure.slice(0, 6).map(({ project, rows, counts: projectCounts, state }) => (
                <button key={project.id} className="risk-row" onClick={() => workspace.setProjectId(project.id)}>
                  <b>{project.name}</b><span className={`risk-count ${rows.length ? "" : "muted"}`}>{rows.length ? `${rows.length} open` : coverageLabel[state.state]}</span>
                  <StackBar counts={projectCounts} total={rows.length}/>
                  <small className="risk-meta">{state.latest ? `${scanLabel(state.latest)} ${relativeTime(now, state.latest.created_at)}` : "Not scanned yet"}{project.monitoring_enabled ? "" : " · monitoring paused"}</small>
                </button>
              ))}
              {!loaded && <div className="sheet-body"><span className="skeleton"/></div>}
            </div>
            {exposure.length > 6 && <div className="sheet-foot"><Link className="link" href="/projects">{exposure.length - 6} more projects</Link></div>}
          </Sheet>
        </div>

        <div className="overview-grid is-even">
          <Sheet title="Recent activity" meta="Scans, deliveries, and access changes">
            <div className="sheet-body">
              {activity.length ? <div className="timeline">{activity.map((item) => <div className="timeline-item" key={item.id}><span className={`dot ${item.tone}`}/><div><b>{item.title}</b><p>{item.detail}</p></div><time>{relativeTime(now, item.at)}</time></div>)}</div> : <p className="muted">Activity appears after the first upload, scan, or alert.</p>}
            </div>
          </Sheet>
          <Sheet title="Monitoring health" actions={<Link className="btn btn-ghost btn-sm" href="/settings#health">Details<Icon name="arrow" size={14}/></Link>}>
            <div className="health-list">
              {services.map((service) => <div className="health-line" key={service.label}><span className={`dot ${service.ok ? "dot-ok" : "dot-warn"}`}/><span>{service.label}</span><b className={service.ok ? "" : "is-warn"}>{service.state}</b></div>)}
              <div className="health-line"><span className="dot"/><span>Scan queue</span><b>{health ? `${health.queued_jobs} queued · ${health.running_jobs} running` : "—"}</b></div>
              <div className="health-line"><span className={`dot ${health?.failed_deliveries ? "dot-bad" : ""}`}/><span>Alert queue</span><b className={health?.failed_deliveries ? "is-warn" : ""}>{health ? `${health.queued_deliveries} queued · ${health.failed_deliveries} failed` : "—"}</b></div>
              <div className="health-line"><span className="dot"/><span>Scheduled checks due</span><b>{health ? health.due_projects : "—"}</b></div>
              <div className="health-line"><span className="dot"/><span>CI checks, last 7 days</span><b>{checks}</b></div>
              <div className="health-line"><span className="dot"/><span>Threat data refreshed</span><b>{health?.intelligence_updated_at ? relativeTime(now, health.intelligence_updated_at) : "Not yet"}</b></div>
            </div>
          </Sheet>
        </div>
      </>}
    </>
  );
}
