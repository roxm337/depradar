"use client";

import { useState } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace, type Filters } from "@/components/workspace/context";
import { byPriority, primaryAdvisory, relativeTime, SEVERITIES, severityOf } from "@/components/workspace/format";
import { Empty, PageHead, Pkg, Segmented, Sev, Sheet, SkeletonRows } from "@/components/workspace/ui";
import type { Finding } from "@/lib/api";

const sorters: Record<Filters["sort"], (a: Finding, b: Finding) => number> = {
  priority: byPriority,
  newest: (a, b) => Date.parse(b.first_seen_at) - Date.parse(a.first_seen_at),
  package: (a, b) => a.package_name.localeCompare(b.package_name) || a.package_version.localeCompare(b.package_version),
};
const decisions: Record<string, string> = { open: "Needs review", acknowledged: "Acknowledged", risk_accepted: "Risk accepted" };

export default function FindingsPage() {
  const workspace = useWorkspace();
  const { findings, projects, filters, setFilters, query, setQuery, now, ready, actions } = workspace;
  const [limit, setLimit] = useState(100);
  const names = new Map(projects.map((project) => [project.id, project.name]));
  const byStatus = (finding: Finding) => filters.status === "all" || finding.status === filters.status;
  const search = query.trim().toLowerCase();
  const visible = findings.filter((finding) => byStatus(finding)
    && (!filters.severities.length || filters.severities.includes(severityOf(finding.severity)))
    && (filters.decision === "all" || finding.workflow_status === filters.decision)
    && (filters.project === "all" || finding.project_id === filters.project)
    && (!search || [finding.package_name, finding.package_version, finding.summary, finding.ecosystem, finding.target_path, names.get(finding.project_id) ?? "", ...finding.advisory_ids].some((value) => value.toLowerCase().includes(search))),
  ).sort(sorters[filters.sort]);
  const statusCounts = { open: findings.filter((finding) => finding.status === "open").length, resolved: findings.filter((finding) => finding.status === "resolved").length, all: findings.length };
  const update = (patch: Partial<Filters>) => { setFilters({ ...filters, ...patch }); setLimit(100); };
  const filtered = Boolean(search) || filters.severities.length > 0 || filters.decision !== "all" || filters.project !== "all";

  return (
    <>
      <PageHead eyebrow="Monitor" title="Findings" lede={<>Every vulnerable package version across your projects. Decisions are kept with each finding; only a complete clean scan resolves one.</>}/>
      <div className="toolbar">
        <Segmented label="Status" value={filters.status} onChange={(status) => update({ status })} options={[{ value: "open", label: "Open", count: statusCounts.open }, { value: "resolved", label: "Resolved", count: statusCounts.resolved }, { value: "all", label: "All", count: statusCounts.all }]}/>
        <label className="search"><Icon name="search" size={16}/><input type="search" value={query} onChange={(event) => { setQuery(event.target.value); setLimit(100); }} placeholder="Package, advisory, project, or path" aria-label="Filter findings"/></label>
        <select className="select" aria-label="Decision" value={filters.decision} onChange={(event) => update({ decision: event.target.value })}><option value="all">Any decision</option><option value="open">Needs review</option><option value="acknowledged">Acknowledged</option><option value="risk_accepted">Risk accepted</option></select>
        <select className="select" aria-label="Project" value={filters.project} onChange={(event) => update({ project: event.target.value })}><option value="all">All projects</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select>
        <select className="select" aria-label="Sort" value={filters.sort} onChange={(event) => update({ sort: event.target.value as Filters["sort"] })}><option value="priority">Sort by priority</option><option value="newest">Newest first</option><option value="package">Package name</option></select>
      </div>
      <div className="toolbar">
        <div className="chips" role="group" aria-label="Severity">{SEVERITIES.map((level) => {
          const active = filters.severities.includes(level);
          const count = findings.filter((finding) => byStatus(finding) && severityOf(finding.severity) === level).length;
          return <button key={level} className="chip" aria-pressed={active} onClick={() => update({ severities: active ? filters.severities.filter((value) => value !== level) : [...filters.severities, level] })}><span className={`sev sev-${level}`}>{level}</span><span className="mono muted">{count}</span></button>;
        })}</div>
        <span className="toolbar-meta">{visible.length} {visible.length === 1 ? "finding" : "findings"}{filtered && <> · <button className="link" onClick={() => { setQuery(""); update({ severities: [], decision: "all", project: "all" }); }}>Clear filters</button></>}</span>
      </div>
      <Sheet>
        <div className="table-wrap">
          <table className="table findings-table">
            <thead><tr><th>Severity</th><th>Package</th><th className="col-optional">Project · manifest</th><th className="col-optional">Advisory</th><th>Fixed in</th><th className="col-optional">Signals</th><th className="col-optional">Detected</th><th aria-label="Actions"/></tr></thead>
            <tbody>
              {!ready ? <SkeletonRows rows={8} columns={8}/> : visible.slice(0, limit).map((finding) => (
                <tr key={finding.id} className="is-link" onClick={() => workspace.setFindingId(finding.id)}>
                  <td><Sev value={finding.severity}/></td>
                  <td><div className="cell-main"><Pkg name={finding.package_name} version={finding.package_version}/><small>{finding.ecosystem}{finding.status === "open" && finding.workflow_status !== "open" ? ` · ${decisions[finding.workflow_status]}` : ""}{finding.status === "resolved" ? " · Resolved" : ""}</small></div></td>
                  <td className="col-optional"><div className="cell-main"><span>{names.get(finding.project_id) ?? "—"}</span><span className="path" title={finding.target_path}>{finding.target_path}</span></div></td>
                  <td className="col-optional"><span className="mono">{primaryAdvisory(finding.advisory_ids)}</span>{finding.advisory_ids.length > 1 && <span className="muted"> +{finding.advisory_ids.length - 1}</span>}</td>
                  <td>{finding.fixed_versions[0] ? <span className="mono">{finding.fixed_versions[0]}</span> : <span className="muted">None yet</span>}</td>
                  <td className="col-optional"><span className="signal-cell">{finding.kev_known && <span className="tag tag-kev">KEV</span>}{finding.epss_score !== null && <span className="epss">EPSS {(finding.epss_score * 100).toFixed(1)}%</span>}{!finding.kev_known && finding.epss_score === null && <span className="muted">—</span>}</span></td>
                  <td className="col-optional muted">{relativeTime(now, finding.first_seen_at)}</td>
                  <td className="right">{finding.status === "open" && finding.workflow_status === "open" && <button className="btn btn-ghost btn-sm row-action" onClick={(event) => { event.stopPropagation(); void actions.acknowledge(finding); }} title="Acknowledge: mute alerts while you work on it"><Icon name="check" size={14}/>Ack</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {ready && !visible.length && (findings.length
            ? <Empty title="No findings match" text="Change the status, severity, or search filters to widen the list."/>
            : <Empty title="No findings yet" text="Upload a lockfile or connect a pipeline. Findings appear here as soon as the first scan completes."/>)}
        </div>
        {visible.length > limit && <div className="sheet-foot"><span>Showing {limit} of {visible.length}</span><button className="btn btn-secondary btn-sm" onClick={() => setLimit(limit + 100)}>Show 100 more</button></div>}
      </Sheet>
    </>
  );
}
