"use client";

import Link from "next/link";
import { useState } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { cadence, countBySeverity, monogram, relativeTime, scanLabel, scanTone, severityRank } from "@/components/workspace/format";
import { Empty, PageHead, Segmented, Sheet, SkeletonRows, StackBar, Switch } from "@/components/workspace/ui";

type Sort = "exposure" | "name" | "recent";

export default function ProjectsPage() {
  const workspace = useWorkspace();
  const { projects, findings, scans, inventories, now, ready, actions } = workspace;
  const [sort, setSort] = useState<Sort>("exposure");
  const rows = projects.map((project) => {
    const open = findings.filter((finding) => finding.project_id === project.id && finding.status === "open");
    const manifests = [...new Map(inventories.filter((row) => row.project_id === project.id).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).map((row) => [row.target_path, row])).values()];
    return { project, open, counts: countBySeverity(open), manifests, scan: scans.find((scan) => scan.project_id === project.id), weight: open.reduce((sum, finding) => sum + 10 ** severityRank(finding.severity), 0) };
  }).sort((a, b) => sort === "name" ? a.project.name.localeCompare(b.project.name) : sort === "recent" ? Date.parse(b.scan?.created_at ?? b.project.created_at) - Date.parse(a.scan?.created_at ?? a.project.created_at) : b.weight - a.weight || a.project.name.localeCompare(b.project.name));
  const monitored = projects.filter((project) => project.monitoring_enabled).length;
  const manifestCount = rows.reduce((sum, row) => sum + row.manifests.length, 0);

  return (
    <>
      <PageHead eyebrow="Monitor" title="Projects" lede={<><strong>{projects.length}</strong> projects · {monitored} with scheduled rechecks · {manifestCount} monitored manifests. Open a project to manage its manifests, scans, and alerts.</>} actions={<><button className="btn btn-secondary" onClick={() => workspace.setModal({ kind: "upload" })}><Icon name="upload" size={15}/>Upload manifest</button><button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "project" })}><Icon name="plus" size={15}/>New project</button></>}/>
      <div className="toolbar"><Segmented label="Sort projects" value={sort} onChange={setSort} options={[{ value: "exposure", label: "Most exposed" }, { value: "recent", label: "Recently scanned" }, { value: "name", label: "Name" }]}/></div>
      <Sheet>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Project</th><th>Exposure</th><th className="col-optional">Manifests</th><th className="col-optional">Last scan</th><th>Monitoring</th><th className="col-optional">Alerts</th><th className="col-optional" aria-label="Open"/></tr></thead>
            <tbody>
              {!ready ? <SkeletonRows rows={5} columns={7}/> : rows.map(({ project, open, counts, manifests, scan }) => (
                <tr key={project.id} className="is-link" onClick={() => workspace.setProjectId(project.id)}>
                  <td><div className="project-name"><span className="monogram">{monogram(project.name)}</span><div className="cell-main"><b>{project.name}</b><small>{project.description || "No description"}</small></div></div></td>
                  <td><div className="cell-main"><StackBar counts={counts} total={open.length}/><small>{open.length ? `${open.length} open · ${counts.critical + counts.high} critical or high` : "No open findings"}</small></div></td>
                  <td className="col-optional"><div className="cell-main"><span>{manifests.length || "None"}</span><small>{manifests[0] ? `newest ${relativeTime(now, manifests[0].created_at)}` : "Upload a lockfile"}</small></div></td>
                  <td className="col-optional">{scan ? <div className="cell-main"><span className="status"><i className={`dot ${scanTone(scan)}`}/>{scanLabel(scan)}</span><small>{relativeTime(now, scan.created_at)}{scan.mode === "check" ? " · CI check" : ""}</small></div> : <span className="muted">Never</span>}</td>
                  <td><span className="project-name"><Switch checked={project.monitoring_enabled} label={`Monitoring for ${project.name}`} onChange={(enabled) => void actions.setMonitoring(project, enabled, project.check_interval_hours)}/><small className="muted">{project.monitoring_enabled ? cadence(project.check_interval_hours) : "paused"}</small></span></td>
                  <td className="col-optional muted">{project.notifications_enabled ? (project.alert_min_severity ? `${project.alert_min_severity} and above` : "Workspace policy") : "Off"}</td>
                  <td className="right col-optional"><Icon name="chevron" size={16}/></td>
                </tr>
              ))}
            </tbody>
          </table>
          {ready && !projects.length && <Empty title="No projects yet" text="Create one project per client application or repository. Pipelines can also create projects automatically with an onboarding token." action={<button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "project" })}><Icon name="plus" size={15}/>New project</button>}/>}
        </div>
      </Sheet>
      <div className="callout page-note"><Icon name="branch" size={16}/><span>Keep every project current without manual uploads: add the DepRadar step to each client pipeline. Default-branch runs update monitored manifests; pull requests are gated without changing them. <Link className="link" href="/settings#ci">Set up CI/CD access</Link></span></div>
    </>
  );
}
