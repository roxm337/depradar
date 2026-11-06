"use client";

import { useEffect, useState, type FormEvent } from "react";
import "./policies.css";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { ConfirmDialog, Dialog } from "@/components/workspace/drawer-dialog";
import { dateTime, relativeTime } from "@/components/workspace/format";
import { DEFAULT_RULES, describeChanges, isPermissive, mergeRules, normalizeRules, rulesEqual, summarizeRules } from "@/components/workspace/policy-logic";
import { Portal } from "@/components/workspace/portal";
import { RuleEditor, rulesProblem } from "@/components/workspace/rule-editor";
import { Empty, PageHead, Sheet, SkeletonRows } from "@/components/workspace/ui";
import { api, type PolicyRules, type PolicyVersion, type Project, type ProjectPolicy } from "@/lib/api";

export default function PoliciesPage() {
  const workspace = useWorkspace();
  const { policies, projects, features, ready } = workspace;
  const [editing, setEditing] = useState<{ project: Project | null; rules: PolicyRules } | null>(null);
  const [removing, setRemoving] = useState<ProjectPolicy | null>(null);
  const installation = policies.installation.rules ?? DEFAULT_RULES;
  const names = new Map(projects.map((project) => [project.id, project]));
  const overrides = policies.projects.filter((row) => row.policy.rules && names.has(row.project_id)).sort((a, b) => (names.get(a.project_id)?.name ?? "").localeCompare(names.get(b.project_id)?.name ?? ""));
  const free = projects.filter((project) => !overrides.some((row) => row.project_id === project.id));

  return (
    <>
      <PageHead title="Policies" lede="The security rules a pipeline run must meet to pass its DepRadar check (the gate). Pipelines can make these rules stricter, never looser. Each save creates a numbered version, and every gate decision records the version it used."/>
      <div className="policy-page">
      {!features.policies && <div className="callout"><Icon name="warning" size={16}/><span>Your DepRadar server runs an older version that does not enforce these policies, so each pipeline still uses only its own settings. Rebuild with <span className="inline-code">docker compose up --build -d api worker</span> to enable them.</span></div>}
      <PolicyFlow installation={installation} version={policies.installation.version} overrides={overrides.length}/>
      {ready ? <InstallationEditor key={`${policies.installation.id ?? "default"}-${policies.installation.version}`} policy={policies.installation} disabled={!features.policies}/> : <Sheet title="Global policy"><div className="sheet-body"><span className="skeleton" style={{ width: "40%" }}/></div></Sheet>}
      <Sheet title="Project policies" meta={overrides.length ? `${overrides.length} ${overrides.length === 1 ? "project adds" : "projects add"} stricter rules` : "Every project follows the global policy"}
        actions={<button className="btn btn-secondary btn-sm" disabled={!features.policies || !free.length} onClick={() => setEditing({ project: null, rules: DEFAULT_RULES })}><Icon name="plus" size={14}/>Add project policy</button>}>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Project</th><th>Adds</th><th className="col-optional">Rules applied</th><th className="col-optional">Version</th><th className="col-optional">Updated</th><th aria-label="Actions"/></tr></thead>
            <tbody>
              {!ready ? <SkeletonRows rows={2} columns={6}/> : overrides.map((row) => {
                const project = names.get(row.project_id);
                if (!project || !row.policy.rules) return null;
                return (
                  <tr key={row.project_id}>
                    <td className="nowrap"><b>{project.name}</b></td>
                    <td>{summarizeRules(row.policy.rules)}</td>
                    <td className="col-optional muted">{summarizeRules(row.effective)}</td>
                    <td className="col-optional num">v{row.policy.version}</td>
                    <td className="col-optional muted nowrap" title={dateTime(row.policy.created_at)}>{relativeTime(workspace.now, row.policy.created_at)}</td>
                    <td className="right"><div className="row-actions">
                      <button className="btn btn-ghost btn-sm" onClick={() => setEditing({ project, rules: row.policy.rules ?? DEFAULT_RULES })}>Edit</button>
                      <button className="btn btn-ghost btn-sm" onClick={() => setRemoving(row)}>Remove</button>
                    </div></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {ready && !overrides.length && <Empty icon="lock" title="No project policies" text="Add one when a client needs stricter rules than the global policy, such as complete coverage for a regulated application." action={projects.length ? <button className="btn btn-secondary" disabled={!features.policies} onClick={() => setEditing({ project: null, rules: DEFAULT_RULES })}><Icon name="plus" size={15}/>Add project policy</button> : undefined}/>}
        </div>
      </Sheet>
      </div>
      {editing && <Portal><ProjectPolicyDialog initial={editing} available={free} installation={installation} onClose={() => setEditing(null)}/></Portal>}
      {removing && <Portal><RemoveDialog row={removing} project={names.get(removing.project_id)} installation={installation} onClose={() => setRemoving(null)}/></Portal>}
    </>
  );
}

/** Pipeline settings → global → project → applied: how the gate is assembled. */
function PolicyFlow({ installation, version, overrides }: { installation: PolicyRules; version: number; overrides: number }) {
  const steps = [
    { icon: "branch", title: "Pipeline settings", text: "Options such as --fail-on in each job" },
    { icon: "shield", title: "Global policy", text: isPermissive(installation) ? "No requirements yet" : summarizeRules(installation), meta: version ? `v${version}` : "default" },
    { icon: "box", title: "Project policies", text: overrides ? `${overrides} ${overrides === 1 ? "project adds" : "projects add"} rules` : "None yet" },
    { icon: "check-circle", title: "Rules applied", text: "The strictest setting of each rule wins" },
  ];
  return (
    <ol className="policy-flow" aria-label="How the rules applied to a pipeline run are built">
      {steps.map((step, index) => (
        <li key={step.title} className={index === steps.length - 1 ? "is-result" : ""}>
          <span className="policy-flow-icon" aria-hidden="true"><Icon name={step.icon} size={15}/></span>
          <span className="policy-flow-copy"><b>{step.title}{step.meta && <small className="tag tag-mono">{step.meta}</small>}</b><small title={step.text}>{step.text}</small></span>
          {index < steps.length - 1 && <Icon name="arrow" size={14}/>}
        </li>
      ))}
    </ol>
  );
}

function InstallationEditor({ policy, disabled }: { policy: PolicyVersion; disabled: boolean }) {
  const { actions, now } = useWorkspace();
  const saved = policy.rules ?? DEFAULT_RULES;
  const [draft, setDraft] = useState<PolicyRules>(saved);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState(false);
  const dirty = !rulesEqual(draft, saved);
  const problem = rulesProblem(draft);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!dirty || problem) return;
    setBusy(true);
    await actions.saveInstallationPolicy(draft, note.trim());
    setBusy(false);
  }
  return (
    <Sheet title="Global policy" meta={policy.version ? <>Version {policy.version} · saved <time dateTime={policy.created_at ?? undefined} title={dateTime(policy.created_at)}>{relativeTime(now, policy.created_at)}</time></> : "Never saved · applies to every project"}
      actions={<button className="btn btn-ghost btn-sm" aria-expanded={history} onClick={() => setHistory(!history)} disabled={!policy.version}><Icon name="clock" size={14}/>{history ? "Hide history" : "History"}</button>}>
      <form className="sheet-body policy-form" onSubmit={submit}>
        <fieldset disabled={disabled || busy} className="policy-fieldset">
          <legend className="sr-only">Global policy rules</legend>
          <RuleEditor idPrefix="installation" value={draft} onChange={setDraft}/>
          <label className="field"><span className="field-label">Change note <span>Optional, shown in the version history</span></span><input className="input" maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Why this change? For example: client contract requires KEV blocking"/></label>
        </fieldset>
        <div className="policy-foot">
          <span className="field-hint" aria-live="polite">{dirty ? <>Not saved yet: {summarizeRules(draft)}</> : <>Current: {summarizeRules(saved)}</>}</span>
          {dirty && <button type="button" className="btn btn-ghost" onClick={() => { setDraft(saved); setNote(""); }}>Discard</button>}
          <button className="btn btn-primary" disabled={disabled || busy || !dirty || Boolean(problem)}>{busy && <span className="spinner"/>}Save as version {policy.version + 1}</button>
        </div>
      </form>
      {history && <VersionHistory projectId={null}/>}
    </Sheet>
  );
}

function VersionHistory({ projectId }: { projectId: string | null }) {
  const { now } = useWorkspace();
  const [rows, setRows] = useState<PolicyVersion[] | null>(null);
  const [failed, setFailed] = useState("");
  useEffect(() => {
    let active = true;
    api<PolicyVersion[]>(`policies/versions${projectId ? `?project_id=${encodeURIComponent(projectId)}` : ""}`)
      .then((values) => { if (active) setRows(values.map((row) => ({ ...row, rules: row.rules ? normalizeRules(row.rules) : null }))); })
      .catch((failure: unknown) => { if (active) setFailed(failure instanceof Error ? failure.message : "Could not load the history."); });
    return () => { active = false; };
  }, [projectId]);
  return (
    <div className="policy-history sheet-foot">
      <h3 className="block-title">Version history</h3>
      {failed ? <p className="field-error"><Icon name="warning" size={13}/>{failed}</p>
        : rows === null ? <div className="policy-history-loading"><span className="skeleton" style={{ width: "55%" }}/><span className="skeleton" style={{ width: "40%" }}/></div>
          : !rows.length ? <p className="muted">No versions saved yet.</p>
            : <ol className="timeline">{rows.map((row, index) => (
              <li className="timeline-item" key={row.id ?? row.version}>
                <span className={`dot ${index === 0 ? "dot-ok" : ""}`}/>
                <div>
                  <b>Version {row.version}{index === 0 && <span className="tag tag-ok">Current</span>}</b>
                  {describeChanges(rows[index + 1]?.rules ?? null, row.rules).map((change) => <p key={change}>{change}</p>)}
                  {row.note && <p className="timeline-note">“{row.note}”</p>}
                </div>
                <time dateTime={row.created_at ?? undefined} title={dateTime(row.created_at)}>{relativeTime(now, row.created_at)}</time>
              </li>
            ))}</ol>}
    </div>
  );
}

function ProjectPolicyDialog({ initial, available, installation, onClose }: { initial: { project: Project | null; rules: PolicyRules }; available: Project[]; installation: PolicyRules; onClose: () => void }) {
  const { actions } = useWorkspace();
  const [projectId, setProjectId] = useState(initial.project?.id ?? "");
  const [draft, setDraft] = useState<PolicyRules>(initial.rules);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const project = initial.project ?? available.find((row) => row.id === projectId) ?? null;
  const effective = mergeRules(installation, draft);
  const problem = rulesProblem(draft, installation);
  const adds = !rulesEqual(effective, mergeRules(installation, null));
  const unchanged = Boolean(initial.project) && rulesEqual(draft, initial.rules);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!project || problem || !adds || unchanged) return;
    setBusy(true);
    if (await actions.saveProjectPolicy(project, draft, note.trim())) onClose();
    setBusy(false);
  }
  return (
    <Dialog title={initial.project ? `Policy for ${initial.project.name}` : "Add a project policy"} description="A project policy adds stricter rules on top of the global policy. Rules the global policy already sets are locked." onClose={onClose}>
      <form onSubmit={submit}>
        <div className="modal-body dialog-scroll">
          {!initial.project && <label className="field"><span className="field-label">Project</span><select className="select" required value={projectId} onChange={(event) => setProjectId(event.target.value)}><option value="" disabled>Choose a project</option>{available.map((row) => <option key={row.id} value={row.id}>{row.name}</option>)}</select></label>}
          <RuleEditor idPrefix="project" value={draft} onChange={setDraft} floor={installation} autoFocus={Boolean(initial.project)}/>
          <label className="field"><span className="field-label">Change note <span>Optional</span></span><input className="input" maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} placeholder="For example: regulated client, every manifest must be scanned"/></label>
          <div className={`callout ${adds ? "" : "is-quiet"}`} aria-live="polite"><Icon name="check-circle" size={16}/><span>{adds ? <>Pipelines of {project?.name ?? "this project"} will have to meet at least: <b>{summarizeRules(effective)}</b>.</> : "Nothing here is stricter than the global policy yet. Turn on a rule or choose a lower severity to add one."}</span></div>
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy || !project || Boolean(problem) || !adds || unchanged}>{busy && <span className="spinner"/>}{initial.project ? "Save new version" : "Add policy"}</button></div>
      </form>
    </Dialog>
  );
}

function RemoveDialog({ row, project, installation, onClose }: { row: ProjectPolicy; project: Project | undefined; installation: PolicyRules; onClose: () => void }) {
  const { actions } = useWorkspace();
  const [busy, setBusy] = useState(false);
  if (!project) return null;
  return (
    <ConfirmDialog title={`Remove the policy for ${project.name}?`} confirmLabel="Remove policy" busy={busy} onClose={onClose} onConfirm={async () => { setBusy(true); if (await actions.saveProjectPolicy(project, null, "Removed project policy")) onClose(); setBusy(false); }}>
      <p>Its pipelines will follow the global policy: <b>{summarizeRules(installation)}</b>.</p>
      <p className="muted">The removal is saved as version {row.policy.version + 1}. Past gate decisions still show the version they used.</p>
    </ConfirmDialog>
  );
}
