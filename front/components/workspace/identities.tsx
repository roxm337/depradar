"use client";

import { useState, type FormEvent } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { ConfirmDialog, Dialog } from "@/components/workspace/drawer-dialog";
import { dateTime, projectName, relativeTime } from "@/components/workspace/format";
import { DEFAULT_ISSUER, githubSnippet, gitlabSnippet, identityState, normalizeRef, providerName, refLabel, REPOSITORY_PLACEHOLDER, repositoryProblem, WORKFLOW_PLACEHOLDER } from "@/components/workspace/policy-logic";
import { Portal } from "@/components/workspace/portal";
import { CopyButton, Empty, Segmented, Sheet } from "@/components/workspace/ui";
import type { IdentityProvider, TrustedIdentity } from "@/lib/api";
import "./identities.css";

export function IdentitiesSection() {
  const { identities, projects, features, now, origin } = useWorkspace();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<TrustedIdentity | null>(null);
  const rows = [...identities.identities].sort((a, b) => Number(Boolean(a.disabled_at)) - Number(Boolean(b.disabled_at)) || a.repository.localeCompare(b.repository));
  const active = rows.filter((row) => !row.disabled_at).length;
  const url = `${origin || "https://depradar.example.com"}/api/backend`;
  const audience = identities.audience || origin || "";

  return (
    <>
      <div className="section-intro"><h2>Trusted identities</h2><p>GitHub Actions and GitLab CI sign in with the short-lived OIDC token every job can request, so there is no long-lived secret to leak or rotate. Pull and merge request runs only get check access; only the trusted branch and workflow can update monitored manifests.</p></div>
      {!features.identities && <div className="callout"><Icon name="warning" size={16}/><span>This API build does not accept OIDC identities yet. Rebuild with <span className="inline-code">docker compose up --build -d api worker</span> to enable them; tokens keep working meanwhile.</span></div>}
      <div className="identity-steps" aria-label="How a pipeline signs in">
        <div><span className="identity-step">1</span><b>The job requests an OIDC token</b><small>for this installation’s audience</small></div>
        <div><span className="identity-step">2</span><b>DepRadar verifies it</b><small>issuer signature, repository, workflow, and branch</small></div>
        <div><span className="identity-step">3</span><b>The job gets 30 minutes of access</b><small>to one project: check, or monitor on the trusted branch</small></div>
      </div>
      <Sheet title="Audience" meta="Pipelines request their OIDC token for this value">
        <div className="sheet-body identity-audience">
          {audience ? <><code className="mono">{audience}</code><CopyButton value={audience} label="Copy audience"/></> : <span className="muted">Shown once the API reports it.</span>}
        </div>
      </Sheet>
      <Sheet title="Identities" meta={rows.length ? `${active} active` : undefined} actions={<button className="btn btn-primary btn-sm" disabled={!features.identities || !projects.length} onClick={() => setAdding(true)}><Icon name="plus" size={14}/>Add identity</button>}>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Repository</th><th className="col-optional">Project</th><th className="col-optional">Workflow</th><th>Can monitor</th><th className="col-optional">Last used</th><th>Status</th><th aria-label="Actions"/></tr></thead>
            <tbody>{rows.map((row) => {
              const state = identityState(row);
              return (
                <tr key={row.id} className={row.disabled_at ? "is-disabled" : ""}>
                  <td><div className="cell-main"><b className="mono identity-repo" title={row.repository}>{row.repository}</b><small>{providerName(row.provider)} · {row.repository_id ? <>ID <span className="mono">{row.repository_id}</span></> : "ID pinned on first run"}{row.issuer !== DEFAULT_ISSUER[row.provider] ? <> · <span title={row.issuer}>self-hosted</span></> : ""}</small></div></td>
                  <td className="col-optional">{projectName(projects, row.project_id)}</td>
                  <td className="col-optional">{row.workflow ? <span className="mono identity-workflow" title={row.workflow}>{row.workflow}</span> : <span className="muted">Any workflow</span>}</td>
                  <td>{row.monitor_ref ? <span className="mono" title={row.monitor_ref}>{refLabel(row.monitor_ref)}</span> : <span className="tag tag-check">Checks only</span>}</td>
                  <td className="col-optional muted" title={dateTime(row.last_used_at)}>{row.last_used_at ? relativeTime(now, row.last_used_at) : "Never"}</td>
                  <td><span className="status"><i className={`dot ${state === "Active" ? "dot-ok" : ""}`}/>{state}</span></td>
                  <td className="right">{!row.disabled_at && <button className="btn btn-ghost btn-sm" onClick={() => setRemoving(row)}>Remove</button>}</td>
                </tr>
              );
            })}</tbody>
          </table>
          {!rows.length && <Empty icon="lock" title="No trusted identities yet" text={projects.length ? "Bind a repository to a project. Its jobs then sign in with OIDC instead of a stored token." : "Create a project first, then bind its repository here."} action={projects.length ? <button className="btn btn-primary" disabled={!features.identities} onClick={() => setAdding(true)}><Icon name="plus" size={15}/>Add the first identity</button> : undefined}/>}
        </div>
      </Sheet>
      {adding && <Portal><IdentityDialog url={url} audience={audience} onClose={() => setAdding(false)}/></Portal>}
      {removing && <Portal><RemoveIdentity identity={removing} onClose={() => setRemoving(null)}/></Portal>}
    </>
  );
}

function IdentityDialog({ url, audience, onClose }: { url: string; audience: string; onClose: () => void }) {
  const { projects, actions } = useWorkspace();
  const [provider, setProvider] = useState<IdentityProvider>("github");
  const [repository, setRepository] = useState("");
  const [repositoryId, setRepositoryId] = useState("");
  const [workflow, setWorkflow] = useState("");
  const [monitor, setMonitor] = useState(true);
  const [branch, setBranch] = useState("main");
  const [projectId, setProjectId] = useState(projects.length === 1 ? projects[0].id : "");
  const [issuer, setIssuer] = useState("");
  const [name, setName] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<TrustedIdentity | null>(null);
  const problem = repositoryProblem(provider, repository);
  const idProblem = repositoryId.trim() && !/^\d{1,20}$/.test(repositoryId.trim()) ? "Repository IDs are numbers." : null;
  const branchProblem = monitor && !branch.trim() ? "Enter the branch whose runs may update monitored state." : null;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTouched(true);
    if (problem || idProblem || branchProblem || !projectId) return;
    setBusy(true);
    setCreated(await actions.createIdentity({
      project_id: projectId,
      provider,
      repository: repository.trim(),
      repository_id: repositoryId.trim() || null,
      workflow: workflow.trim() || null,
      monitor_ref: monitor ? normalizeRef(branch) : null,
      issuer: issuer.trim() || DEFAULT_ISSUER[provider],
      ...(name.trim() ? { name: name.trim() } : {}),
    }));
    setBusy(false);
  }

  if (created) {
    const snippet = created.provider === "github" ? githubSnippet(url) : gitlabSnippet(url, audience);
    return (
      <Dialog title="Connect the pipeline" description={`${created.repository} is trusted for ${projectName(projects, created.project_id)}. Add this to its CI configuration.`} onClose={onClose} steps={[2, 2]}>
        <div className="modal-body">
          <div className="field"><span className="field-label">{created.provider === "github" ? "GitHub Actions workflow" : ".gitlab-ci.yml"}<CopyButton value={snippet}/></span><code className="code">{snippet}</code></div>
          <div className="field"><span className="field-label">Audience<CopyButton value={audience} label="Copy"/></span><code className="code">{audience}</code></div>
          <div className="callout"><Icon name="lock" size={16}/><span>{created.monitor_ref ? <>Runs on <b className="mono">{refLabel(created.monitor_ref)}</b>{created.workflow ? <> from <b className="mono">{created.workflow}</b></> : ""} update monitored manifests. Every other run, including pull and merge requests, is check-only.</> : <>Every run is check-only: it gates the change but never updates monitored manifests.</>}</span></div>
        </div>
        <div className="modal-foot"><button className="btn btn-primary" data-autofocus onClick={onClose}><Icon name="check" size={15}/>Done</button></div>
      </Dialog>
    );
  }

  return (
    <Dialog title="Add a trusted identity" description="Bind a repository’s CI jobs to one project. DepRadar checks every OIDC token against these rules before granting access." onClose={onClose} steps={[1, 2]}>
      <form onSubmit={submit} noValidate>
        <div className="modal-body dialog-scroll">
          <div className="field"><span className="field-label">Provider</span><Segmented label="Provider" value={provider} onChange={(value) => { setProvider(value); setIssuer(""); }} options={[{ value: "github", label: "GitHub Actions" }, { value: "gitlab", label: "GitLab CI" }]}/></div>
          <label className="field"><span className="field-label">DepRadar project</span>
            <select className="select" value={projectId} onChange={(event) => setProjectId(event.target.value)} required aria-invalid={touched && !projectId}>
              <option value="" disabled>Choose a project</option>
              {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
            </select>
            {touched && !projectId && <span className="field-error"><Icon name="warning" size={13}/>Choose the project these jobs may access.</span>}
          </label>
          <label className="field"><span className="field-label">Repository</span>
            <input className="input mono" value={repository} onChange={(event) => setRepository(event.target.value)} placeholder={REPOSITORY_PLACEHOLDER[provider]} required aria-invalid={touched && Boolean(problem)} aria-describedby={touched && problem ? "identity-repository-error" : undefined} autoComplete="off" spellCheck={false}/>
            {touched && problem && <span className="field-error" id="identity-repository-error"><Icon name="warning" size={13}/>{problem}</span>}
          </label>
          <label className="field"><span className="field-label">Repository ID <span>Recommended</span></span>
            <input className="input mono" value={repositoryId} onChange={(event) => setRepositoryId(event.target.value)} inputMode="numeric" placeholder="123456789" aria-invalid={Boolean(idProblem)} aria-describedby="identity-id-hint" autoComplete="off"/>
            <span className={idProblem ? "field-error" : "field-hint"} id="identity-id-hint">{idProblem ?? (provider === "github" ? <>Run <span className="inline-code">gh api repos/OWNER/REPO --jq .id</span>. The ID survives renames and rejects a deleted and re-created repository. Left empty, the first verified run’s ID is pinned.</> : "Shown as Project ID on the GitLab project’s overview page. It survives renames and transfers. Left empty, the first verified run’s ID is pinned.")}</span>
          </label>
          <label className="field"><span className="field-label">Trusted workflow <span>Optional</span></span>
            <input className="input mono" value={workflow} onChange={(event) => setWorkflow(event.target.value)} placeholder={WORKFLOW_PLACEHOLDER[provider]} autoComplete="off" spellCheck={false}/>
            <span className="field-hint">Only this {provider === "github" ? "workflow file" : "CI configuration"} may sign in. Leave it empty to accept any workflow in the repository.</span>
          </label>
          <div className="field">
            <span className="field-label">Monitored state</span>
            <div className="choice-list" role="radiogroup" aria-label="Monitored state">
              <button type="button" role="radio" className="choice" aria-checked={monitor} onClick={() => setMonitor(true)}><span className="radio"/><b>Update it from a protected branch</b><small>Runs on this branch keep manifests current. Pull and merge requests stay check-only.</small></button>
              <button type="button" role="radio" className="choice" aria-checked={!monitor} onClick={() => setMonitor(false)}><span className="radio"/><b>Checks only</b><small>Every run gates the change and nothing updates monitored manifests.</small></button>
            </div>
            {monitor && (
              <label className="identity-branch"><span className="sr-only">Branch</span>
                <span className="muted mono">refs/heads/</span>
                <input className="input mono" value={branch.replace(/^refs\/heads\//, "")} onChange={(event) => setBranch(event.target.value)} placeholder="main" aria-label="Branch" aria-invalid={touched && Boolean(branchProblem)} autoComplete="off" spellCheck={false}/>
              </label>
            )}
            {touched && branchProblem && <span className="field-error"><Icon name="warning" size={13}/>{branchProblem}</span>}
          </div>
          <details className="identity-advanced">
            <summary>Advanced</summary>
            <div className="form-grid">
              <label className="field"><span className="field-label">Issuer <span>{provider === "gitlab" ? "Your GitLab URL when self-hosted" : "GitHub Enterprise Server only"}</span></span><input className="input mono" value={issuer} onChange={(event) => setIssuer(event.target.value)} placeholder={DEFAULT_ISSUER[provider]} autoComplete="off" spellCheck={false}/></label>
              <label className="field"><span className="field-label">Name <span>Optional</span></span><input className="input" value={name} maxLength={100} onChange={(event) => setName(event.target.value)} placeholder={repository.trim() || "acme storefront CI"}/></label>
            </div>
          </details>
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy && <span className="spinner"/>}Add identity</button></div>
      </form>
    </Dialog>
  );
}

function RemoveIdentity({ identity, onClose }: { identity: TrustedIdentity; onClose: () => void }) {
  const { actions, projects } = useWorkspace();
  const [busy, setBusy] = useState(false);
  return (
    <ConfirmDialog title={`Remove ${identity.repository}?`} confirmLabel="Remove identity" busy={busy} onClose={onClose} onConfirm={async () => { setBusy(true); if (await actions.removeIdentity(identity)) onClose(); setBusy(false); }}>
      <p>Its jobs can no longer sign in to {projectName(projects, identity.project_id)}, and access they were granted in the last 30 minutes is revoked now.</p>
      <p className="muted">Recorded decisions keep the verified run details. Pipelines need a token or a new identity to run again.</p>
    </ConfirmDialog>
  );
}
