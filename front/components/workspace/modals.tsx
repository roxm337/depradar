"use client";

import { useState, type DragEvent, type FormEvent } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { bytes, inventoryKind, supportedInventory, tokenPresets } from "@/components/workspace/format";
import { CopyButton, Modal, Pkg, Segmented } from "@/components/workspace/ui";
import type { CreatedApiToken } from "@/lib/api";

export function Modals() {
  const { modal, setModal } = useWorkspace();
  const close = () => setModal(null);
  if (!modal) return null;
  if (modal.kind === "project") return <ProjectModal onClose={close}/>;
  if (modal.kind === "upload") return <UploadModal onClose={close} initialProject={modal.projectId}/>;
  if (modal.kind === "risk") return <RiskModal onClose={close} findingId={modal.findingId}/>;
  if (modal.kind === "connector") return modal.channel === "email" ? <EmailModal onClose={close}/> : <TelegramModal onClose={close}/>;
  return <TokenModal onClose={close}/>;
}

function ProjectModal({ onClose }: { onClose: () => void }) {
  const { actions } = useWorkspace();
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    if (await actions.createProject(String(form.get("name") ?? "").trim(), String(form.get("description") ?? "").trim())) onClose();
    setBusy(false);
  }
  return (
    <Modal title="New project" description="One project per client application or repository." onClose={onClose}>
      <form onSubmit={submit}>
        <div className="modal-body">
          <label className="field"><span className="field-label">Name</span><input className="input" name="name" required maxLength={120} placeholder="acme/storefront" autoFocus/><span className="field-hint">Use the repository name so CI pipelines can find it automatically.</span></label>
          <label className="field"><span className="field-label">Description <span>Optional</span></span><textarea className="textarea" name="description" maxLength={1000} placeholder="What the project is and who owns it"/></label>
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy && <span className="spinner"/>}Create project</button></div>
      </form>
    </Modal>
  );
}

function UploadModal({ onClose, initialProject }: { onClose: () => void; initialProject?: string }) {
  const { projects, actions } = useWorkspace();
  const [projectId, setProjectId] = useState(initialProject ?? projects[0]?.id ?? "");
  const [file, setFile] = useState<File | null>(null);
  const [targetPath, setTargetPath] = useState("");
  const [revision, setRevision] = useState("");
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const valid = file ? supportedInventory(file.name) : false;

  function choose(next: File | undefined) {
    if (!next) return;
    setFile(next);
    // Default the manifest path to the file name; monorepos refine it to the real path.
    setTargetPath((current) => current || next.name);
  }
  function drop(event: DragEvent<HTMLLabelElement>) { event.preventDefault(); setOver(false); choose(event.dataTransfer.files[0]); }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || !valid || !projectId) return;
    setBusy(true);
    if (await actions.uploadInventory({ projectId, file, targetPath, revision })) onClose();
    setBusy(false);
  }

  return (
    <Modal title="Upload a manifest" description="A lockfile or SBOM is stored as an immutable snapshot and scanned right away." onClose={onClose}>
      <form onSubmit={submit}>
        <div className="modal-body">
          {projects.length ? <label className="field"><span className="field-label">Project</span><select className="select" value={projectId} onChange={(event) => setProjectId(event.target.value)}>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label> : <div className="callout"><Icon name="box" size={16}/>Create a project first, then upload its lockfile.</div>}
          <label className={`dropzone ${over ? "is-over" : ""} ${file && valid ? "has-file" : ""}`} onDragOver={(event) => { event.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={drop}>
            <input type="file" accept=".json,.lock,.yaml,.txt,.toml,.mod" onChange={(event) => choose(event.target.files?.[0])}/>
            <Icon name={file ? "file" : "upload"} size={22}/>
            {file ? <><b>{file.name}</b><small>{bytes(file.size)} · {valid ? inventoryKind(file.name) : "Unsupported file type"}</small></> : <><b>Drop a lockfile here, or browse</b><small>npm, pnpm, Yarn, Bun, Composer, Poetry, uv, pip, Pipenv, Bundler, Cargo, Go, Pub, or CycloneDX · up to 10 MB</small></>}
          </label>
          {file && !valid && <div className="callout is-danger"><Icon name="warning" size={16}/>DepRadar accepts lockfiles and CycloneDX SBOMs. Manifests without pinned versions, such as package.json, cannot be scanned reliably.</div>}
          <div className="form-row">
            <label className="field"><span className="field-label">Manifest path <span>Optional</span></span><input className="input mono" value={targetPath} onChange={(event) => setTargetPath(event.target.value)} maxLength={512} placeholder="apps/web/pnpm-lock.yaml"/></label>
            <label className="field"><span className="field-label">Revision <span>Optional</span></span><input className="input mono" value={revision} onChange={(event) => setRevision(event.target.value)} maxLength={200} placeholder="main@4f2a9c1"/></label>
          </div>
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy || !file || !valid || !projectId}>{busy ? <span className="spinner"/> : <Icon name="upload" size={15}/>}Upload and scan</button></div>
      </form>
    </Modal>
  );
}

const riskPresets = [{ value: "7", label: "7 days" }, { value: "30", label: "30 days" }, { value: "90", label: "90 days" }, { value: "custom", label: "Custom" }];
const daysFromNow = (days: number) => new Date(Date.now() + days * 86_400_000);

function RiskModal({ onClose, findingId }: { onClose: () => void; findingId: string }) {
  const { findings, actions } = useWorkspace();
  const finding = findings.find((row) => row.id === findingId);
  const [preset, setPreset] = useState("30");
  const [busy, setBusy] = useState(false);
  if (!finding) return null;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!finding) return;
    const form = new FormData(event.currentTarget);
    const expires = preset === "custom" ? new Date(String(form.get("expiry"))) : daysFromNow(Number(preset));
    setBusy(true);
    if (await actions.acceptRisk(finding, String(form.get("reason") ?? "").trim(), expires.toISOString())) onClose();
    setBusy(false);
  }
  return (
    <Modal title="Accept risk temporarily" description="The finding stays open and visible, but alerts and CI gates ignore it until the acceptance expires." onClose={onClose}>
      <form onSubmit={submit}>
        <div className="modal-body">
          <div className="callout"><Icon name="shield" size={16}/><span><Pkg name={finding.package_name} version={finding.package_version}/> · {finding.advisory_ids.join(", ")}</span></div>
          <label className="field"><span className="field-label">Reason</span><textarea className="textarea" name="reason" required maxLength={2000} placeholder="Why the risk is acceptable for now, and what will change it" autoFocus/></label>
          <div className="field"><span className="field-label">Expires after</span><Segmented label="Expiry" value={preset} onChange={setPreset} options={riskPresets}/></div>
          {preset === "custom" && <label className="field"><span className="field-label">Expiry date</span><input className="input" type="datetime-local" name="expiry" required/><span className="field-hint">Up to 365 days from now.</span></label>}
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy && <span className="spinner"/>}Record acceptance</button></div>
      </form>
    </Modal>
  );
}

function EmailModal({ onClose }: { onClose: () => void }) {
  const { connectors, actions } = useWorkspace();
  const existing: Record<string, string | number | boolean> = connectors.find((connector) => connector.id === "email")?.config ?? {};
  const [step, setStep] = useState<"configure" | "verify">("configure");
  const [busy, setBusy] = useState(false);
  async function configure(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    const sent = await actions.configureEmail({ host: String(form.get("host")), port: Number(form.get("port")), username: String(form.get("username") ?? ""), sender: String(form.get("sender")), recipient: String(form.get("recipient")), tls_mode: String(form.get("tls_mode")) });
    setBusy(false);
    if (sent) setStep("verify");
  }
  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    if (await actions.verifyEmail(String(new FormData(event.currentTarget).get("code") ?? "").trim())) onClose();
    setBusy(false);
  }
  return (
    <Modal title={step === "configure" ? "Email destination" : "Verify the address"} description={step === "configure" ? "Alerts are sent through your SMTP server. The password stays in the backend environment as DEPRADAR_SMTP_PASSWORD." : "Enter the code DepRadar just sent. It expires after 15 minutes."} onClose={onClose} steps={[step === "configure" ? 1 : 2, 2]}>
      {step === "configure" ? (
        <form onSubmit={configure}>
          <div className="modal-body">
            <div className="form-row">
              <label className="field"><span className="field-label">SMTP host</span><input className="input" name="host" required defaultValue={String(existing.host ?? "")} placeholder="smtp.example.com" autoFocus/></label>
              <label className="field"><span className="field-label">Port</span><input className="input" name="port" type="number" min={1} max={65535} required defaultValue={Number(existing.port ?? 587)}/></label>
            </div>
            <div className="form-row">
              <label className="field"><span className="field-label">Security</span><select className="select" name="tls_mode" defaultValue={String(existing.tls_mode ?? "starttls")}><option value="starttls">STARTTLS</option><option value="tls">TLS</option></select></label>
              <label className="field"><span className="field-label">Username <span>Optional</span></span><input className="input" name="username" defaultValue={String(existing.username ?? "")}/></label>
            </div>
            <div className="form-row">
              <label className="field"><span className="field-label">From</span><input className="input" name="sender" type="email" required defaultValue={String(existing.sender ?? "")} placeholder="radar@agency.example"/></label>
              <label className="field"><span className="field-label">Send alerts to</span><input className="input" name="recipient" type="email" required defaultValue={String(existing.recipient ?? "")} placeholder="security@agency.example"/></label>
            </div>
          </div>
          <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy && <span className="spinner"/>}Send verification code</button></div>
        </form>
      ) : (
        <form onSubmit={verify}>
          <div className="modal-body"><label className="field"><span className="field-label">Verification code</span><input className="input mono" name="code" required minLength={8} maxLength={100} autoComplete="one-time-code" autoFocus/></label></div>
          <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={() => setStep("configure")}>Back</button><button className="btn btn-primary" disabled={busy}>{busy && <span className="spinner"/>}Verify email</button></div>
        </form>
      )}
    </Modal>
  );
}

function TelegramModal({ onClose }: { onClose: () => void }) {
  const { actions } = useWorkspace();
  const [command, setCommand] = useState("");
  const [busy, setBusy] = useState(false);
  async function start() { setBusy(true); setCommand((await actions.pairTelegram()) ?? ""); setBusy(false); }
  async function confirm() { setBusy(true); if (await actions.confirmTelegram()) onClose(); setBusy(false); }
  return (
    <Modal title="Telegram chat" description="Pair a private chat with your own bot. Its token stays in the backend environment as DEPRADAR_TELEGRAM_BOT_TOKEN." onClose={onClose} steps={[command ? 2 : 1, 2]}>
      <div className="modal-body">
        {command ? <>
          <div className="secret"><small>Send this message to your bot in a private chat within 15 minutes</small><code>{command}</code><div><CopyButton value={command} label="Copy command"/></div></div>
          <p className="field-hint">Group chats are ignored. DepRadar only reads the pairing command; the bot never accepts other instructions.</p>
        </> : <div className="callout"><Icon name="send" size={16}/>DepRadar generates a one-time command. Sending it from your private chat proves you own the destination.</div>}
      </div>
      <div className="modal-foot"><button className="btn btn-ghost" onClick={onClose}>Cancel</button>{command ? <button className="btn btn-primary" disabled={busy} onClick={() => void confirm()}>{busy && <span className="spinner"/>}I sent it</button> : <button className="btn btn-primary" disabled={busy} onClick={() => void start()}>{busy && <span className="spinner"/>}Start pairing</button>}</div>
    </Modal>
  );
}

const expiries = [{ value: "30", label: "30 days" }, { value: "90", label: "90 days" }, { value: "180", label: "180 days" }, { value: "365", label: "1 year" }];

function TokenModal({ onClose }: { onClose: () => void }) {
  const { projects, actions, notify, reload } = useWorkspace();
  const [preset, setPreset] = useState("pipeline");
  const [projectId, setProjectId] = useState("");
  const [expiry, setExpiry] = useState("90");
  const [created, setCreated] = useState<CreatedApiToken | null>(null);
  const [busy, setBusy] = useState(false);
  const restrictedConflict = Boolean(projectId) && tokenPresets[preset].scopes.includes("projects:write");
  function finish() { if (created) void reload(); onClose(); }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (restrictedConflict) { notify("error", "Tokens that create projects must cover every project."); return; }
    setBusy(true);
    setCreated(await actions.createToken({ name: String(new FormData(event.currentTarget).get("name") ?? "").trim(), scopes: tokenPresets[preset].scopes, project_id: projectId || null, expires_in_days: Number(expiry) }));
    setBusy(false);
  }
  if (created) {
    return (
      <Modal title="Copy your token now" description="It is shown once. DepRadar stores only a hash, so a lost token must be replaced." onClose={finish} steps={[2, 2]}>
        <div className="modal-body">
          <div className="secret"><small>{created.name} · expires {new Date(created.expires_at).toLocaleDateString()}</small><code>{created.token}</code><div><CopyButton value={created.token} label="Copy token"/></div></div>
          <div className="callout"><Icon name="key" size={16}/><span>Save it as a masked CI secret named <span className="inline-code">DEPRADAR_TOKEN</span>. Scopes: {created.scopes.join(", ")}.</span></div>
        </div>
        <div className="modal-foot"><button className="btn btn-primary" onClick={finish}><Icon name="check" size={15}/>Done</button></div>
      </Modal>
    );
  }
  return (
    <Modal title="New CI/CD token" description="Pipelines use tokens to upload lockfiles and evaluate the dependency gate." onClose={onClose} steps={[1, 2]}>
      <form onSubmit={submit}>
        <div className="modal-body">
          <label className="field"><span className="field-label">Name</span><input className="input" name="name" required maxLength={100} placeholder="acme-storefront · GitHub Actions" autoFocus/></label>
          <div className="field"><span className="field-label">Access</span><div className="choice-list" role="radiogroup" aria-label="Access">{Object.entries(tokenPresets).map(([key, value]) => <button key={key} type="button" role="radio" className="choice" aria-checked={preset === key} onClick={() => setPreset(key)}><span className="radio"/><b>{value.label}</b><small>{value.detail}</small></button>)}</div></div>
          <div className="form-row">
            <label className="field"><span className="field-label">Project</span><select className="select" value={projectId} onChange={(event) => setProjectId(event.target.value)}><option value="">All projects</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>
            <div className="field"><span className="field-label">Expires after</span><select className="select" value={expiry} onChange={(event) => setExpiry(event.target.value)}>{expiries.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></div>
          </div>
          {restrictedConflict && <div className="callout is-danger"><Icon name="warning" size={16}/>Project onboarding needs a token that covers every project. Choose “All projects” or another access level.</div>}
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy || restrictedConflict}>{busy && <span className="spinner"/>}Create token</button></div>
      </form>
    </Modal>
  );
}
