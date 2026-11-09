"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { copyText } from "@/components/workspace/drawer-parts";
import { dateTime, primaryAdvisory, relativeTime, severityRank } from "@/components/workspace/format";
import { actorLabel, adjustmentParts, eventLabel, intelligenceAge, MODE_LABEL, policyLabel, providerName, refLabel, revisionLabel, shortSha, STATUS_LABEL, STATUS_TAG, STATUS_TONE, summarizeGate } from "@/components/workspace/policy-logic";
import { Drawer, Pkg, Sev } from "@/components/workspace/ui";
import type { DecisionDetail, DecisionSummary, GateItem, ReportFormat, ScanGate } from "@/lib/api";
import "./decision-drawer.css";

const VIOLATION_LIMIT = 20;
const WORKFLOW_LABEL: Record<string, string> = { risk_accepted: "Risk accepted", acknowledged: "Acknowledged", open: "Open" };
const REPORTS: { format: ReportFormat; label: string }[] = [{ format: "sarif", label: "SARIF" }, { format: "junit", label: "JUnit" }, { format: "markdown", label: "Markdown" }];

/** Shows a short hash and copies the full value. */
function HashChip({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(timer);
  }, [copied]);
  return (
    <button type="button" className={`hash-chip ${copied ? "is-copied" : ""}`} title={value} aria-label={`Copy ${label} ${value}`} onClick={() => void copyText(value).then((done) => setCopied(done))}>
      {shortSha(value)}<Icon name={copied ? "check" : "copy"} size={12}/>{copied && <span className="sr-only">Copied</span>}
    </button>
  );
}

export function DecisionDrawer({ summary, onClose }: { summary: DecisionSummary; onClose: () => void }) {
  const { actions } = useWorkspace();
  const [detail, setDetail] = useState<DecisionDetail | null>(null);
  const [failed, setFailed] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    actions.loadDecision(summary.id)
      .then((value) => { if (active) { setDetail(value); setFailed(""); } })
      .catch((failure: unknown) => { if (active) setFailed(failure instanceof Error ? failure.message : "Could not load the decision."); });
    return () => { active = false; };
    // The loader is recreated every render; the decision ID and retries are what matter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary.id, attempt]);

  return (
    <Drawer label={`Gate decision for ${summary.project_name}`} onClose={onClose}>
      <div className="drawer-head">
        <div className="drawer-top">
          <span className={`tag ${STATUS_TAG[summary.status]}`}><i className={`dot ${STATUS_TONE[summary.status]}`}/>{STATUS_LABEL[summary.status]}</span>
          <span className={`tag ${summary.mode === "check" ? "tag-check" : ""}`}>{MODE_LABEL[summary.mode]}</span>
          {summary.actor.verified && <span className="tag tag-ok"><Icon name="shield" size={12}/>Verified run</span>}
          <button className="icon-btn" onClick={onClose} aria-label="Close decision"><Icon name="close"/></button>
        </div>
        <h2 className="drawer-title">{summary.project_name}</h2>
        <span className="drawer-sub">{revisionLabel(summary)} · <time dateTime={summary.created_at}>{dateTime(summary.created_at)}</time></span>
      </div>
      <div className="drawer-body">
        {failed ? (
          <div className="callout is-danger" role="alert"><Icon name="warning" size={16}/><span>{failed} <button className="link" onClick={() => { setFailed(""); setAttempt(attempt + 1); }}>Retry</button></span></div>
        ) : detail === null ? (
          <div className="decision-loading" aria-busy="true" aria-label="Loading decision">{[70, 45, 85, 55, 65].map((width, index) => <span key={index} className="skeleton" style={{ width: `${width}%` }}/>)}</div>
        ) : <DecisionBody detail={detail}/>}
      </div>
      <div className="drawer-foot decision-foot">
        <span className="foot-meta">Reports are generated from this saved record.</span>
        {REPORTS.map((report) => <ReportButton key={report.format} id={summary.id} format={report.format} label={report.label} download={actions.downloadDecisionReport}/>)}
      </div>
    </Drawer>
  );
}

function ReportButton({ id, format, label, download }: { id: string; format: ReportFormat; label: string; download: (id: string, format: ReportFormat) => Promise<boolean> }) {
  const [busy, setBusy] = useState(false);
  return <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={async () => { setBusy(true); await download(id, format); setBusy(false); }}>{busy ? <span className="spinner"/> : <Icon name="download" size={14}/>}{label}</button>;
}

function DecisionBody({ detail }: { detail: DecisionDetail }) {
  const { now } = useWorkspace();
  const [all, setAll] = useState(false);
  const result = detail.result;
  // Most severe first across every manifest, not grouped by the manifest that found it.
  const violations = result.scans
    .flatMap((gate) => gate.items.filter((item) => item.outcome === "violation").map((item) => ({ gate, item })))
    .sort((a, b) => severityRank(b.item.severity) - severityRank(a.item.severity) || a.item.package_name.localeCompare(b.item.package_name));
  const errors = result.scans.filter((gate) => gate.error);
  const incomplete = result.scans.filter((gate) => !gate.complete && !gate.error);
  const shown = all ? violations : violations.slice(0, VIOLATION_LIMIT);
  // Reasons already name most missing manifests; list only the ones they do not mention.
  const missing = result.missing_manifests.filter((row) => !result.reasons.some((reason) => reason.includes(row.target_path)));
  const verdict = detail.status === "pass"
    ? "Every scan met the rules applied."
    : detail.status === "error" ? "At least one scan failed or could not be checked, so the gate cannot pass." : "The change did not meet the rules applied.";

  return (
    <>
      <section className="block">
        <h3 className="block-title">Why it {detail.status === "pass" ? "passed" : detail.status === "fail" ? "failed" : "errored"}</h3>
        <div className={`decision-verdict is-${detail.status}`}>
          <Icon name={detail.status === "pass" ? "check-circle" : detail.status === "fail" ? "x-circle" : "warning"} size={18}/>
          <div>
            <b>{verdict}</b>
            <div className="decision-counts">
              <span><b className="num">{detail.violations}</b> {detail.violations === 1 ? "violation" : "violations"}</span>
              <span><b className="num">{detail.ignored}</b> ignored</span>
              <span><b className="num">{detail.below_threshold}</b> below the severity limit</span>
              {detail.missing_manifests > 0 && <span><b className="num">{detail.missing_manifests}</b> missing {detail.missing_manifests === 1 ? "manifest" : "manifests"}</span>}
            </div>
          </div>
        </div>
        {result.reasons.length > 0 && <ul className="decision-reasons">{result.reasons.map((reason) => <li key={reason}><Icon name="warning" size={14}/>{reason}</li>)}</ul>}
        {missing.length > 0 && (
          <div className="decision-list">
            <span className="decision-list-title">Required manifests that were not scanned</span>
            {missing.map((row) => <div className="decision-row" key={`${row.project_id}:${row.target_path}`}><Icon name="file" size={14}/><span className="mono">{row.target_path}</span><small>{row.project_name}</small></div>)}
          </div>
        )}
        {errors.map((gate) => <div key={gate.scan_id} className="callout is-danger"><Icon name="warning" size={16}/><span><b className="mono">{gate.target_path}</b>: {gate.error}</span></div>)}
        {incomplete.length > 0 && result.policy.fail_on_incomplete && <div className="callout"><Icon name="warning" size={16}/><span>The policy requires every package to be checked, and {incomplete.length === 1 ? "one scan" : `${incomplete.length} scans`} could not check them all.</span></div>}
        {violations.length > 0 && (
          <div className="decision-list">
            <span className="decision-list-title">Violations</span>
            {shown.map(({ gate, item }) => <Violation key={`${gate.scan_id}:${item.package_name}:${item.package_version}:${item.advisory_ids.join(",")}`} gate={gate} item={item}/>)}
            {violations.length > VIOLATION_LIMIT && <button className="link decision-more" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${violations.length} violations`}</button>}
          </div>
        )}
      </section>

      <section className="block">
        <h3 className="block-title">Policy</h3>
        <dl className="kv">
          <dt>Rules applied</dt><dd>{summarizeGate(result.policy)}</dd>
          <dt>Policy versions</dt><dd><Link className="link" href="/policies">{policyLabel(detail.policy_sources)}<Icon name="arrow" size={13}/></Link></dd>
        </dl>
        {result.adjustments.length ? (
          <div className="decision-list">
            <span className="decision-list-title">Your policies made the pipeline’s settings stricter</span>
            {result.adjustments.map((adjustment) => {
              const parts = adjustmentParts(adjustment);
              return (
                <div className="adjustment" key={`${adjustment.rule}:${adjustment.source}`}>
                  <b>{parts.rule}</b>
                  <span className="adjustment-change"><span className="sr-only">Pipeline asked for </span><s className="mono">{parts.requested}</s><Icon name="arrow" size={13}/><span className="sr-only">, applied </span><span className="mono">{parts.enforced}</span></span>
                  <small>by {parts.source}</small>
                </div>
              );
            })}
          </div>
        ) : <p className="muted">The pipeline’s own settings were already at least as strict as your policies.</p>}
      </section>

      <section className="block">
        <h3 className="block-title">Evidence<span className="muted block-count">{detail.inputs.length} {detail.inputs.length === 1 ? "manifest" : "manifests"}</span></h3>
        <div className="list">
          {detail.inputs.map((input) => (
            <div className="evidence-row" key={input.scan_id}>
              <span className="manifest-path"><Icon name="file" size={14}/>{input.target_path}</span>
              <div className="manifest-meta">
                <span className={`tag ${input.mode === "check" ? "tag-check" : ""}`}>{MODE_LABEL[input.mode]}</span>
                <span className="status"><i className={`dot ${input.complete ? "dot-ok" : "dot-warn"}`}/>{input.complete ? "Every package checked" : "Some packages not checked"}</span>
                <span>Scanner <span className="mono">{input.engine_version ?? "unknown"}</span></span>
                <span>SHA-256 <HashChip value={input.sha256} label="SHA-256"/></span>
              </div>
              {!input.complete && input.coverage_notes.length > 0 && <ul className="evidence-notes">{input.coverage_notes.map((note) => <li key={note}>{note}</li>)}</ul>}
            </div>
          ))}
          {!detail.inputs.length && <p className="muted evidence-row">No scan inputs were recorded.</p>}
        </div>
        <p className="field-hint">{intelligenceAge(detail.created_at, detail.intelligence_updated_at)}</p>
      </section>

      <section className="block">
        <h3 className="block-title">Exceptions applied{detail.exceptions.length > 0 && <span className="muted block-count">{detail.exceptions.length}</span>}</h3>
        {detail.exceptions.length ? (
          <div className="decision-list">
            {detail.exceptions.map((exception) => (
              <div className="exception" key={`${exception.finding_id ?? exception.package_name}:${exception.advisory_ids.join(",")}`}>
                <div className="exception-top"><Pkg name={exception.package_name} version={exception.package_version}/><span className="mono muted">{primaryAdvisory(exception.advisory_ids)}</span><span className="tag tag-info">{WORKFLOW_LABEL[exception.workflow_status] ?? exception.workflow_status}</span></div>
                <small>{exception.risk_until && <>Expires {dateTime(exception.risk_until)} ({relativeTime(now, exception.risk_until)}) · </>}<span className="mono">{exception.target_path}</span></small>
              </div>
            ))}
          </div>
        ) : <p className="muted">No acknowledged or accepted findings changed this result.</p>}
      </section>

      <section className="block">
        <h3 className="block-title">Run identity</h3>
        {detail.actor.verified ? null : <div className="callout"><Icon name="info" size={16}/><span>{detail.actor.kind === "owner" ? "Requested from the dashboard by the owner." : "Not verified: the pipeline signed in with a stored API token, so the repository, branch, and commit are only what the pipeline reported."}</span></div>}
        <dl className="kv">
          <dt>Signed in with</dt><dd>{detail.actor.verified ? <span className="identity-verified"><Icon name="shield" size={13}/>Temporary token (OIDC) from {providerName(detail.actor.provider)}</span> : detail.actor.kind === "owner" ? "Owner session" : `API token “${actorLabel(detail.actor)}”`}</dd>
          {detail.actor.repository && <><dt>Repository</dt><dd className="mono">{detail.actor.repository}</dd></>}
          {detail.actor.workflow && <><dt>Workflow</dt><dd className="mono">{detail.actor.workflow}</dd></>}
          {detail.actor.ref && <><dt>Ref</dt><dd>{refLabel(detail.actor.ref)} <span className="mono muted">{detail.actor.ref}</span></dd></>}
          {detail.actor.event && <><dt>Event</dt><dd>{eventLabel(detail.actor.event)}</dd></>}
          {detail.commit && <><dt>Commit</dt><dd className="mono">{detail.commit}</dd></>}
          {!detail.commit && detail.revision && <><dt>Revision</dt><dd className="mono">{detail.revision}</dd></>}
          {detail.actor.run_url ? <><dt>Run</dt><dd><a className="link" href={detail.actor.run_url} target="_blank" rel="noopener noreferrer">{detail.actor.run_id ? `Run ${detail.actor.run_id}` : "Open run"}<Icon name="external" size={13}/><span className="sr-only"> (opens in a new tab)</span></a></dd></> : detail.actor.run_id && <><dt>Run</dt><dd className="mono">{detail.actor.run_id}</dd></>}
          <dt>Decision ID</dt><dd className="mono">{detail.id}</dd>
        </dl>
      </section>
    </>
  );
}

function Violation({ gate, item }: { gate: ScanGate; item: GateItem }) {
  return (
    <div className="violation">
      <div className="violation-top">
        <Sev value={item.severity}/>
        <Pkg name={item.package_name} version={item.package_version}/>
        {item.kev_known && <span className="tag tag-kev">KEV</span>}
        {item.new && <span className="tag">New</span>}
      </div>
      <span className="violation-ids mono">{item.advisory_ids.join(", ")}</span>
      <small>{item.reasons.join("; ")} · fixed in {item.fixed_versions.length ? <span className="mono">{item.fixed_versions.slice(0, 3).join(", ")}</span> : "no release yet"} · <span className="mono">{gate.target_path}</span></small>
    </div>
  );
}
