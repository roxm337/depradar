"use client";

import Link from "next/link";
import { useMemo, useState, type KeyboardEvent } from "react";
import "./decisions.css";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { DecisionDrawer } from "@/components/workspace/decision-drawer";
import { dateTime, relativeTime } from "@/components/workspace/format";
import { Pagination } from "@/components/workspace/pagination";
import { actorLabel, matchesDecision, MODE_LABEL, outcomeText, policyLabel, revisionLabel, STATUS_LABEL, STATUS_TONE, statusCounts, type StatusFilter } from "@/components/workspace/policy-logic";
import { Empty, Kbd, PageHead, Segmented, Sheet, SkeletonRows } from "@/components/workspace/ui";
import { api, type DecisionSummary } from "@/lib/api";

const PAGE_SIZES = [25, 50, 100];
const WEEK = 7 * 86_400_000;

export default function DecisionsPage() {
  const workspace = useWorkspace();
  const { decisions, projects, features, ready, now, notify } = workspace;
  const [status, setStatus] = useState<StatusFilter>("all");
  const [project, setProject] = useState("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [older, setOlder] = useState<DecisionSummary[]>([]);
  const [olderDone, setOlderDone] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);

  // The workspace keeps the newest page fresh; older pages are fetched on demand and deduplicated.
  const rows = useMemo(() => {
    const seen = new Set(decisions.map((row) => row.id));
    return [...decisions, ...older.filter((row) => !seen.has(row.id))];
  }, [decisions, older]);
  const scoped = rows.filter((row) => (project === "all" || row.project_id === project) && matchesDecision(row, query));
  const counts = statusCounts(scoped);
  const visible = scoped.filter((row) => status === "all" || row.status === status);
  const start = (Math.min(page, Math.max(1, Math.ceil(visible.length / pageSize))) - 1) * pageSize;
  const pageRows = visible.slice(start, start + pageSize);
  const open = rows.find((row) => row.id === openId) ?? null;
  const filtered = status !== "all" || project !== "all" || Boolean(query.trim());
  const mayHaveMore = !olderDone && decisions.length >= 100;

  const recent = rows.filter((row) => now && now - Date.parse(row.created_at) < WEEK);
  const recentPassed = recent.filter((row) => row.status === "pass").length;
  const recentBlocked = recent.length - recentPassed;
  const recentEnforced = recent.filter((row) => row.adjustments > 0).length;
  const recentVerified = recent.filter((row) => row.actor.verified).length;

  async function loadOlder() {
    setLoadingOlder(true);
    try {
      const next = await api<DecisionSummary[]>(`ci/decisions?limit=100&offset=${decisions.length + older.length}`);
      setOlder((current) => [...current, ...next]);
      if (next.length < 100) setOlderDone(true);
    } catch (failure) { notify("error", failure instanceof Error ? failure.message : "Could not load older decisions."); }
    finally { setLoadingOlder(false); }
  }
  const update = (apply: () => void) => { apply(); setPage(1); };
  const onRowKey = (event: KeyboardEvent<HTMLTableRowElement>, id: string) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setOpenId(id); }
  };

  return (
    <>
      <PageHead title="Decisions" lede="Every pipeline gate decision, with the policy, evidence, and exceptions it used. Records never change, and their reports download exactly what the pipeline saw."/>
      {!features.decisions && <div className="callout decisions-note"><Icon name="warning" size={16}/><span>This API build does not record gate decisions yet. Rebuild with <span className="inline-code">docker compose up --build -d api worker</span>, then pipelines record a decision on every run.</span></div>}
      <div className="stat-row decisions-stats" aria-label="Last 7 days">
        <div className="stat"><span>Decisions · 7 days</span><strong>{ready ? recent.length : "—"}</strong></div>
        <div className="stat"><span>Passed</span><strong>{ready ? (recent.length ? `${Math.round((recentPassed / recent.length) * 100)}%` : "—") : "—"}</strong></div>
        <div className="stat"><span>Failed or errored</span><strong className={recentBlocked ? "is-hot" : ""}>{ready ? recentBlocked : "—"}</strong></div>
        <div className="stat"><span>Central policy enforced</span><strong>{ready ? recentEnforced : "—"}</strong><small className="muted">{ready && recent.length ? `${recentVerified} of ${recent.length} from verified runs` : ""}</small></div>
      </div>
      <div className="toolbar">
        <label className="search-field">
          <Icon name="search" size={15}/>
          <input className="input" type="search" data-page-search value={query} onChange={(event) => update(() => setQuery(event.target.value))} placeholder="Search project, revision, commit, or pipeline" aria-label="Search decisions" autoComplete="off" spellCheck={false}/>
          <Kbd>/</Kbd>
        </label>
        <Segmented label="Status" value={status} onChange={(value) => update(() => setStatus(value))} options={[{ value: "all", label: "All", count: counts.all }, { value: "pass", label: "Passed", count: counts.pass }, { value: "fail", label: "Failed", count: counts.fail }, { value: "error", label: "Error", count: counts.error }]}/>
        <select className="select" aria-label="Project" value={project} onChange={(event) => update(() => setProject(event.target.value))}>
          <option value="all">All projects</option>
          {projects.map((row) => <option key={row.id} value={row.id}>{row.name}</option>)}
        </select>
        <span className="toolbar-meta" aria-live="polite">{visible.length} {visible.length === 1 ? "decision" : "decisions"}{filtered && <> · <button className="link" onClick={() => update(() => { setStatus("all"); setProject("all"); setQuery(""); })}>Clear filters</button></>}</span>
      </div>
      <Sheet>
        <div className="table-wrap">
          <table className="table decisions-table">
            <thead><tr><th>Status</th><th>Project · revision</th><th className="col-optional">Pipeline</th><th className="col-optional">Policy</th><th>Outcome</th><th className="col-optional">Decided</th><th className="col-optional" aria-label="Open"/></tr></thead>
            <tbody>
              {!ready ? <SkeletonRows rows={6} columns={7}/> : pageRows.map((row) => (
                <tr key={row.id} className={`is-link ${row.id === openId ? "is-active" : ""}`} tabIndex={0} onClick={() => setOpenId(row.id)} onKeyDown={(event) => onRowKey(event, row.id)} aria-label={`${STATUS_LABEL[row.status]} decision for ${row.project_name}, ${revisionLabel(row)}`}>
                  <td><span className="status decision-status"><i className={`dot ${STATUS_TONE[row.status]}`}/>{STATUS_LABEL[row.status]}</span></td>
                  <td><div className="cell-main"><span className="decision-project"><b>{row.project_name}</b><span className={`tag ${row.mode === "check" ? "tag-check" : ""}`}>{MODE_LABEL[row.mode]}</span></span><small className="mono" title={row.commit ?? row.revision ?? undefined}>{revisionLabel(row)}</small></div></td>
                  <td className="col-optional"><div className="cell-main decision-actor"><span>{actorLabel(row.actor)}</span>{row.actor.verified ? <small className="decision-verified"><Icon name="shield" size={12}/>Verified</small> : <small>{row.actor.kind === "owner" ? "Dashboard" : "API token"}</small>}</div></td>
                  <td className="col-optional"><div className="cell-main"><span className="nowrap">{policyLabel(row.policy_sources)}</span>{row.adjustments > 0 ? <small><span className="tag tag-info decision-enforced">{row.adjustments} {row.adjustments === 1 ? "rule" : "rules"} enforced</span></small> : <small>As requested</small>}</div></td>
                  <td><div className="cell-main"><span className={row.violations || row.missing_manifests ? "decision-outcome is-hot" : "decision-outcome"}>{outcomeText(row)}</span>{row.ignored > 0 && <small>{row.ignored} ignored</small>}</div></td>
                  <td className="col-optional muted nowrap"><time dateTime={row.created_at} title={dateTime(row.created_at)}>{relativeTime(now, row.created_at)}</time></td>
                  <td className="right col-optional"><Icon name="chevron" size={16}/></td>
                </tr>
              ))}
            </tbody>
          </table>
          {ready && !visible.length && (rows.length
            ? <Empty title="No decisions match" text="Change the status, project, or search to widen the list." action={<button className="btn btn-secondary" onClick={() => update(() => { setStatus("all"); setProject("all"); setQuery(""); })}>Clear filters</button>}/>
            : <Empty icon="check-circle" title="No gate decisions yet" text="The CI client records a decision each time it gates a change (POST /api/ci/decisions), with the enforced policy, scanner evidence, and exceptions. Connect a pipeline and its first run appears here." action={<Link className="btn btn-primary" href="/settings#ci"><Icon name="branch" size={15}/>Set up CI/CD access</Link>}/>)}
        </div>
        {ready && visible.length > 0 && <Pagination total={visible.length} page={page} pageSize={pageSize} sizes={PAGE_SIZES} noun="decisions" onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1); }}/>}
        {ready && mayHaveMore && <div className="sheet-foot decisions-older"><span>Showing the newest {rows.length} decisions.</span><button className="btn btn-secondary btn-sm" disabled={loadingOlder} onClick={() => void loadOlder()}>{loadingOlder && <span className="spinner"/>}Load older decisions</button></div>}
      </Sheet>
      {open && <DecisionDrawer key={open.id} summary={open} onClose={() => setOpenId(null)}/>}
    </>
  );
}
