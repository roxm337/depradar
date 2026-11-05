"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent, type KeyboardEvent } from "react";
import "./packages.css";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { defaultFilters } from "@/components/workspace/findings-logic";
import { dateTime, relativeTime } from "@/components/workspace/format";
import { coverageNote, indexLabel, noMatchText, searchPath, summarize, versionLabel, type PackageQuery } from "@/components/workspace/packages-logic";
import { Pagination } from "@/components/workspace/pagination";
import { Empty, Kbd, PageHead, Sheet, SkeletonRows } from "@/components/workspace/ui";
import { api, ApiError, type ComponentCoverage, type ComponentMatch, type ComponentSearch, type ComponentSnapshot } from "@/lib/api";

const PAGE_SIZES = [25, 50, 100];
const PENDING_PREVIEW = 5;
const EMPTY_QUERY: PackageQuery = { name: "", ecosystem: "", version: "" };

// An API build without package search answers 404 or 405.
const missing = (failure: unknown) => failure instanceof ApiError && (failure.status === 404 || failure.status === 405);
const failureText = (failure: unknown, fallback: string) => (failure instanceof Error ? failure.message : fallback);

type Loaded<T> = { key: string; data?: T; error?: string };

export default function PackagesPage() {
  const workspace = useWorkspace();
  const { now, scans, syncedAt, actions } = workspace;
  const router = useRouter();
  const [form, setForm] = useState<PackageQuery>(EMPTY_QUERY);
  const [submitted, setSubmitted] = useState<PackageQuery | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [coverageState, setCoverageState] = useState<Loaded<ComponentCoverage> | null>(null);
  const [result, setResult] = useState<Loaded<ComponentSearch> | null>(null);
  const [unsupported, setUnsupported] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [showAllPending, setShowAllPending] = useState(false);

  const path = submitted ? searchPath(submitted) : null;
  const coverageKey = `${syncedAt ?? ""}:${attempt}`;
  const searchKey = path ? `${path}:${coverageKey}` : null;

  // Both requests refresh when the workspace reloads, so a manifest rechecked from here appears
  // in the index as soon as its scan finishes.
  useEffect(() => {
    let cancelled = false;
    api<ComponentCoverage>("components/coverage")
      .then((data) => { if (!cancelled) setCoverageState({ key: coverageKey, data }); })
      .catch((failure) => {
        if (cancelled) return;
        if (missing(failure)) setUnsupported(true);
        setCoverageState({ key: coverageKey, error: failureText(failure, "Could not load the package index.") });
      });
    return () => { cancelled = true; };
  }, [coverageKey]);

  useEffect(() => {
    if (!path || !searchKey) return;
    let cancelled = false;
    api<ComponentSearch>(path)
      .then((data) => { if (!cancelled) setResult({ key: searchKey, data }); })
      .catch((failure) => {
        if (cancelled) return;
        if (missing(failure)) setUnsupported(true);
        setResult({ key: searchKey, error: failureText(failure, "The search failed.") });
      });
    return () => { cancelled = true; };
  }, [path, searchKey]);

  // A refresh keeps showing the previous answer for the same search; a new search shows skeletons.
  const current = result && path && result.key.startsWith(`${path}:`) ? result : null;
  const searching = Boolean(path) && current?.key !== searchKey && !current?.data;
  const search = current?.data ?? null;
  const coverage = search?.coverage ?? coverageState?.data ?? null;
  const coverageLoading = !coverageState && !unsupported;
  const matches = search?.matches ?? [];
  const summary = summarize(matches);
  const start = (Math.min(page, Math.max(1, Math.ceil(matches.length / pageSize))) - 1) * pageSize;
  const pageRows = matches.slice(start, start + pageSize);
  const queued = new Set(scans.filter((scan) => scan.status === "queued" || scan.status === "running").map((scan) => scan.inventory_id));
  const pending = coverage?.not_indexed ?? [];
  const pendingIdle = pending.filter((snapshot) => !queued.has(snapshot.inventory_id));
  const pendingShown = showAllPending ? pending : pending.slice(0, PENDING_PREVIEW);
  const note = coverage ? coverageNote(coverage) : null;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!form.name.trim()) return;
    setSubmitted({ ...form });
    setPage(1);
  }
  function clear() {
    setForm(EMPTY_QUERY);
    setSubmitted(null);
    setPage(1);
  }
  const retry = () => setAttempt((value) => value + 1);
  const openProject = (id: string) => workspace.setProjectId(id);
  const onRowKey = (event: KeyboardEvent<HTMLTableRowElement>, id: string) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openProject(id); }
  };
  function showFindings(match: ComponentMatch) {
    workspace.setFilters({ ...defaultFilters, project: match.snapshot.project_id });
    workspace.setQuery(match.name);
    router.push("/findings");
  }
  const manifestLabel = (snapshot: ComponentSnapshot) => `${snapshot.project_name} · ${snapshot.target_path}`;

  return (
    <>
      <PageHead title="Packages" lede="Find which projects use a package, at which version, across every current monitored manifest. Answers come from the last uploaded manifests, not from what is deployed."/>
      {unsupported && <div className="callout packages-note"><Icon name="warning" size={16}/><span>This API build does not index packages yet. Rebuild with <span className="inline-code">docker compose up --build -d api worker</span>; manifests are indexed on their next scan.</span></div>}

      <form className="toolbar packages-form" role="search" onSubmit={submit}>
        <label className="search-field">
          <Icon name="search" size={15}/>
          <input className="input" type="search" data-page-search value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Package name, for example lodash or flask-sqlalchemy" aria-label="Package name" autoComplete="off" spellCheck={false} maxLength={512} disabled={unsupported}/>
          <Kbd>/</Kbd>
        </label>
        <select className="select" aria-label="Ecosystem" value={form.ecosystem} onChange={(event) => setForm({ ...form, ecosystem: event.target.value })} disabled={unsupported}>
          <option value="">All ecosystems</option>
          {(coverage?.ecosystems ?? []).map((ecosystem) => <option key={ecosystem} value={ecosystem}>{ecosystem}</option>)}
        </select>
        <input className="input packages-version" value={form.version} onChange={(event) => setForm({ ...form, version: event.target.value })} placeholder="Exact version" aria-label="Exact version (optional)" title="Matches the version exactly as the manifest records it" autoComplete="off" spellCheck={false} maxLength={200} disabled={unsupported}/>
        <button className="btn btn-primary" type="submit" disabled={unsupported || !form.name.trim()} title={!form.name.trim() ? "Enter a package name" : undefined}><Icon name="search" size={15}/>Search</button>
        {submitted && <button className="btn btn-ghost" type="button" onClick={clear}>Clear</button>}
        <span className="toolbar-meta" aria-live="polite">{coverage ? `${coverage.indexed} of ${coverage.snapshots} manifests indexed` : coverageLoading ? "Loading the index…" : ""}</span>
      </form>

      {coverageState?.error && !unsupported && !coverage && <div className="callout is-danger packages-note" role="alert"><Icon name="warning" size={16}/><span>{coverageState.error} <button className="link" onClick={retry}>Try again</button></span></div>}

      {pending.length > 0 && (
        <Sheet className="packages-pending" title="Not indexed yet" meta={`${pending.length} ${pending.length === 1 ? "manifest" : "manifests"} · searches skip ${pending.length === 1 ? "it" : "them"} until ${pending.length === 1 ? "it is" : "they are"} scanned again`} actions={pendingIdle.length > 1 ? <button className="btn btn-secondary btn-sm" onClick={() => void actions.rescanAll(pendingIdle.map((snapshot) => snapshot.inventory_id), "manifests without a package index")}><Icon name="refresh" size={14}/>Recheck all</button> : undefined} foot={pending.length > PENDING_PREVIEW ? <button className="link" onClick={() => setShowAllPending((value) => !value)}>{showAllPending ? "Show fewer" : `Show all ${pending.length}`}</button> : undefined}>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Project · manifest</th><th className="col-optional">Uploaded</th><th aria-label="Recheck"/></tr></thead>
              <tbody>
                {pendingShown.map((snapshot) => (
                  <tr key={snapshot.inventory_id}>
                    <td><div className="cell-main"><b>{snapshot.project_name}</b><small className="mono package-path">{snapshot.target_path}</small></div></td>
                    <td className="col-optional muted nowrap"><time dateTime={snapshot.uploaded_at} title={dateTime(snapshot.uploaded_at)}>{relativeTime(now, snapshot.uploaded_at)}</time></td>
                    <td className="right">{queued.has(snapshot.inventory_id)
                      ? <span className="status"><span className="spinner"/>Scan queued</span>
                      : <button className="btn btn-secondary btn-sm" onClick={() => void actions.rescan(snapshot.inventory_id, manifestLabel(snapshot))}><Icon name="refresh" size={14}/>Recheck</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Sheet>
      )}

      {coverage && coverage.partial.length > 0 && (
        <div className="callout is-warn packages-note"><Icon name="warning" size={16}/><p>{coverage.partial.length === 1 ? "1 manifest was" : `${coverage.partial.length} manifests were`} indexed by an incomplete scan, so a package may be missing from {coverage.partial.length === 1 ? "it" : "them"}: {coverage.partial.slice(0, 3).map(manifestLabel).join(", ")}{coverage.partial.length > 3 ? `, and ${coverage.partial.length - 3} more` : ""}.</p></div>
      )}

      {current?.error && !unsupported && <div className="callout is-danger packages-note" role="alert"><Icon name="warning" size={16}/><span>{current.error} <button className="link" onClick={retry}>Try again</button></span></div>}

      {search && matches.length > 0 && (
        <div className="packages-summary" aria-live="polite">
          <span><strong>{search.name}</strong> is used in <strong>{summary.manifests} {summary.manifests === 1 ? "manifest" : "manifests"}</strong> across <strong>{summary.projects} {summary.projects === 1 ? "project" : "projects"}</strong>{note ? "; some manifests were not fully searched" : ""}.</span>
          <span className="packages-versions" aria-label="Manifests per version">{summary.versions.map((row) => <span key={`${row.ecosystem}:${row.name}:${row.version}`} className="tag tag-mono" title={`${row.ecosystem} ${row.name}`}>{versionLabel(row.version)} · {row.manifests}</span>)}</span>
        </div>
      )}

      {(searching || (search && matches.length > 0)) && (
        <Sheet>
          <div className="table-wrap">
            <table className="table packages-table">
              <thead><tr><th>Package</th><th>Version</th><th>Project · manifest</th><th className="col-optional">Uploaded</th><th className="col-optional">Index</th><th>Open findings</th><th className="col-optional" aria-label="Open"/></tr></thead>
              <tbody>
                {searching ? <SkeletonRows rows={5} columns={7}/> : pageRows.map((match) => (
                  <tr key={`${match.snapshot.inventory_id}:${match.ecosystem}:${match.name}:${match.version}`} className="is-link" tabIndex={0} onClick={() => openProject(match.snapshot.project_id)} onKeyDown={(event) => onRowKey(event, match.snapshot.project_id)} aria-label={`${match.name} ${versionLabel(match.version)} in ${manifestLabel(match.snapshot)}`}>
                    <td><div className="cell-main"><span className="package-name">{match.name}</span><small>{match.ecosystem}</small></div></td>
                    <td>{match.version ? <span className="package-version">{match.version}</span> : <span className="tag" title="The manifest does not pin a version, so advisories cannot be matched">Unpinned</span>}</td>
                    <td><div className="cell-main"><b>{match.snapshot.project_name}</b><small className="mono package-path">{match.snapshot.target_path}</small></div></td>
                    <td className="col-optional nowrap"><div className="cell-main"><time dateTime={match.snapshot.uploaded_at} title={dateTime(match.snapshot.uploaded_at)}>{relativeTime(now, match.snapshot.uploaded_at)}</time>{match.snapshot.revision && <small className="mono" title={match.snapshot.revision}>{match.snapshot.revision}</small>}</div></td>
                    <td className="col-optional nowrap"><div className="cell-main"><span className={`tag ${match.indexed_by.complete ? "tag-ok" : "tag-warn"}`} title={match.indexed_by.coverage_notes.join("\n") || undefined}>{indexLabel(match.indexed_by)}</span>{match.indexed_by.completed_at && <small>{relativeTime(now, match.indexed_by.completed_at)}</small>}</div></td>
                    <td className="nowrap">{match.open_findings > 0
                      ? <button className="link" onClick={(event) => { event.stopPropagation(); showFindings(match); }}>{match.open_findings} open</button>
                      : <span className="muted">None</span>}</td>
                    <td className="right col-optional"><Icon name="chevron" size={16}/></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!searching && matches.length > 0 && <Pagination total={matches.length} page={page} pageSize={pageSize} sizes={PAGE_SIZES} noun="matches" onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1); }}/>}
          {!searching && search?.truncated && <div className="sheet-foot">Showing the first {matches.length} matches. Add an ecosystem or an exact version to narrow the search.</div>}
        </Sheet>
      )}

      {search && !matches.length && !searching && (
        <Sheet><Empty icon="search" title="No matches" text={noMatchText(search.name, search.coverage)} action={<button className="btn btn-secondary" onClick={clear}>New search</button>}/></Sheet>
      )}

      {!submitted && !unsupported && coverage && (coverage.snapshots === 0
        ? <Sheet><Empty icon="layers" title="No monitored manifests yet" text="Package search covers the current monitored manifest of every project. Upload a lockfile or SBOM, or connect a pipeline, and its packages are indexed when the scan finishes." action={<button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "upload" })}><Icon name="upload" size={15}/>Upload manifest</button>}/></Sheet>
        : <Sheet><Empty icon="layers" title="Search every monitored manifest" text="Enter a package name to see which projects use it, at which version, and how recently each manifest was uploaded. Names match the way their registry compares them, so flask_sqlalchemy also finds Flask-SQLAlchemy."/></Sheet>)}
      {!submitted && coverageLoading && <Sheet><div className="table-wrap"><table className="table"><tbody><SkeletonRows rows={3} columns={3}/></tbody></table></div></Sheet>}
    </>
  );
}
