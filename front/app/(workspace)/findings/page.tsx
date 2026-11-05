"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Icon } from "@/components/icon";
import { useWorkspace } from "@/components/workspace/context";
import { useStored } from "@/components/workspace/findings-storage";
import { acknowledgeable, ageLabel, csvFileName, decisionOf, defaultFilters, epssPercent, filterFindings, isFiltered, OPTIONAL_COLUMNS, PAGE_SIZES, pageWindow, parseColumns, parsePageSize, parseViews, rangeIds, serializeColumns, serializeViews, severityCounts, sortFindings, toCsv, toggleSort, upsertView, type ColumnKey, type FindingView, type SortKey } from "@/components/workspace/findings-logic";
import { FindingsToolbar } from "@/components/workspace/findings-toolbar";
import { dateTime, primaryAdvisory } from "@/components/workspace/format";
import { Pagination } from "@/components/workspace/pagination";
import { Checkbox, Empty, Kbd, Modal, PageHead, Pkg, Sev, Sheet, SkeletonRows } from "@/components/workspace/ui";
import type { Finding } from "@/lib/api";
import "./findings.css";

const SORT_LABEL: Record<SortKey, string> = { priority: "priority", severity: "severity", package: "package", project: "project", fixed: "fixed version", epss: "EPSS", age: "age" };
const COLUMN_LABEL = Object.fromEntries(OPTIONAL_COLUMNS.map((column) => [column.key, column.label])) as Record<ColumnKey, string>;
const NO_IDS: string[] = [];
const serializePageSize = (size: number) => String(size);

function typing(target: EventTarget | null) {
  return target instanceof HTMLElement && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));
}

/** State that resets to `initial` whenever `key` changes, without an effect. */
function useKeyed<T>(key: string, initial: T): [T, (value: T) => void] {
  const [entry, setEntry] = useState({ key, value: initial });
  const set = useCallback((value: T) => setEntry({ key, value }), [key]);
  return [entry.key === key ? entry.value : initial, set];
}

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = Object.assign(document.createElement("a"), { href: url, download: name });
  link.click();
  URL.revokeObjectURL(url);
}

function DecisionCell({ finding }: { finding: Finding }) {
  const decision = decisionOf(finding);
  if (decision.kind === "awaiting") return <span className="muted">Awaiting</span>;
  const tone = decision.kind === "resolved" ? "tag-ok" : decision.kind === "accepted" ? "tag-info" : "";
  return <span className={`tag ${tone}`} title={decision.label}>{decision.kind === "accepted" ? "Risk accepted" : decision.label}</span>;
}

export default function FindingsPage() {
  const workspace = useWorkspace();
  const { findings, projects, filters, setFilters, query, setQuery, now, ready, actions, notify } = workspace;
  const [views, setViews] = useStored("depradar-findings-views", parseViews, serializeViews);
  const [columns, setColumns] = useStored("depradar-findings-columns", parseColumns, serializeColumns);
  const [pageSize, setPageSize] = useStored("depradar-findings-page-size", parsePageSize, serializePageSize);
  const [savingView, setSavingView] = useState(false);
  const [busy, setBusy] = useState(false);

  const names = useMemo(() => new Map(projects.map((project) => [project.id, project.name])), [projects]);
  const visible = useMemo(() => sortFindings(filterFindings(findings, filters, query, names), filters.sort, names), [findings, filters, query, names]);
  const ids = useMemo(() => visible.map((finding) => finding.id), [visible]);
  // Paging, selection, and the keyboard cursor start over whenever the list itself changes.
  const listKey = JSON.stringify([filters, query, pageSize]);
  const [page, setPage] = useKeyed(listKey, 1);
  const [selected, setSelected] = useKeyed<string[]>(listKey, NO_IDS);
  const [anchor, setAnchor] = useKeyed<string | null>(listKey, null);
  const [cursor, setCursor] = useKeyed<string | null>(listKey, null);
  const shiftClick = useRef(false);

  const span = pageWindow(visible.length, page, pageSize);
  const rows = visible.slice(span.from ? span.from - 1 : 0, span.to);
  const pageIds = rows.map((finding) => finding.id);
  const chosen = useMemo(() => visible.filter((finding) => selected.includes(finding.id)), [visible, selected]);
  const ackable = chosen.filter(acknowledgeable);
  const statusCounts = { open: findings.filter((finding) => finding.status === "open").length, resolved: findings.filter((finding) => finding.status === "resolved").length, all: findings.length };
  const filtered = isFiltered(filters, query);
  const shown = (key: ColumnKey) => columns.includes(key);
  const width = 4 + columns.length;

  function toggle(id: string, shift = false) {
    if (shift && anchor) {
      const range = rangeIds(ids, anchor, id);
      const adding = !selected.includes(id);
      setSelected(adding ? [...new Set([...selected, ...range])] : selected.filter((value) => !range.includes(value)));
    } else {
      setSelected(selected.includes(id) ? selected.filter((value) => value !== id) : [...selected, id]);
    }
    setAnchor(id);
  }

  async function acknowledgeSelection(targets: Finding[]) {
    if (!targets.length || busy) return;
    setBusy(true);
    const { failed } = await actions.bulkAcknowledge(targets);
    setBusy(false);
    if (!failed) setSelected(NO_IDS);
  }

  function moveCursor(step: number) {
    if (!ids.length) return;
    const index = cursor ? ids.indexOf(cursor) : -1;
    const next = ids[Math.min(ids.length - 1, Math.max(0, index < 0 ? (step > 0 ? span.from - 1 : span.to - 1) : index + step))];
    setCursor(next);
    const position = ids.indexOf(next) + 1;
    if (position < span.from || position > span.to) setPage(Math.ceil(position / pageSize));
  }

  // Triage without the mouse: J/K move, Enter opens, X selects, A acknowledges, Esc clears.
  function handleKey(event: KeyboardEvent) {
    if (event.metaKey || event.ctrlKey || event.altKey || typing(event.target)) return;
    if (workspace.findingId || workspace.modal || savingView || document.querySelector('[role="dialog"]')) return;
    const key = event.key.toLowerCase();
    if (key === "j" || key === "k") { event.preventDefault(); moveCursor(key === "j" ? 1 : -1); }
    else if (key === "enter" && cursor) { event.preventDefault(); workspace.setFindingId(cursor); }
    else if (key === "x" && cursor) { event.preventDefault(); toggle(cursor, event.shiftKey); }
    else if (key === "a") {
      const targets = chosen.length ? ackable : visible.filter((finding) => finding.id === cursor && acknowledgeable(finding));
      if (targets.length) { event.preventDefault(); void acknowledgeSelection(targets); }
    } else if (key === "escape" && (selected.length || cursor)) {
      event.preventDefault();
      if (selected.length) setSelected(NO_IDS); else setCursor(null);
    }
  }
  // Subscribe once; the listener always calls the latest handler.
  const keyHandler = useRef(handleKey);
  useEffect(() => { keyHandler.current = handleKey; });
  useEffect(() => {
    const listener = (event: KeyboardEvent) => keyHandler.current(event);
    document.addEventListener("keydown", listener);
    return () => document.removeEventListener("keydown", listener);
  }, []);

  useEffect(() => {
    if (cursor) document.querySelector(`[data-finding="${cursor}"]`)?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [cursor, page]);

  function sortHeader(key: SortKey, label: string, className = "") {
    const active = filters.sort.key === key;
    const icon = !active ? "sort" : filters.sort.dir === "asc" ? "sort-up" : "sort-down";
    return (
      <th className={className} aria-sort={active ? (filters.sort.dir === "asc" ? "ascending" : "descending") : undefined}>
        <button type="button" onClick={() => setFilters({ ...filters, sort: toggleSort(filters.sort, key) })}>{label}<Icon name={icon} size={13} className="sort-icon"/></button>
      </th>
    );
  }

  const allOnPage = pageIds.length > 0 && pageIds.every((id) => selected.includes(id));
  const someOnPage = pageIds.some((id) => selected.includes(id));

  return (
    <>
      <PageHead title="Findings" lede="Every vulnerable package version across your projects. Decisions stay with each finding, and only a complete clean scan resolves one."/>
      <FindingsToolbar
        filters={filters}
        query={query}
        projects={projects}
        statusCounts={statusCounts}
        severityCounts={severityCounts(findings, filters, query, names)}
        resultCount={visible.length}
        filtered={filtered}
        sortLabel={filters.sort.key === "priority" ? null : SORT_LABEL[filters.sort.key]}
        columns={columns}
        views={views}
        onQuery={setQuery}
        onFilters={(patch) => setFilters({ ...filters, ...patch })}
        onClear={() => { setQuery(""); setFilters({ ...defaultFilters, sort: filters.sort }); }}
        onResetSort={() => setFilters({ ...filters, sort: defaultFilters.sort })}
        onApplyView={(view: FindingView) => { setQuery(view.query); setFilters({ ...view.filters, sort: filters.sort }); }}
        onSaveView={() => setSavingView(true)}
        onDeleteView={(view) => { setViews(views.filter((item) => item.id !== view.id)); notify("info", `View “${view.name}” deleted.`); }}
        onColumns={setColumns}
        onExport={() => download(csvFileName(new Date()), toCsv(chosen.length ? chosen : visible, names), "text/csv;charset=utf-8")}
      />
      <Sheet className="findings-sheet">
        <div className="table-wrap">
          <table className="table findings-table">
            <thead>
              <tr>
                <th className="select-col"><Checkbox checked={allOnPage} indeterminate={someOnPage} label="Select every finding on this page" onChange={(checked) => setSelected(checked ? [...new Set([...selected, ...pageIds])] : selected.filter((id) => !pageIds.includes(id)))}/></th>
                {sortHeader("severity", "Severity", "col-severity")}
                {sortHeader("package", "Package")}
                {shown("project") && sortHeader("project", "Project · manifest", "col-optional col-project")}
                {shown("advisory") && <th className="col-optional col-advisory">Advisory</th>}
                {shown("fixed") && sortHeader("fixed", "Fixed in", "col-optional col-fixed")}
                {shown("signals") && sortHeader("epss", "Exploit risk", "col-optional col-signals")}
                {shown("age") && sortHeader("age", COLUMN_LABEL.age, "col-optional col-age")}
                {shown("decision") && <th className="col-optional col-decision">Decision</th>}
                <th aria-label="Actions"/>
              </tr>
            </thead>
            <tbody>
              {!ready ? <SkeletonRows rows={8} columns={width}/> : rows.map((finding) => {
                const isSelected = selected.includes(finding.id);
                return (
                  <tr key={finding.id} data-finding={finding.id} className={`is-link ${isSelected ? "is-selected" : ""} ${cursor === finding.id ? "is-active" : ""}`} onClick={() => { setCursor(finding.id); workspace.setFindingId(finding.id); }}>
                    <td className="select-col" onClickCapture={(event) => { shiftClick.current = event.shiftKey; }}><Checkbox checked={isSelected} label={`Select ${finding.package_name} ${finding.package_version}`} onChange={() => toggle(finding.id, shiftClick.current)}/></td>
                    <td className="col-severity"><Sev value={finding.severity}/></td>
                    <td><div className="cell-main"><Pkg name={finding.package_name} version={finding.package_version}/><small>{finding.ecosystem}{finding.workflow_status !== "open" || finding.status === "resolved" ? <span className={shown("decision") ? "decision-inline" : ""}> · {decisionOf(finding).label}</span> : null}</small></div></td>
                    {shown("project") && <td className="col-optional col-project"><div className="cell-main"><span className="cell-truncate">{names.get(finding.project_id) ?? "—"}</span><span className="path" title={finding.target_path}>{finding.target_path}</span></div></td>}
                    {shown("advisory") && <td className="col-optional col-advisory nowrap"><span className="mono advisory-id" title={finding.advisory_ids.join(", ")}>{primaryAdvisory(finding.advisory_ids)}</span>{finding.advisory_ids.length > 1 && <span className="muted"> +{finding.advisory_ids.length - 1}</span>}</td>}
                    {shown("fixed") && <td className="col-optional col-fixed nowrap">{finding.fixed_versions[0] ? <span className="mono">{finding.fixed_versions[0]}</span> : <span className="muted">No fix yet</span>}</td>}
                    {shown("signals") && <td className="col-optional col-signals"><span className="signal-cell">{finding.kev_known && <span className="tag tag-kev" title="Listed in the CISA Known Exploited Vulnerabilities catalog">KEV</span>}{finding.epss_score !== null && <span className="epss" title="EPSS: probability of exploitation in the next 30 days">{epssPercent(finding.epss_score)}</span>}{!finding.kev_known && finding.epss_score === null && <span className="muted">—</span>}</span></td>}
                    {shown("age") && <td className="col-optional col-age muted num nowrap"><time dateTime={finding.first_seen_at} title={`First detected ${dateTime(finding.first_seen_at)}`}>{ageLabel(now, finding.first_seen_at)}</time></td>}
                    {shown("decision") && <td className="col-optional col-decision"><DecisionCell finding={finding}/></td>}
                    <td className="right">{acknowledgeable(finding) && <button className="icon-btn row-action" onClick={(event) => { event.stopPropagation(); void actions.acknowledge(finding); }} title="Acknowledge (A): mute alerts while you work on it" aria-label={`Acknowledge ${finding.package_name}`}><Icon name="check" size={15}/></button>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {ready && !visible.length && (findings.length
            ? <Empty icon="filter" title="No findings match" text="Nothing fits these filters. Widen the status or severity, or clear the search." action={filtered ? <button className="btn btn-secondary" onClick={() => { setQuery(""); setFilters({ ...defaultFilters, sort: filters.sort }); }}>Clear filters</button> : undefined}/>
            : <Empty icon="shield" title="No findings yet" text="Upload a lockfile or connect a pipeline. Findings appear here as soon as the first scan completes." action={<button className="btn btn-primary" onClick={() => workspace.setModal({ kind: "upload" })}><Icon name="upload" size={15}/>Upload manifest</button>}/>)}
        </div>
        {ready && visible.length > 0 && <Pagination total={visible.length} page={span.page} pageSize={pageSize} sizes={PAGE_SIZES} onPage={setPage} onPageSize={setPageSize}/>}
      </Sheet>
      {ready && visible.length > 0 && !chosen.length && <p className="findings-keys"><Kbd>J</Kbd><Kbd>K</Kbd> move · <Kbd>↵</Kbd> open · <Kbd>X</Kbd> select · <Kbd>A</Kbd> acknowledge · shift-click selects a range</p>}
      {chosen.length > 0 && (
        <div className="bulk-bar" role="region" aria-label="Selected findings">
          <span className="num"><b>{chosen.length}</b> selected</span>
          <span className="bulk-sep" aria-hidden="true"/>
          <button className="btn btn-primary btn-sm" disabled={!ackable.length || busy} onClick={() => void acknowledgeSelection(ackable)} title={ackable.length ? undefined : "Only open findings awaiting a decision can be acknowledged"}>{busy ? <span className="spinner"/> : <Icon name="check" size={14}/>}Acknowledge{ackable.length !== chosen.length ? ` ${ackable.length}` : ""}</button>
          <button className="btn btn-secondary btn-sm" onClick={() => download(csvFileName(new Date()), toCsv(chosen, names), "text/csv;charset=utf-8")}><Icon name="download" size={14}/>Export</button>
          <button className="btn btn-ghost btn-sm" onClick={() => setSelected(NO_IDS)}>Clear<Kbd>Esc</Kbd></button>
        </div>
      )}
      {savingView && <SaveViewModal existing={views} onClose={() => setSavingView(false)} onSave={(name) => { setViews(upsertView(views, name, filters, query)); setSavingView(false); notify("success", `View “${name.trim()}” saved in this browser.`); }}/>}
    </>
  );
}

function SaveViewModal({ existing, onClose, onSave }: { existing: FindingView[]; onClose: () => void; onSave: (name: string) => void }) {
  const [name, setName] = useState("");
  const replaces = existing.some((view) => view.name.toLowerCase() === name.trim().toLowerCase());
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (name.trim()) onSave(name);
  }
  return (
    <Modal title="Save view" description="Keeps the current filters and search, so you can return to them from Views." onClose={onClose}>
      <form onSubmit={submit}>
        <div className="modal-body">
          <label className="field"><span className="field-label">Name</span><input className="input" value={name} onChange={(event) => setName(event.target.value)} maxLength={40} required autoFocus placeholder="Client A · critical and exploited"/></label>
          <span className="field-hint">{replaces ? "A view with this name exists; saving replaces it." : "Saved in this browser only."}</span>
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={!name.trim()}>{replaces ? "Replace view" : "Save view"}</button></div>
      </form>
    </Modal>
  );
}
