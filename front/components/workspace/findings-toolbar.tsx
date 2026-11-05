"use client";

import { Icon } from "@/components/icon";
import { SEVERITIES } from "@/components/workspace/format";
import { ALL_COLUMNS, BUILTIN_VIEWS, OPTIONAL_COLUMNS, sameView, type ColumnKey, type FindingFilters, type FindingView } from "@/components/workspace/findings-logic";
import { Kbd, Menu, MenuItem, Segmented } from "@/components/workspace/ui";
import type { Project } from "@/lib/api";

type Props = {
  filters: FindingFilters;
  query: string;
  projects: Project[];
  statusCounts: { open: number; resolved: number; all: number };
  severityCounts: Record<string, number>;
  resultCount: number;
  filtered: boolean;
  /** Set while a column sort replaces the default priority order. */
  sortLabel: string | null;
  columns: ColumnKey[];
  views: FindingView[];
  onQuery: (value: string) => void;
  onFilters: (patch: Partial<FindingFilters>) => void;
  onClear: () => void;
  onResetSort: () => void;
  onApplyView: (view: FindingView) => void;
  onSaveView: () => void;
  onDeleteView: (view: FindingView) => void;
  onColumns: (columns: ColumnKey[]) => void;
  onExport: () => void;
};

export function FindingsToolbar({ filters, query, projects, statusCounts, severityCounts, resultCount, filtered, sortLabel, columns, views, onQuery, onFilters, onClear, onResetSort, onApplyView, onSaveView, onDeleteView, onColumns, onExport }: Props) {
  return (
    <>
      <div className="toolbar findings-toolbar">
        <label className="search-field">
          <Icon name="search" size={15}/>
          <input className="input" type="search" data-page-search value={query} onChange={(event) => onQuery(event.target.value)} placeholder="Search package, advisory, project, or path" aria-label="Search findings" autoComplete="off" spellCheck={false}/>
          <Kbd>/</Kbd>
        </label>
        <select className="select" aria-label="Project" value={filters.project} onChange={(event) => onFilters({ project: event.target.value })}>
          <option value="all">All projects</option>
          {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
        </select>
        <select className="select" aria-label="Decision" value={filters.decision} onChange={(event) => onFilters({ decision: event.target.value })}>
          <option value="all">Any decision</option>
          <option value="open">Awaiting decision</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="risk_accepted">Risk accepted</option>
          <option value="decided">Acknowledged or accepted</option>
        </select>
        <div className="toolbar-end">
          <Menu label="Saved views" trigger={({ props }) => <button className="btn btn-secondary" {...props} title="Saved views"><Icon name="bookmark" size={15}/><span className="btn-label">Views</span><Icon name="chevron-down" size={14}/></button>}>
            {(close) => (
              <>
                <div className="menu-heading">Views</div>
                {BUILTIN_VIEWS.map((view) => <MenuItem key={view.id} checked={sameView(filters, query, view)} onSelect={() => { close(); onApplyView(view); }}>{view.name}</MenuItem>)}
                {views.length > 0 && (
                  <>
                    <div className="menu-sep"/>
                    <div className="menu-heading">Saved by you</div>
                    {views.map((view) => (
                      <div className="view-row" key={view.id}>
                        <MenuItem checked={sameView(filters, query, view)} onSelect={() => { close(); onApplyView(view); }}>{view.name}</MenuItem>
                        <button className="icon-btn view-delete" role="menuitem" aria-label={`Delete the view ${view.name}`} title="Delete view" onClick={() => onDeleteView(view)}><Icon name="trash" size={14}/></button>
                      </div>
                    ))}
                  </>
                )}
                <div className="menu-sep"/>
                <MenuItem icon="plus" onSelect={() => { close(); onSaveView(); }}>Save current view…</MenuItem>
              </>
            )}
          </Menu>
          <Menu label="Columns" trigger={({ props }) => <button className="btn btn-secondary" {...props} title="Columns"><Icon name="columns" size={15}/><span className="btn-label">Columns</span><Icon name="chevron-down" size={14}/></button>}>
            {() => (
              <>
                <div className="menu-heading">Show columns</div>
                {OPTIONAL_COLUMNS.map((column) => <MenuItem key={column.key} checked={columns.includes(column.key)} onSelect={() => onColumns(ALL_COLUMNS.filter((key) => (key === column.key ? !columns.includes(key) : columns.includes(key))))}>{column.label}</MenuItem>)}
                <div className="menu-sep"/>
                <MenuItem onSelect={() => onColumns(ALL_COLUMNS)}>Reset to default</MenuItem>
              </>
            )}
          </Menu>
          <button className="btn btn-secondary" onClick={onExport} disabled={!resultCount} title={resultCount ? `Download ${resultCount} ${resultCount === 1 ? "finding" : "findings"} as CSV` : "Nothing to export"}><Icon name="download" size={15}/><span className="btn-label">Export</span></button>
        </div>
      </div>
      <div className="toolbar findings-filters">
        <Segmented label="Status" value={filters.status} onChange={(status) => onFilters({ status })} options={[{ value: "open", label: "Open", count: statusCounts.open }, { value: "resolved", label: "Resolved", count: statusCounts.resolved }, { value: "all", label: "All", count: statusCounts.all }]}/>
        <span className="filter-divider" aria-hidden="true"/>
        <div className="chips" role="group" aria-label="Severity">
          {SEVERITIES.map((level) => {
            const active = filters.severities.includes(level);
            return (
              <button key={level} className="chip" aria-pressed={active} onClick={() => onFilters({ severities: active ? filters.severities.filter((value) => value !== level) : [...filters.severities, level] })}>
                <i className={`sev-dot bar-${level}`} aria-hidden="true"/><span className="sev-name">{level}</span><small>{severityCounts[level] ?? 0}</small>
              </button>
            );
          })}
        </div>
        <span className="filter-divider" aria-hidden="true"/>
        <button className="chip" aria-pressed={filters.exploited} onClick={() => onFilters({ exploited: !filters.exploited })}>Known exploited</button>
        <button className="chip" aria-pressed={filters.fixable} onClick={() => onFilters({ fixable: !filters.fixable })}>Fix available</button>
        {sortLabel && <button className="chip is-sort" onClick={onResetSort} title="Return to priority order">Sorted by {sortLabel}<Icon name="close" size={12}/></button>}
        {filtered && <button className="btn btn-ghost btn-sm" onClick={onClear}><Icon name="close" size={13}/>Clear filters</button>}
        <span className="toolbar-meta num">{resultCount} {resultCount === 1 ? "finding" : "findings"}</span>
      </div>
    </>
  );
}
