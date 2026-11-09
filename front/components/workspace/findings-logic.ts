// Pure logic for the Findings page: filtering, sorting, saved views, columns, paging, and CSV export.
// No React and no "@/" imports, so `node --test` can load it directly.
import type { Finding } from "../../lib/api.ts";
import { byPriority, severityOf, severityRank, shortDate } from "./format.ts";

// ── Filters and sorting ──────────────────────────────────────────────────────

export type SortKey = "priority" | "severity" | "package" | "project" | "fixed" | "epss" | "age";
export type SortDir = "asc" | "desc";
export type Sort = { key: SortKey; dir: SortDir };
export type StatusFilter = "open" | "resolved" | "all";
// "decided" matches anything the owner has already acknowledged or accepted.
export type DecisionFilter = "all" | "open" | "acknowledged" | "risk_accepted" | "decided";

export type FindingFilters = {
  status: StatusFilter;
  severities: string[];
  decision: string;
  project: string;
  exploited: boolean;
  fixable: boolean;
  sort: Sort;
};

export const defaultFilters: FindingFilters = {
  status: "open",
  severities: [],
  decision: "all",
  project: "all",
  exploited: false,
  fixable: false,
  sort: { key: "priority", dir: "desc" },
};

// The direction a first click on a column header applies: worst or oldest first for the
// measures people triage by, alphabetical for names.
const FIRST_DIRECTION: Record<SortKey, SortDir> = { priority: "desc", severity: "desc", package: "asc", project: "asc", fixed: "asc", epss: "desc", age: "desc" };

export function toggleSort(sort: Sort, key: SortKey): Sort {
  return sort.key === key ? { key, dir: sort.dir === "asc" ? "desc" : "asc" } : { key, dir: FIRST_DIRECTION[key] };
}

export type ProjectNames = ReadonlyMap<string, string>;

const collator = new Intl.Collator("en", { numeric: true, sensitivity: "base" });

// Ascending order for each key; "desc" reverses it. Ties always fall back to priority, then ID,
// so the order is stable between refreshes.
function ascending(key: SortKey, names: ProjectNames): (a: Finding, b: Finding) => number {
  const project = (finding: Finding) => names.get(finding.project_id) ?? "";
  const fix = (finding: Finding) => finding.fixed_versions[0] ?? "";
  switch (key) {
    case "priority": return (a, b) => byPriority(b, a);
    case "severity": return (a, b) => severityRank(a.severity) - severityRank(b.severity);
    case "package": return (a, b) => collator.compare(a.package_name, b.package_name) || collator.compare(a.package_version, b.package_version);
    case "project": return (a, b) => collator.compare(project(a), project(b));
    case "fixed": return (a, b) => (fix(a) && fix(b) ? collator.compare(fix(a), fix(b)) : Number(!fix(a)) - Number(!fix(b)));
    case "epss": return (a, b) => (a.epss_score ?? -1) - (b.epss_score ?? -1);
    case "age": return (a, b) => Date.parse(b.first_seen_at) - Date.parse(a.first_seen_at);
  }
}

export function sortFindings(rows: readonly Finding[], sort: Sort, names: ProjectNames): Finding[] {
  const compare = ascending(sort.key, names);
  const sign = sort.dir === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => sign * compare(a, b) || byPriority(a, b) || a.id.localeCompare(b.id));
}

export function searchTerms(query: string) {
  return query.toLowerCase().split(/\s+/).filter(Boolean);
}

function haystack(finding: Finding, names: ProjectNames) {
  return [finding.package_name, finding.package_version, finding.summary, finding.ecosystem, finding.target_path, names.get(finding.project_id) ?? "", ...finding.advisory_ids].join("\n").toLowerCase();
}

function decisionMatches(filter: string, finding: Finding) {
  if (filter === "all") return true;
  if (filter === "decided") return finding.workflow_status !== "open";
  return finding.workflow_status === filter;
}

export type Facet = "severity";

/** Every term of the query must appear somewhere in the finding. `skip` leaves one filter out. */
export function filterFindings(findings: readonly Finding[], filters: FindingFilters, query: string, names: ProjectNames, skip?: Facet): Finding[] {
  const terms = searchTerms(query);
  return findings.filter((finding) => {
    if (filters.status !== "all" && finding.status !== filters.status) return false;
    if (skip !== "severity" && filters.severities.length && !filters.severities.includes(severityOf(finding.severity))) return false;
    if (!decisionMatches(filters.decision, finding)) return false;
    if (filters.project !== "all" && finding.project_id !== filters.project) return false;
    if (filters.exploited && !finding.kev_known) return false;
    if (filters.fixable && !finding.fixed_versions.length) return false;
    if (terms.length) {
      const text = haystack(finding, names);
      if (!terms.every((term) => text.includes(term))) return false;
    }
    return true;
  });
}

/** How many findings each severity would show, given every other active filter. */
export function severityCounts(findings: readonly Finding[], filters: FindingFilters, query: string, names: ProjectNames) {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const finding of filterFindings(findings, filters, query, names, "severity")) counts[severityOf(finding.severity)] += 1;
  return counts;
}

export function isFiltered(filters: FindingFilters, query: string) {
  return filters.status !== defaultFilters.status || filters.severities.length > 0 || filters.decision !== "all" || filters.project !== "all" || filters.exploited || filters.fixable || query.trim() !== "";
}

export const acknowledgeable = (finding: Finding) => finding.status === "open" && finding.workflow_status === "open";

// ── Presentation helpers ─────────────────────────────────────────────────────

export function ageMs(now: number, value: string) {
  return Math.max(0, now - Date.parse(value));
}

export function ageLabel(now: number, value: string) {
  if (!now) return "—";
  const age = ageMs(now, value);
  if (age < 3_600_000) return "<1h";
  if (age < 86_400_000) return `${Math.floor(age / 3_600_000)}h`;
  return `${Math.floor(age / 86_400_000)}d`;
}

export type Decision = { kind: "resolved" | "awaiting" | "acknowledged" | "accepted"; label: string };

export function decisionOf(finding: Finding): Decision {
  if (finding.status === "resolved") return { kind: "resolved", label: "Resolved" };
  if (finding.workflow_status === "acknowledged") return { kind: "acknowledged", label: "Acknowledged" };
  if (finding.workflow_status === "risk_accepted") return { kind: "accepted", label: finding.risk_until ? `Risk accepted until ${shortDate(finding.risk_until)}` : "Risk accepted" };
  return { kind: "awaiting", label: "Not reviewed" };
}

export const epssPercent = (score: number) => `${(score * 100).toFixed(1)}%`;

// ── Saved views ──────────────────────────────────────────────────────────────

export type FindingView = { id: string; name: string; filters: FindingFilters; query: string; builtin: boolean };

const view = (id: string, name: string, patch: Partial<FindingFilters>): FindingView => ({ id, name, filters: { ...defaultFilters, ...patch }, query: "", builtin: true });

export const BUILTIN_VIEWS: FindingView[] = [
  view("all-open", "All open", {}),
  view("critical-high", "Critical and high", { severities: ["critical", "high"] }),
  view("exploited", "Known exploited", { exploited: true }),
  view("fixable", "Fix available", { fixable: true }),
  view("awaiting", "Not reviewed", { decision: "open" }),
  view("decided", "Acknowledged or risk accepted", { decision: "decided" }),
];

const SORT_KEYS: readonly string[] = ["priority", "severity", "package", "project", "fixed", "epss", "age"];

/** Accepts only well-formed stored filters; anything else falls back to the defaults. */
export function normalizeFilters(value: unknown): FindingFilters | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  const sort = raw.sort as Record<string, unknown> | undefined;
  const status = ["open", "resolved", "all"].includes(String(raw.status)) ? (raw.status as StatusFilter) : defaultFilters.status;
  return {
    status,
    severities: Array.isArray(raw.severities) ? raw.severities.filter((item): item is string => typeof item === "string" && ["critical", "high", "medium", "low", "unknown"].includes(item)) : [],
    decision: ["all", "open", "acknowledged", "risk_accepted", "decided"].includes(String(raw.decision)) ? String(raw.decision) : "all",
    project: typeof raw.project === "string" && raw.project ? raw.project : "all",
    exploited: raw.exploited === true,
    fixable: raw.fixable === true,
    sort: sort && SORT_KEYS.includes(String(sort.key)) && (sort.dir === "asc" || sort.dir === "desc") ? { key: sort.key as SortKey, dir: sort.dir } : defaultFilters.sort,
  };
}

export function parseViews(raw: string | null): FindingView[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const views: FindingView[] = [];
    for (const item of parsed) {
      if (!item || typeof item !== "object") continue;
      const entry = item as Record<string, unknown>;
      const filters = normalizeFilters(entry.filters);
      const name = typeof entry.name === "string" ? entry.name.trim().slice(0, 40) : "";
      if (!filters || !name || typeof entry.id !== "string") continue;
      views.push({ id: entry.id, name, filters, query: typeof entry.query === "string" ? entry.query : "", builtin: false });
    }
    return views;
  } catch { return []; }
}

export const serializeViews = (views: FindingView[]) => JSON.stringify(views.map(({ id, name, filters, query }) => ({ id, name, filters, query })));

/** Saving under an existing name (ignoring case) replaces that view. */
export function upsertView(views: FindingView[], name: string, filters: FindingFilters, query: string): FindingView[] {
  const clean = name.trim().slice(0, 40);
  const existing = views.find((item) => item.name.toLowerCase() === clean.toLowerCase());
  const next: FindingView = { id: existing?.id ?? `user-${clean.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${views.length + 1}`, name: clean, filters, query: query.trim(), builtin: false };
  return existing ? views.map((item) => (item.id === existing.id ? next : item)) : [...views, next];
}

const sameSeverities = (a: string[], b: string[]) => a.length === b.length && [...a].sort().every((value, index) => value === [...b].sort()[index]);

/** A view is current when its filters and search match, whatever the sort. */
export function sameView(filters: FindingFilters, query: string, candidate: FindingView) {
  const other = candidate.filters;
  return filters.status === other.status && filters.decision === other.decision && filters.project === other.project && filters.exploited === other.exploited && filters.fixable === other.fixable && sameSeverities(filters.severities, other.severities) && query.trim() === candidate.query.trim();
}

// ── Columns ──────────────────────────────────────────────────────────────────

export const OPTIONAL_COLUMNS = [
  { key: "project", label: "Project" },
  { key: "advisory", label: "Advisory" },
  { key: "fixed", label: "Fixed in" },
  { key: "signals", label: "Exploit risk" },
  { key: "age", label: "Age" },
  { key: "decision", label: "Review" },
] as const;
export type ColumnKey = (typeof OPTIONAL_COLUMNS)[number]["key"];
export const ALL_COLUMNS: ColumnKey[] = OPTIONAL_COLUMNS.map((column) => column.key);

export function parseColumns(raw: string | null): ColumnKey[] {
  if (!raw) return ALL_COLUMNS;
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? ALL_COLUMNS.filter((key) => parsed.includes(key)) : ALL_COLUMNS;
  } catch { return ALL_COLUMNS; }
}

export const serializeColumns = (columns: ColumnKey[]) => JSON.stringify(columns);

// ── Paging and selection ─────────────────────────────────────────────────────

export const PAGE_SIZES = [25, 50, 100];

export function parsePageSize(raw: string | null) {
  const size = Number(raw);
  return PAGE_SIZES.includes(size) ? size : PAGE_SIZES[0];
}

/** `from` and `to` are 1-based and inclusive; both are 0 for an empty list. */
export function pageWindow(total: number, page: number, size: number) {
  const pages = Math.max(1, Math.ceil(total / size));
  const current = Math.min(Math.max(1, page), pages);
  return { page: current, pages, from: total ? (current - 1) * size + 1 : 0, to: Math.min(total, current * size) };
}

/** IDs from `anchor` to `target` inclusive, in list order; just the target if the anchor is not listed. */
export function rangeIds(ids: readonly string[], anchor: string | null, target: string): string[] {
  const end = ids.indexOf(target);
  const start = anchor ? ids.indexOf(anchor) : -1;
  if (end < 0) return [];
  if (start < 0) return [target];
  return ids.slice(Math.min(start, end), Math.max(start, end) + 1);
}

// ── CSV export ───────────────────────────────────────────────────────────────

/**
 * One CSV field. A leading = + - @ (or tab/CR) would be run as a formula by spreadsheets, so such
 * text is prefixed with a single quote. Fields with a comma, quote, or line break are quoted.
 */
export function csvCell(value: string | number | boolean | null | undefined): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export const CSV_HEADER = ["Severity", "Package", "Version", "Ecosystem", "Project", "Manifest", "Advisories", "Fixed versions", "EPSS (%)", "Known exploited", "First seen", "Status", "Review"];

export function toCsv(rows: readonly Finding[], names: ProjectNames): string {
  const lines = [CSV_HEADER.map(csvCell).join(",")];
  for (const finding of rows) {
    lines.push([
      severityOf(finding.severity), finding.package_name, finding.package_version, finding.ecosystem, names.get(finding.project_id) ?? "", finding.target_path,
      finding.advisory_ids.join("; "), finding.fixed_versions.join("; "), finding.epss_score === null ? "" : (finding.epss_score * 100).toFixed(1),
      finding.kev_known ? "yes" : "no", finding.first_seen_at, finding.status, decisionOf(finding).label,
    ].map(csvCell).join(","));
  }
  return `${lines.join("\r\n")}\r\n`;
}

export const csvFileName = (date: Date) => `depradar-findings-${date.toISOString().slice(0, 10)}.csv`;
