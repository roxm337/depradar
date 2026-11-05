import type { ComponentCoverage, ComponentMatch } from "@/lib/api";

export type PackageQuery = { name: string; ecosystem: string; version: string };

/** The API path for a search, or null when there is no name to search for. */
export function searchPath(query: PackageQuery): string | null {
  const name = query.name.trim();
  if (!name) return null;
  const params = new URLSearchParams({ name });
  if (query.ecosystem) params.set("ecosystem", query.ecosystem);
  if (query.version.trim()) params.set("version", query.version.trim());
  return `components?${params}`;
}

export type VersionCount = { ecosystem: string; name: string; version: string; manifests: number };
export type MatchSummary = { projects: number; manifests: number; versions: VersionCount[] };

/** How widely the matches spread: distinct projects and manifests, and manifests per version. */
export function summarize(matches: readonly ComponentMatch[]): MatchSummary {
  const projects = new Set(matches.map((match) => match.snapshot.project_id));
  const manifests = new Set(matches.map((match) => match.snapshot.inventory_id));
  const versions = new Map<string, VersionCount>();
  for (const match of matches) {
    const key = JSON.stringify([match.ecosystem, match.name, match.version]);
    const entry = versions.get(key) ?? { ecosystem: match.ecosystem, name: match.name, version: match.version, manifests: 0 };
    entry.manifests += 1;
    versions.set(key, entry);
  }
  return {
    projects: projects.size,
    manifests: manifests.size,
    versions: [...versions.values()].sort((a, b) => b.manifests - a.manifests || a.version.localeCompare(b.version, undefined, { numeric: true })),
  };
}

export const versionLabel = (version: string) => version || "Unpinned";

const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;

/** What qualifies a search answer; never lets missing data read as "not used". */
export function coverageNote(coverage: ComponentCoverage): string | null {
  const parts: string[] = [];
  if (coverage.not_indexed.length) parts.push(`${plural(coverage.not_indexed.length, "manifest is", "manifests are")} not indexed yet and not searched`);
  if (coverage.partial.length) parts.push(`${plural(coverage.partial.length, "manifest was", "manifests were")} indexed by an incomplete scan and may be missing packages`);
  return parts.length ? `${parts.join("; ")}.` : null;
}

/** The empty-result message: what was searched, and what was not. */
export function noMatchText(name: string, coverage: ComponentCoverage): string {
  const searched = `No current monitored manifest lists ${name}. Searched ${plural(coverage.indexed, "indexed manifest", "indexed manifests")}`;
  const note = coverageNote(coverage);
  return note ? `${searched}; ${note.charAt(0).toLowerCase()}${note.slice(1)}` : `${searched}.`;
}

export const indexLabel = (index: ComponentMatch["indexed_by"]) => (index.complete ? "Complete scan" : "Partial scan");
